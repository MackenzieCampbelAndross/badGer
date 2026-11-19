use crate::compiler::CompiledPolicy;
use crate::enforcement::EnforcementBridge;
use crate::model::{
    ContextCondition, DecisionOutcome, EvaluationContext, EvaluationDecision,
};

pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Evaluates a capability authorization request against active compiled policies.
    /// Returns a structured, explainable decision.
    pub fn evaluate(
        ctx: &EvaluationContext,
        policies: &[&CompiledPolicy],
    ) -> EvaluationDecision {
        let cat = ctx.capability.category();
        let enf_path = EnforcementBridge::resolve_enforcement_path(&ctx.capability);

        // Filter and sort applicable policies by priority descending
        let mut applicable: Vec<&&CompiledPolicy> = policies
            .iter()
            .filter(|cp| {
                let p = &cp.policy;

                // 1. Staging check: staging policies are not evaluated for live authorization
                if p.is_staging {
                    return false;
                }

                // 2. Time validity check
                if p.valid_until_unix > 0 && ctx.timestamp_unix > p.valid_until_unix {
                    return false;
                }
                if p.valid_from_unix > 0 && ctx.timestamp_unix < p.valid_from_unix {
                    return false;
                }

                // 3. Principal match
                let principal_match = cp
                    .principal_regexes
                    .iter()
                    .any(|r| r.is_match(&ctx.principal));
                if !principal_match {
                    return false;
                }

                // 4. Workload match
                let workload_match = cp
                    .workload_regexes
                    .iter()
                    .any(|r| r.is_match(&ctx.workload));
                if !workload_match {
                    return false;
                }

                // 5. Resource match
                let resource_match = cp
                    .resource_regexes
                    .iter()
                    .any(|r| r.is_match(&ctx.resource));
                if !resource_match {
                    return false;
                }

                true
            })
            .collect();

        applicable.sort_by(|a, b| b.policy.priority.cmp(&a.policy.priority));

        // Evaluate Deny rules first across all applicable policies (Deny precedence)
        for cp in &applicable {
            if let Some(denied_caps) = cp.denied_by_category.get(cat) {
                for denied in denied_caps {
                    if denied.subsumes(&ctx.capability) {
                        return EvaluationDecision {
                            decision: DecisionOutcome::Deny,
                            policy_id: cp.policy.id.clone(),
                            policy_version: cp.policy.version,
                            matched_rule: format!("DENY: {:?}", denied),
                            principal: ctx.principal.clone(),
                            workload: ctx.workload.clone(),
                            resource: ctx.resource.clone(),
                            capability: ctx.capability.clone(),
                            reason: format!(
                                "Explicitly denied by policy '{}' rule: {:?}",
                                cp.policy.name, denied
                            ),
                            evaluated_at: ctx.timestamp_unix,
                            enforcement_path: enf_path,
                        };
                    }
                }
            }
        }

        // Evaluate Allow rules in priority order
        for cp in &applicable {
            // Check context conditions
            let mut conditions_met = true;

            for cond in &cp.policy.context_conditions {
                match cond {
                    ContextCondition::ClientIp { cidr } => {
                        if let Some(ref ip) = ctx.client_ip {
                            if !ip.starts_with(cidr.trim_end_matches("/24").trim_end_matches("/32")) {
                                conditions_met = false;
                                break;
                            }
                        } else {
                            conditions_met = false;
                            break;
                        }
                    }
                    ContextCondition::TimeWindow { valid_from_unix, valid_until_unix } => {
                        if ctx.timestamp_unix < *valid_from_unix || ctx.timestamp_unix > *valid_until_unix {
                            conditions_met = false;
                            break;
                        }
                    }
                    ContextCondition::MaxRiskScore { max_score } => {
                        if ctx.risk_score > *max_score {
                            conditions_met = false;
                            break;
                        }
                    }
                    ContextCondition::Environment { name } => {
                        if ctx.environment != *name {
                            conditions_met = false;
                            break;
                        }
                    }
                    ContextCondition::MfaVerified { required } => {
                        if *required && !ctx.mfa_verified {
                            conditions_met = false;
                            break;
                        }
                    }
                }
            }

            if !conditions_met {
                continue; // Skip this policy's allow rules because context conditions failed
            }

            // Check approval requirements
            if let Some(ref app) = cp.policy.approval_requirements {
                if app.approved_by.len() < app.min_approvals as usize {
                    return EvaluationDecision {
                        decision: DecisionOutcome::Deny,
                        policy_id: cp.policy.id.clone(),
                        policy_version: cp.policy.version,
                        matched_rule: "APPROVAL_PENDING".to_string(),
                        principal: ctx.principal.clone(),
                        workload: ctx.workload.clone(),
                        resource: ctx.resource.clone(),
                        capability: ctx.capability.clone(),
                        reason: format!(
                            "Capability requires {} approvals, but only {} recorded",
                            app.min_approvals,
                            app.approved_by.len()
                        ),
                        evaluated_at: ctx.timestamp_unix,
                        enforcement_path: enf_path,
                    };
                }
            }

            if let Some(allowed_caps) = cp.allowed_by_category.get(cat) {
                for allowed in allowed_caps {
                    if allowed.subsumes(&ctx.capability) {
                        return EvaluationDecision {
                            decision: DecisionOutcome::Allow,
                            policy_id: cp.policy.id.clone(),
                            policy_version: cp.policy.version,
                            matched_rule: format!("ALLOW: {:?}", allowed),
                            principal: ctx.principal.clone(),
                            workload: ctx.workload.clone(),
                            resource: ctx.resource.clone(),
                            capability: ctx.capability.clone(),
                            reason: format!(
                                "Granted by policy '{}' (priority {})",
                                cp.policy.name, cp.policy.priority
                            ),
                            evaluated_at: ctx.timestamp_unix,
                            enforcement_path: enf_path,
                        };
                    }
                }
            }
        }

        // Default Deny
        EvaluationDecision {
            decision: DecisionOutcome::Deny,
            policy_id: "default_deny".to_string(),
            policy_version: 1,
            matched_rule: "DEFAULT_DENY".to_string(),
            principal: ctx.principal.clone(),
            workload: ctx.workload.clone(),
            resource: ctx.resource.clone(),
            capability: ctx.capability.clone(),
            reason: "Default deny: no active policy rule granted the requested capability".to_string(),
            evaluated_at: ctx.timestamp_unix,
            enforcement_path: enf_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;
    use crate::compiler::PolicyCompiler;
    use crate::model::Policy;

    #[test]
    fn test_evaluator_allow_and_deny_precedence() {
        let cap_read_all = Capability::FsRead {
            path: "/workspace".to_string(),
            recursive: true,
        };
        let cap_read_secret = Capability::FsRead {
            path: "/workspace/secret.key".to_string(),
            recursive: false,
        };

        let pol = Policy {
            id: "pol-test".to_string(),
            tenant_id: "tenant-a".to_string(),
            name: "Test Policy".to_string(),
            version: 1,
            priority: 10,
            principal_selectors: vec!["agent-*".to_string()],
            workload_selectors: vec!["*".to_string()],
            resource_selectors: vec!["*".to_string()],
            allowed_capabilities: vec![cap_read_all],
            denied_capabilities: vec![cap_read_secret.clone()],
            context_conditions: Vec::new(),
            approval_requirements: None,
            valid_from_unix: 0,
            valid_until_unix: 0,
            is_staging: false,
            signature: String::new(),
            provenance: "test".to_string(),
        };

        let compiled = PolicyCompiler::compile(pol).unwrap();
        let policies = vec![&compiled];

        // 1. Access normal file -> ALLOW
        let ctx1 = EvaluationContext {
            principal: "agent-worker-1".to_string(),
            workload: "wkl-1".to_string(),
            resource: "/workspace/main.rs".to_string(),
            capability: Capability::FsRead {
                path: "/workspace/main.rs".to_string(),
                recursive: false,
            },
            client_ip: None,
            timestamp_unix: 1000,
            environment: "production".to_string(),
            risk_score: 10,
            mfa_verified: false,
        };
        let dec1 = PolicyEvaluator::evaluate(&ctx1, &policies);
        assert_eq!(dec1.decision, DecisionOutcome::Allow);

        // 2. Access secret file -> DENY (denied takes precedence)
        let ctx2 = EvaluationContext {
            principal: "agent-worker-1".to_string(),
            workload: "wkl-1".to_string(),
            resource: "/workspace/secret.key".to_string(),
            capability: cap_read_secret,
            client_ip: None,
            timestamp_unix: 1000,
            environment: "production".to_string(),
            risk_score: 10,
            mfa_verified: false,
        };
        let dec2 = PolicyEvaluator::evaluate(&ctx2, &policies);
        assert_eq!(dec2.decision, DecisionOutcome::Deny);
    }
}
