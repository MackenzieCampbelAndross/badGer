use crate::compiler::CompiledPolicy;
use crate::evaluator::PolicyEvaluator;
use crate::model::{DecisionOutcome, EvaluationContext, EvaluationDecision};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDiffResult {
    pub total_simulated: usize,
    pub newly_allowed_count: usize,
    pub newly_denied_count: usize,
    pub unchanged_count: usize,
    pub newly_allowed: Vec<EvaluationContext>,
    pub newly_denied: Vec<EvaluationContext>,
    pub impact_summary: String,
}

pub struct PolicySimulator;

impl PolicySimulator {
    /// Simulates evaluation of a batch of capability requests against active policies
    pub fn simulate(
        policies: &[&CompiledPolicy],
        requests: &[EvaluationContext],
    ) -> Vec<EvaluationDecision> {
        requests
            .iter()
            .map(|req| PolicyEvaluator::evaluate(req, policies))
            .collect()
    }

    /// Compares outcomes between current production policies and a proposed candidate policy
    pub fn compare_policies(
        current_policies: &[&CompiledPolicy],
        proposed_policies: &[&CompiledPolicy],
        sample_requests: &[EvaluationContext],
    ) -> PolicyDiffResult {
        let mut newly_allowed = Vec::new();
        let mut newly_denied = Vec::new();
        let mut unchanged_count = 0;

        for req in sample_requests {
            let current_dec = PolicyEvaluator::evaluate(req, current_policies);
            let proposed_dec = PolicyEvaluator::evaluate(req, proposed_policies);

            if current_dec.decision == DecisionOutcome::Deny && proposed_dec.decision == DecisionOutcome::Allow {
                newly_allowed.push(req.clone());
            } else if current_dec.decision == DecisionOutcome::Allow && proposed_dec.decision == DecisionOutcome::Deny {
                newly_denied.push(req.clone());
            } else {
                unchanged_count += 1;
            }
        }

        let summary = format!(
            "Simulation across {} requests: {} newly permitted, {} newly blocked, {} unchanged",
            sample_requests.len(),
            newly_allowed.len(),
            newly_denied.len(),
            unchanged_count
        );

        PolicyDiffResult {
            total_simulated: sample_requests.len(),
            newly_allowed_count: newly_allowed.len(),
            newly_denied_count: newly_denied.len(),
            unchanged_count,
            newly_allowed,
            newly_denied,
            impact_summary: summary,
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
    fn test_policy_simulator_diff() {
        let cap = Capability::NetConnect {
            destination: "10.0.0.1".to_string(),
            min_port: 80,
            max_port: 80,
            protocol: "tcp".to_string(),
        };

        let pol1 = Policy {
            id: "pol-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            name: "Initial Policy".to_string(),
            version: 1,
            priority: 1,
            principal_selectors: vec!["*".to_string()],
            workload_selectors: vec!["*".to_string()],
            resource_selectors: vec!["*".to_string()],
            allowed_capabilities: Vec::new(), // Deny all
            denied_capabilities: Vec::new(),
            context_conditions: Vec::new(),
            approval_requirements: None,
            valid_from_unix: 0,
            valid_until_unix: 0,
            is_staging: false,
            signature: String::new(),
            provenance: "test".to_string(),
        };

        let pol2 = Policy {
            id: "pol-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            name: "Proposed Policy".to_string(),
            version: 2,
            priority: 1,
            principal_selectors: vec!["*".to_string()],
            workload_selectors: vec!["*".to_string()],
            resource_selectors: vec!["*".to_string()],
            allowed_capabilities: vec![cap.clone()], // Allow net
            denied_capabilities: Vec::new(),
            context_conditions: Vec::new(),
            approval_requirements: None,
            valid_from_unix: 0,
            valid_until_unix: 0,
            is_staging: false,
            signature: String::new(),
            provenance: "test".to_string(),
        };

        let comp1 = PolicyCompiler::compile(pol1).unwrap();
        let comp2 = PolicyCompiler::compile(pol2).unwrap();

        let req = EvaluationContext {
            principal: "prn-1".to_string(),
            workload: "wkl-1".to_string(),
            resource: "10.0.0.1:80".to_string(),
            capability: cap,
            client_ip: None,
            timestamp_unix: 100,
            environment: "prod".to_string(),
            risk_score: 5,
            mfa_verified: false,
        };

        let diff = PolicySimulator::compare_policies(&[&comp1], &[&comp2], &[req]);
        assert_eq!(diff.newly_allowed_count, 1);
        assert_eq!(diff.newly_denied_count, 0);
    }
}
