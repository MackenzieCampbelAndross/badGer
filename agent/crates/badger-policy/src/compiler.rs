use crate::capability::Capability;
use crate::model::Policy;
use badger_common::{BadgerError, BadgerResult};
use regex::Regex;
use std::collections::HashMap;

/// Pre-compiled policy representation optimized for high-throughput evaluation.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub policy: Policy,
    pub principal_regexes: Vec<Regex>,
    pub workload_regexes: Vec<Regex>,
    pub resource_regexes: Vec<Regex>,
    /// Index of allowed capabilities by category for fast pruning
    pub allowed_by_category: HashMap<&'static str, Vec<Capability>>,
    /// Index of denied capabilities by category
    pub denied_by_category: HashMap<&'static str, Vec<Capability>>,
}

pub struct PolicyValidator;

impl PolicyValidator {
    pub fn validate(policy: &Policy) -> BadgerResult<()> {
        if policy.id.trim().is_empty() {
            return Err(BadgerError::PolicyInvalid("Policy ID cannot be empty".to_string()));
        }
        if policy.tenant_id.trim().is_empty() {
            return Err(BadgerError::PolicyInvalid("Policy Tenant ID cannot be empty".to_string()));
        }
        if policy.version == 0 {
            return Err(BadgerError::PolicyInvalid("Policy version must be >= 1".to_string()));
        }

        // Validate time window
        if policy.valid_until_unix > 0 && policy.valid_from_unix > policy.valid_until_unix {
            return Err(BadgerError::PolicyInvalid(format!(
                "Invalid time window: valid_from ({}) > valid_until ({})",
                policy.valid_from_unix, policy.valid_until_unix
            )));
        }

        // Validate selectors
        for s in &policy.principal_selectors {
            if s.contains('*') {
                let pat = format!("^{}$", s.replace('.', "\\.").replace('*', ".*"));
                Regex::new(&pat).map_err(|e| BadgerError::PolicyInvalid(format!("Invalid principal selector '{}': {}", s, e)))?;
            }
        }
        for s in &policy.workload_selectors {
            if s.contains('*') {
                let pat = format!("^{}$", s.replace('.', "\\.").replace('*', ".*"));
                Regex::new(&pat).map_err(|e| BadgerError::PolicyInvalid(format!("Invalid workload selector '{}': {}", s, e)))?;
            }
        }
        for s in &policy.resource_selectors {
            if s.contains('*') {
                let pat = format!("^{}$", s.replace('.', "\\.").replace('*', ".*"));
                Regex::new(&pat).map_err(|e| BadgerError::PolicyInvalid(format!("Invalid resource selector '{}': {}", s, e)))?;
            }
        }

        // Validate approval requirements
        if let Some(ref app) = policy.approval_requirements {
            if app.min_approvals == 0 {
                return Err(BadgerError::PolicyInvalid("min_approvals must be >= 1".to_string()));
            }
            if app.min_approvals as usize > app.required_approvers.len() {
                return Err(BadgerError::PolicyInvalid(format!(
                    "min_approvals ({}) cannot exceed total required approvers ({})",
                    app.min_approvals, app.required_approvers.len()
                )));
            }
        }

        // Check for direct conflicting rules
        for allowed in &policy.allowed_capabilities {
            for denied in &policy.denied_capabilities {
                if allowed == denied {
                    return Err(BadgerError::PolicyInvalid(format!(
                        "Conflicting rule: capability '{:?}' is declared in both allow and deny sets",
                        allowed
                    )));
                }
            }
        }

        Ok(())
    }
}

pub struct PolicyCompiler;

impl PolicyCompiler {
    pub fn compile(policy: Policy) -> BadgerResult<CompiledPolicy> {
        PolicyValidator::validate(&policy)?;

        let mut principal_regexes = Vec::new();
        for s in &policy.principal_selectors {
            let pat = if s.contains('*') {
                format!("^{}$", s.replace('.', "\\.").replace('*', ".*"))
            } else {
                format!("^{}$", regex::escape(s))
            };
            principal_regexes.push(Regex::new(&pat).map_err(|e| {
                BadgerError::PolicyInvalid(format!("Failed to compile regex for selector '{}': {}", s, e))
            })?);
        }

        let mut workload_regexes = Vec::new();
        for s in &policy.workload_selectors {
            let pat = if s.contains('*') {
                format!("^{}$", s.replace('.', "\\.").replace('*', ".*"))
            } else {
                format!("^{}$", regex::escape(s))
            };
            workload_regexes.push(Regex::new(&pat).map_err(|e| {
                BadgerError::PolicyInvalid(format!("Failed to compile regex for selector '{}': {}", s, e))
            })?);
        }

        let mut resource_regexes = Vec::new();
        for s in &policy.resource_selectors {
            let pat = if s.contains('*') {
                format!("^{}$", s.replace('.', "\\.").replace('*', ".*"))
            } else {
                format!("^{}$", regex::escape(s))
            };
            resource_regexes.push(Regex::new(&pat).map_err(|e| {
                BadgerError::PolicyInvalid(format!("Failed to compile regex for selector '{}': {}", s, e))
            })?);
        }

        let mut allowed_by_category: HashMap<&'static str, Vec<Capability>> = HashMap::new();
        for cap in &policy.allowed_capabilities {
            allowed_by_category.entry(cap.category()).or_default().push(cap.clone());
        }

        let mut denied_by_category: HashMap<&'static str, Vec<Capability>> = HashMap::new();
        for cap in &policy.denied_capabilities {
            denied_by_category.entry(cap.category()).or_default().push(cap.clone());
        }

        Ok(CompiledPolicy {
            policy,
            principal_regexes,
            workload_regexes,
            resource_regexes,
            allowed_by_category,
            denied_by_category,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;

    #[test]
    fn test_policy_validation_catches_conflicts() {
        let cap = Capability::FsRead {
            path: "/secret".to_string(),
            recursive: true,
        };

        let pol = Policy {
            id: "pol-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            name: "Conflict Test".to_string(),
            version: 1,
            priority: 10,
            principal_selectors: vec!["*".to_string()],
            workload_selectors: vec!["*".to_string()],
            resource_selectors: vec!["*".to_string()],
            allowed_capabilities: vec![cap.clone()],
            denied_capabilities: vec![cap],
            context_conditions: Vec::new(),
            approval_requirements: None,
            valid_from_unix: 0,
            valid_until_unix: 0,
            is_staging: false,
            signature: String::new(),
            provenance: "test".to_string(),
        };

        let res = PolicyCompiler::compile(pol);
        assert!(res.is_err(), "Must reject policy with conflicting allow and deny rules");
    }
}
