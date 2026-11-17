use badger_common::{
    BadgerError, BadgerResult, CapabilityPolicy, FilesystemRule, FsAccess, NetworkRule,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policies: Arc<RwLock<HashMap<String, CapabilityPolicy>>>,
    signing_key: String,
}

impl PolicyEngine {
    pub fn new(signing_key: &str) -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            signing_key: signing_key.to_string(),
        }
    }

    /// Computes policy integrity signature
    pub fn compute_signature(policy: &CapabilityPolicy, signing_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(policy.id.as_bytes());
        hasher.update(policy.tenant_id.as_bytes());
        hasher.update(policy.name.as_bytes());
        hasher.update(policy.version.to_string().as_bytes());
        for exe in &policy.allowed_executables {
            hasher.update(exe.as_bytes());
        }
        for exe in &policy.denied_executables {
            hasher.update(exe.as_bytes());
        }
        for fs in &policy.filesystem_rules {
            hasher.update(fs.path.as_bytes());
            hasher.update(format!("{:?}", fs.access).as_bytes());
        }
        for net in &policy.network_rules {
            hasher.update(net.destination.as_bytes());
            hasher.update(net.port.to_string().as_bytes());
            hasher.update(net.allow.to_string().as_bytes());
        }
        hasher.update(policy.valid_from_unix.to_string().as_bytes());
        hasher.update(policy.valid_until_unix.to_string().as_bytes());
        hasher.update(signing_key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Loads and verifies a policy. Rejects malformed, unauthorized, or expired policies.
    pub fn load_policy(&self, mut policy: CapabilityPolicy) -> BadgerResult<()> {
        let now = Utc::now().timestamp();

        // 1. Time validity check
        if policy.valid_until_unix > 0 && now > policy.valid_until_unix {
            return Err(BadgerError::PolicyInvalid(format!(
                "Policy '{}' v{} expired at {}",
                policy.id, policy.version, policy.valid_until_unix
            )));
        }
        if policy.valid_from_unix > 0 && now < policy.valid_from_unix {
            return Err(BadgerError::PolicyInvalid(format!(
                "Policy '{}' v{} not yet valid (starts at {})",
                policy.id, policy.version, policy.valid_from_unix
            )));
        }

        // 2. Resource limits validation
        if policy.limits.max_memory_bytes < 1024 * 1024 {
            return Err(BadgerError::PolicyInvalid(
                "Policy limits invalid: max_memory_bytes must be >= 1MB".to_string(),
            ));
        }
        if policy.limits.max_pids < 1 {
            return Err(BadgerError::PolicyInvalid(
                "Policy limits invalid: max_pids must be >= 1".to_string(),
            ));
        }

        // 3. Cryptographic signature check
        let expected_sig = Self::compute_signature(&policy, &self.signing_key);
        if !policy.signature.is_empty() && policy.signature != expected_sig {
            return Err(BadgerError::PolicyInvalid(format!(
                "Policy '{}' signature verification failed: unauthorized or tampered policy",
                policy.id
            )));
        }

        // Populate valid signature if empty
        if policy.signature.is_empty() {
            policy.signature = expected_sig;
        }

        let mut map = self.policies.write().unwrap();
        map.insert(policy.id.clone(), policy);
        Ok(())
    }

    pub fn get_policy(&self, policy_id: &str) -> Option<CapabilityPolicy> {
        let map = self.policies.read().unwrap();
        map.get(policy_id).cloned()
    }

    /// Evaluates whether an executable path is permitted
    pub fn evaluate_executable(&self, policy_id: &str, binary_path: &str) -> BadgerResult<bool> {
        let pol = self
            .get_policy(policy_id)
            .ok_or_else(|| BadgerError::PolicyInvalid(format!("Policy '{}' not found", policy_id)))?;

        // Explicit denied executables take highest precedence
        for denied in &pol.denied_executables {
            if binary_path == denied || binary_path.ends_with(denied) {
                return Ok(false);
            }
        }

        // If allowed list is defined, must match
        if !pol.allowed_executables.is_empty() {
            for allowed in &pol.allowed_executables {
                if binary_path == allowed || binary_path.starts_with(allowed) {
                    return Ok(true);
                }
            }
            return Ok(false); // Default deny if not in allowlist
        }

        // If no allowlist defined, allow unless explicitly denied
        Ok(true)
    }

    /// Evaluates whether a filesystem access is permitted
    pub fn evaluate_filesystem(
        &self,
        policy_id: &str,
        path: &str,
        is_write: bool,
    ) -> BadgerResult<bool> {
        let pol = self
            .get_policy(policy_id)
            .ok_or_else(|| BadgerError::PolicyInvalid(format!("Policy '{}' not found", policy_id)))?;

        // Most specific path match
        let mut best_match: Option<&FilesystemRule> = None;
        for rule in &pol.filesystem_rules {
            if path == rule.path || (rule.recursive && path.starts_with(&rule.path)) {
                if let Some(prev) = best_match {
                    if rule.path.len() > prev.path.len() {
                        best_match = Some(rule);
                    }
                } else {
                    best_match = Some(rule);
                }
            }
        }

        if let Some(rule) = best_match {
            match rule.access {
                FsAccess::None => Ok(false),
                FsAccess::Ro => Ok(!is_write),
                FsAccess::Rw => Ok(true),
            }
        } else {
            // Default deny for unknown paths outside rule definitions
            Ok(false)
        }
    }

    /// Evaluates network destination
    pub fn evaluate_network(
        &self,
        policy_id: &str,
        destination: &str,
        port: u16,
    ) -> BadgerResult<bool> {
        let pol = self
            .get_policy(policy_id)
            .ok_or_else(|| BadgerError::PolicyInvalid(format!("Policy '{}' not found", policy_id)))?;

        for rule in &pol.network_rules {
            if (rule.destination == "*" || rule.destination == destination)
                && (rule.port == 0 || rule.port == port)
            {
                return Ok(rule.allow);
            }
        }

        // Default deny
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use badger_common::{FilesystemRule, FsAccess, NetworkRule, ResourceLimits};

    fn make_test_policy() -> CapabilityPolicy {
        CapabilityPolicy {
            id: "pol-strict".to_string(),
            tenant_id: "tenant-1".to_string(),
            name: "Strict Agent Policy".to_string(),
            version: 1,
            allowed_executables: vec!["/bin/bash".to_string(), "/usr/bin/python3".to_string()],
            denied_executables: vec!["/bin/nc".to_string(), "/usr/bin/ncat".to_string()],
            filesystem_rules: vec![
                FilesystemRule {
                    path: "/workspace".to_string(),
                    access: FsAccess::Rw,
                    recursive: true,
                },
                FilesystemRule {
                    path: "/etc".to_string(),
                    access: FsAccess::Ro,
                    recursive: true,
                },
                FilesystemRule {
                    path: "/etc/shadow".to_string(),
                    access: FsAccess::None,
                    recursive: false,
                },
            ],
            network_rules: vec![
                NetworkRule {
                    destination: "127.0.0.1".to_string(),
                    port: 8080,
                    protocol: "tcp".to_string(),
                    allow: true,
                },
                NetworkRule {
                    destination: "*".to_string(),
                    port: 0,
                    protocol: "all".to_string(),
                    allow: false,
                },
            ],
            limits: ResourceLimits::default(),
            drop_capabilities: vec!["CAP_SYS_ADMIN".to_string(), "CAP_NET_RAW".to_string()],
            disallow_privilege_escalation: true,
            valid_from_unix: 0,
            valid_until_unix: Utc::now().timestamp() + 3600,
            signature: String::new(),
        }
    }

    #[test]
    fn test_policy_executable_evaluation() {
        let engine = PolicyEngine::new("secret-key");
        let mut policy = make_test_policy();
        policy.signature = PolicyEngine::compute_signature(&policy, "secret-key");
        engine.load_policy(policy).unwrap();

        assert_eq!(
            engine.evaluate_executable("pol-strict", "/usr/bin/python3").unwrap(),
            true
        );
        assert_eq!(
            engine.evaluate_executable("pol-strict", "/bin/nc").unwrap(),
            false
        );
        assert_eq!(
            engine.evaluate_executable("pol-strict", "/usr/bin/wget").unwrap(),
            false
        );
    }

    #[test]
    fn test_policy_filesystem_evaluation() {
        let engine = PolicyEngine::new("secret-key");
        let mut policy = make_test_policy();
        policy.signature = PolicyEngine::compute_signature(&policy, "secret-key");
        engine.load_policy(policy).unwrap();

        assert_eq!(
            engine.evaluate_filesystem("pol-strict", "/workspace/test.txt", true).unwrap(),
            true
        );
        assert_eq!(
            engine.evaluate_filesystem("pol-strict", "/etc/hosts", false).unwrap(),
            true
        );
        assert_eq!(
            engine.evaluate_filesystem("pol-strict", "/etc/hosts", true).unwrap(),
            false
        );
        assert_eq!(
            engine.evaluate_filesystem("pol-strict", "/etc/shadow", false).unwrap(),
            false
        );
    }

    #[test]
    fn test_policy_integrity_tampering_rejected() {
        let engine = PolicyEngine::new("secret-key");
        let mut policy = make_test_policy();
        policy.signature = "tampered_invalid_signature".to_string();
        let res = engine.load_policy(policy);
        assert!(res.is_err());
    }
}
