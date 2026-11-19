use crate::bpf_types::{parse_ipv4_cidr, parse_ipv6_cidr};
use crate::types::NetworkPolicy;
use badger_common::{BadgerError, BadgerResult};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct NetworkPolicyEngine {
    policies: Arc<RwLock<HashMap<String, NetworkPolicy>>>,
    history: Arc<RwLock<HashMap<String, Vec<NetworkPolicy>>>>,
    signing_key: String,
    cache_dir: Option<PathBuf>,
}

impl NetworkPolicyEngine {
    pub fn new(signing_key: &str, cache_dir: Option<PathBuf>) -> Self {
        let engine = Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(HashMap::new())),
            signing_key: signing_key.to_string(),
            cache_dir,
        };

        // Load offline cached policies if cache directory exists
        if let Some(ref dir) = engine.cache_dir {
            let _ = engine.load_cache_from_disk(dir);
        }

        engine
    }

    /// Computes deterministic cryptographic signature for a network policy
    pub fn compute_signature(policy: &NetworkPolicy, signing_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(policy.id.as_bytes());
        hasher.update(policy.tenant_id.as_bytes());
        hasher.update(policy.workload_id.as_bytes());
        hasher.update(policy.version.to_string().as_bytes());
        hasher.update(format!("{:?}", policy.default_action).as_bytes());
        hasher.update(policy.block_cloud_metadata.to_string().as_bytes());

        for r in &policy.rules {
            hasher.update(r.rule_id.to_string().as_bytes());
            hasher.update(r.destination_cidr.as_bytes());
            hasher.update(r.min_port.to_string().as_bytes());
            hasher.update(r.max_port.to_string().as_bytes());
            hasher.update(format!("{:?}", r.protocol).as_bytes());
            hasher.update(format!("{:?}", r.action).as_bytes());
            hasher.update(r.priority.to_string().as_bytes());
        }

        hasher.update(policy.valid_from_unix.to_string().as_bytes());
        hasher.update(policy.valid_until_unix.to_string().as_bytes());
        hasher.update(signing_key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Validates policy structure, expiration, and cryptographic signature
    pub fn validate_policy(&self, policy: &NetworkPolicy) -> BadgerResult<()> {
        let now = Utc::now().timestamp();

        // 1. Time validity
        if policy.valid_until_unix > 0 && now > policy.valid_until_unix {
            return Err(BadgerError::PolicyInvalid(format!(
                "Network policy '{}' v{} expired at {}",
                policy.id, policy.version, policy.valid_until_unix
            )));
        }
        if policy.valid_from_unix > 0 && now < policy.valid_from_unix {
            return Err(BadgerError::PolicyInvalid(format!(
                "Network policy '{}' v{} not yet valid (starts at {})",
                policy.id, policy.version, policy.valid_from_unix
            )));
        }

        // 2. Rule structure validation
        for r in &policy.rules {
            if r.min_port > r.max_port {
                return Err(BadgerError::PolicyInvalid(format!(
                    "Invalid port range in rule {}: min_port {} > max_port {}",
                    r.rule_id, r.min_port, r.max_port
                )));
            }

            let is_v4 = parse_ipv4_cidr(&r.destination_cidr).is_some();
            let is_v6 = parse_ipv6_cidr(&r.destination_cidr).is_some();
            if !is_v4 && !is_v6 {
                return Err(BadgerError::PolicyInvalid(format!(
                    "Invalid destination CIDR '{}' in rule {}",
                    r.destination_cidr, r.rule_id
                )));
            }
        }

        // 3. Signature verification
        let expected_sig = Self::compute_signature(policy, &self.signing_key);
        if !policy.signature.is_empty() && policy.signature != expected_sig {
            return Err(BadgerError::PolicyInvalid(format!(
                "Network policy '{}' signature verification failed: unauthorized or tampered policy",
                policy.id
            )));
        }

        Ok(())
    }

    /// Loads a validated policy into the active policy table with rollback tracking
    pub fn load_policy(&self, mut policy: NetworkPolicy) -> BadgerResult<()> {
        self.validate_policy(&policy)?;

        // Ensure signature is populated
        if policy.signature.is_empty() {
            policy.signature = Self::compute_signature(&policy, &self.signing_key);
        }

        // Sort rules by priority ascending
        policy.rules.sort_by_key(|r| r.priority);

        let workload_id = policy.workload_id.clone();

        let mut policies = self.policies.write().unwrap();
        let mut history = self.history.write().unwrap();

        // Check version monotonicity
        if let Some(existing) = policies.get(&workload_id) {
            if policy.version <= existing.version {
                return Err(BadgerError::PolicyInvalid(format!(
                    "Policy version regression rejected: attempted to deploy v{} over current v{}",
                    policy.version, existing.version
                )));
            }
            // Archive current policy for rollback
            history
                .entry(workload_id.clone())
                .or_default()
                .push(existing.clone());
        }

        // Persist to offline disk cache if enabled
        if let Some(ref dir) = self.cache_dir {
            let _ = self.save_policy_to_cache(dir, &policy);
        }

        policies.insert(workload_id, policy);
        Ok(())
    }

    /// Rolls back to the previously active policy for a workload
    pub fn rollback_policy(&self, workload_id: &str) -> BadgerResult<NetworkPolicy> {
        let mut history = self.history.write().unwrap();
        let prev_policy = history
            .get_mut(workload_id)
            .and_then(|stack| stack.pop())
            .ok_or_else(|| {
                BadgerError::PolicyInvalid(format!(
                    "No prior policy version available for rollback on workload '{}'",
                    workload_id
                ))
            })?;

        let mut policies = self.policies.write().unwrap();
        policies.insert(workload_id.to_string(), prev_policy.clone());

        // Update disk cache
        if let Some(ref dir) = self.cache_dir {
            let _ = self.save_policy_to_cache(dir, &prev_policy);
        }

        Ok(prev_policy)
    }

    pub fn get_policy(&self, workload_id: &str) -> Option<NetworkPolicy> {
        self.policies.read().unwrap().get(workload_id).cloned()
    }

    pub fn list_policies(&self) -> Vec<NetworkPolicy> {
        self.policies.read().unwrap().values().cloned().collect()
    }

    fn save_policy_to_cache(&self, dir: &Path, policy: &NetworkPolicy) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        let file_path = dir.join(format!("{}.json", policy.workload_id));
        let data = serde_json::to_string_pretty(policy)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(file_path, data)
    }

    fn load_cache_from_disk(&self, dir: &Path) -> std::io::Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(policy) = serde_json::from_str::<NetworkPolicy>(&content) {
                        if self.validate_policy(&policy).is_ok() {
                            let mut policies = self.policies.write().unwrap();
                            policies.insert(policy.workload_id.clone(), policy);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{NetworkAction, NetworkProtocol, NetworkRule};

    fn sample_policy(version: u32, valid_until: i64) -> NetworkPolicy {
        NetworkPolicy {
            id: "net-pol-1".to_string(),
            tenant_id: "tenant-a".to_string(),
            workload_id: "agent-123".to_string(),
            version,
            default_action: NetworkAction::Deny,
            block_cloud_metadata: true,
            rules: vec![NetworkRule {
                rule_id: 1,
                direction: crate::types::NetworkDirection::Egress,
                destination_cidr: "10.20.0.0/16".to_string(),
                min_port: 443,
                max_port: 443,
                protocol: NetworkProtocol::Tcp,
                action: NetworkAction::Allow,
                priority: 100,
                description: "Allow internal TLS".to_string(),
            }],
            valid_from_unix: 0,
            valid_until_unix: valid_until,
            signature: String::new(),
            issuer: "security-team".to_string(),
        }
    }

    #[test]
    fn test_policy_signing_and_tampering() {
        let engine = NetworkPolicyEngine::new("secret-key", None);
        let mut policy = sample_policy(1, Utc::now().timestamp() + 3600);

        // Sign
        policy.signature = NetworkPolicyEngine::compute_signature(&policy, "secret-key");
        assert!(engine.load_policy(policy.clone()).is_ok());

        // Tamper with rule
        let mut tampered = policy.clone();
        tampered.version = 2;
        tampered.rules[0].min_port = 80;
        // Signature not recomputed
        assert!(engine.load_policy(tampered).is_err());
    }

    #[test]
    fn test_policy_expiration() {
        let engine = NetworkPolicyEngine::new("secret-key", None);
        // Expired in past
        let expired = sample_policy(1, Utc::now().timestamp() - 60);
        assert!(engine.load_policy(expired).is_err());
    }

    #[test]
    fn test_policy_rollback_and_monotonicity() {
        let engine = NetworkPolicyEngine::new("secret-key", None);
        let now = Utc::now().timestamp();

        let mut v1 = sample_policy(1, now + 3600);
        v1.signature = NetworkPolicyEngine::compute_signature(&v1, "secret-key");
        assert!(engine.load_policy(v1).is_ok());

        let mut v2 = sample_policy(2, now + 3600);
        v2.signature = NetworkPolicyEngine::compute_signature(&v2, "secret-key");
        assert!(engine.load_policy(v2).is_ok());

        // Attempt regression to v1 -> rejected
        let mut v1_replay = sample_policy(1, now + 3600);
        v1_replay.signature = NetworkPolicyEngine::compute_signature(&v1_replay, "secret-key");
        assert!(engine.load_policy(v1_replay).is_err());

        // Rollback to v1 via explicit method -> succeeds
        let rolled_back = engine.rollback_policy("agent-123").unwrap();
        assert_eq!(rolled_back.version, 1);
    }

    #[test]
    fn test_offline_disk_cache() {
        let temp_dir = std::env::temp_dir().join(format!("badger_test_cache_{}", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();

        {
            let engine = NetworkPolicyEngine::new("secret-key", Some(temp_dir.clone()));
            let mut p = sample_policy(1, now + 3600);
            p.signature = NetworkPolicyEngine::compute_signature(&p, "secret-key");
            engine.load_policy(p).unwrap();
        }

        // New engine loading from existing cache directory
        {
            let engine2 = NetworkPolicyEngine::new("secret-key", Some(temp_dir.clone()));
            let cached = engine2.get_policy("agent-123");
            assert!(cached.is_some());
            assert_eq!(cached.unwrap().version, 1);
        }

        let _ = fs::remove_dir_all(temp_dir);
    }
}
