use crate::compiler::{CompiledPolicy, PolicyCompiler};
use crate::model::Policy;
use crate::signer::PolicySigner;
use badger_common::{BadgerError, BadgerResult};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub struct PolicyDistributor {
    signing_key: Vec<u8>,
    cache_dir: PathBuf,
    active_policies: Arc<RwLock<HashMap<String, CompiledPolicy>>>,
    staging_policies: Arc<RwLock<HashMap<String, CompiledPolicy>>>,
    version_history: Arc<RwLock<HashMap<String, Vec<Policy>>>>, // policy_id -> history
}

impl PolicyDistributor {
    pub fn new(signing_key: &[u8], cache_dir: &Path) -> Self {
        let _ = fs::create_dir_all(cache_dir);
        Self {
            signing_key: signing_key.to_vec(),
            cache_dir: cache_dir.to_path_buf(),
            active_policies: Arc::new(RwLock::new(HashMap::new())),
            staging_policies: Arc::new(RwLock::new(HashMap::new())),
            version_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Stages a proposed policy for validation, simulation, and operator approval
    pub fn stage_policy(&self, mut policy: Policy) -> BadgerResult<CompiledPolicy> {
        policy.is_staging = true;

        // 1. Verify signature
        PolicySigner::verify(&policy, &self.signing_key)?;

        // 2. Validate and compile
        let compiled = PolicyCompiler::compile(policy.clone())?;

        let mut staging = self.staging_policies.write().unwrap();
        staging.insert(policy.id.clone(), compiled.clone());

        Ok(compiled)
    }

    /// Activates a validated policy with anti-rollback protection and persistence to offline disk cache
    pub fn activate_policy(&self, mut policy: Policy) -> BadgerResult<CompiledPolicy> {
        policy.is_staging = false;

        // 1. Verify signature
        PolicySigner::verify(&policy, &self.signing_key)?;

        // 2. Anti-rollback check: new version must be strictly greater than current active version
        {
            let active = self.active_policies.read().unwrap();
            if let Some(current) = active.get(&policy.id) {
                if policy.version <= current.policy.version {
                    return Err(BadgerError::PolicyInvalid(format!(
                        "Rollback attack rejected: proposed version {} <= active version {}",
                        policy.version, current.policy.version
                    )));
                }
            }
        }

        // 3. Compile
        let compiled = PolicyCompiler::compile(policy.clone())?;

        // 4. Archive current version to rollback history
        {
            let mut active = self.active_policies.write().unwrap();
            let mut history = self.version_history.write().unwrap();

            if let Some(prev) = active.get(&policy.id) {
                history
                    .entry(policy.id.clone())
                    .or_default()
                    .push(prev.policy.clone());
            }

            active.insert(policy.id.clone(), compiled.clone());
        }

        // 5. Remove from staging if present
        {
            let mut staging = self.staging_policies.write().unwrap();
            staging.remove(&policy.id);
        }

        // 6. Persist to offline disk cache for survivability during control plane outages
        let cache_file = self.cache_dir.join(format!("{}.json", policy.id));
        if let Ok(json_data) = serde_json::to_string_pretty(&policy) {
            let _ = fs::write(cache_file, json_data);
        }

        Ok(compiled)
    }

    /// Performs an authorized rollback to the immediately preceding version in history
    pub fn rollback_policy(&self, policy_id: &str) -> BadgerResult<CompiledPolicy> {
        let mut history = self.version_history.write().unwrap();
        let prev_policy = history
            .get_mut(policy_id)
            .and_then(|list| list.pop())
            .ok_or_else(|| {
                BadgerError::PolicyInvalid(format!(
                    "No rollback history available for policy '{}'",
                    policy_id
                ))
            })?;

        // Compile and restore
        let compiled = PolicyCompiler::compile(prev_policy.clone())?;
        let mut active = self.active_policies.write().unwrap();
        active.insert(policy_id.to_string(), compiled.clone());

        // Update offline cache
        let cache_file = self.cache_dir.join(format!("{}.json", policy_id));
        if let Ok(json_data) = serde_json::to_string_pretty(&prev_policy) {
            let _ = fs::write(cache_file, json_data);
        }

        Ok(compiled)
    }

    /// Loads policies from offline disk cache on agent startup or during control plane disconnection
    pub fn load_offline_cache(&self) -> BadgerResult<usize> {
        if !self.cache_dir.exists() {
            return Ok(0);
        }

        let mut loaded = 0;
        let entries = fs::read_dir(&self.cache_dir).map_err(BadgerError::Io)?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(policy) = serde_json::from_str::<Policy>(&content) {
                        if PolicySigner::verify(&policy, &self.signing_key).is_ok() {
                            if let Ok(compiled) = PolicyCompiler::compile(policy.clone()) {
                                let mut active = self.active_policies.write().unwrap();
                                active.insert(policy.id.clone(), compiled);
                                loaded += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(loaded)
    }

    pub fn get_active_compiled_policies(&self) -> Vec<CompiledPolicy> {
        let active = self.active_policies.read().unwrap();
        active.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_distributor_anti_rollback_and_cache() {
        let dir = std::env::temp_dir().join(format!("badger_test_dist_{}", Uuid::new_v4().simple()));
        let _ = fs::create_dir_all(&dir);
        let key = b"master-dist-key";
        let distributor = PolicyDistributor::new(key, &dir);

        let mut pol_v1 = Policy {
            id: "pol-prod".to_string(),
            tenant_id: "tenant-a".to_string(),
            name: "Prod Policy".to_string(),
            version: 1,
            priority: 1,
            principal_selectors: vec!["*".to_string()],
            workload_selectors: vec!["*".to_string()],
            resource_selectors: vec!["*".to_string()],
            allowed_capabilities: Vec::new(),
            denied_capabilities: Vec::new(),
            context_conditions: Vec::new(),
            approval_requirements: None,
            valid_from_unix: 0,
            valid_until_unix: 0,
            is_staging: false,
            signature: String::new(),
            provenance: "test".to_string(),
        };
        pol_v1.signature = PolicySigner::sign(&pol_v1, key);
        distributor.activate_policy(pol_v1.clone()).unwrap();

        // Activate v2
        let mut pol_v2 = pol_v1.clone();
        pol_v2.version = 2;
        pol_v2.signature = PolicySigner::sign(&pol_v2, key);
        distributor.activate_policy(pol_v2).unwrap();

        // Attempt rollback to v1 via activate_policy -> must be rejected
        let res_rollback_attack = distributor.activate_policy(pol_v1);
        assert!(res_rollback_attack.is_err(), "Must reject rollback attack");

        // Legitimate rollback via rollback_policy
        let restored = distributor.rollback_policy("pol-prod").unwrap();
        assert_eq!(restored.policy.version, 1);
    }
}
