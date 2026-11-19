pub mod bpf_types;
pub mod dns;
pub mod enforcer;
pub mod policy;
pub mod telemetry;
pub mod types;

pub use dns::{DnsSecurityConfig, DnsSecurityManager, ResolvedDestination};
pub use enforcer::NetworkEnforcer;
pub use policy::NetworkPolicyEngine;
pub use telemetry::NetworkTelemetryRegistry;
pub use types::{
    NetworkAction, NetworkDecisionEvent, NetworkDirection, NetworkPolicy, NetworkPolicyBundle,
    NetworkProtocol, NetworkRule, NetworkStats,
};

use badger_common::BadgerResult;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::info;

#[derive(Clone)]
pub struct NetworkSecuritySubsystem {
    policy_engine: NetworkPolicyEngine,
    telemetry_registry: NetworkTelemetryRegistry,
    dns_manager: DnsSecurityManager,
    enforcers: Arc<RwLock<HashMap<String, Arc<NetworkEnforcer>>>>,
}

impl NetworkSecuritySubsystem {
    pub fn new(signing_key: &str, cache_dir: Option<PathBuf>) -> Self {
        Self {
            policy_engine: NetworkPolicyEngine::new(signing_key, cache_dir),
            telemetry_registry: NetworkTelemetryRegistry::new(),
            dns_manager: DnsSecurityManager::new(DnsSecurityConfig::default()),
            enforcers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn policy_engine(&self) -> &NetworkPolicyEngine {
        &self.policy_engine
    }

    pub fn telemetry_registry(&self) -> &NetworkTelemetryRegistry {
        &self.telemetry_registry
    }

    pub fn dns_manager(&self) -> &DnsSecurityManager {
        &self.dns_manager
    }

    /// Deploys or dynamically updates a network policy
    pub fn deploy_policy(&self, policy: NetworkPolicy) -> BadgerResult<()> {
        let workload_id = policy.workload_id.clone();
        self.policy_engine.load_policy(policy.clone())?;

        // If an enforcer is actively running for this workload, update in-kernel BPF maps
        let enforcers = self.enforcers.read().unwrap();
        if let Some(enforcer) = enforcers.get(&workload_id) {
            enforcer.update_policy(&policy)?;
            info!(
                "Dynamically updated kernel network enforcement for workload '{}' to v{}",
                workload_id, policy.version
            );
        }

        Ok(())
    }

    /// Rolls back active policy to previous version and updates running kernel enforcer
    pub fn rollback_policy(&self, workload_id: &str) -> BadgerResult<NetworkPolicy> {
        let rolled_back = self.policy_engine.rollback_policy(workload_id)?;

        let enforcers = self.enforcers.read().unwrap();
        if let Some(enforcer) = enforcers.get(workload_id) {
            enforcer.update_policy(&rolled_back)?;
            info!(
                "Kernel network enforcement for workload '{}' rolled back to v{}",
                workload_id, rolled_back.version
            );
        }

        Ok(rolled_back)
    }

    /// Attaches kernel network enforcement to a workload cgroup
    pub fn attach_enforcer(
        &self,
        workload_id: &str,
        cgroup_path: PathBuf,
    ) -> BadgerResult<Arc<NetworkEnforcer>> {
        let enforcer = Arc::new(NetworkEnforcer::new(workload_id, cgroup_path));

        // Get configured policy or synthesize default zero-trust deny policy
        let policy = self
            .policy_engine
            .get_policy(workload_id)
            .unwrap_or_else(|| NetworkPolicy {
                id: format!("net-pol-default-{}", workload_id),
                tenant_id: "default".to_string(),
                workload_id: workload_id.to_string(),
                version: 1,
                default_action: NetworkAction::Deny,
                block_cloud_metadata: true,
                rules: Vec::new(),
                valid_from_unix: 0,
                valid_until_unix: 0,
                signature: String::new(),
                issuer: "badger-kernel-security".to_string(),
            });

        // Attach eBPF programs
        enforcer.attach(&policy)?;

        // Pipe telemetry into central registry
        let mut rx = enforcer.subscribe();
        let registry = self.telemetry_registry.clone();
        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                registry.record_event(event);
            }
        });

        let mut enforcers = self.enforcers.write().unwrap();
        enforcers.insert(workload_id.to_string(), enforcer.clone());

        Ok(enforcer)
    }

    /// Detaches network enforcement for a workload
    pub fn detach_enforcer(&self, workload_id: &str) -> BadgerResult<()> {
        let mut enforcers = self.enforcers.write().unwrap();
        if let Some(enforcer) = enforcers.remove(workload_id) {
            enforcer.detach()?;
        }
        Ok(())
    }
}
