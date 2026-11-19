pub mod access;
pub mod connectors;
pub mod credentials;
pub mod drift;
pub mod graph;
pub mod spiffe;
pub mod types;

pub use access::{AccessProvenance, EffectiveAccessAnalyzer, EffectivePermission, OverPrivilegedFinding};
pub use connectors::{
    BadgerWorkloadConnector, ConnectorRegistry, ConnectorStatus, DockerConnector,
    IdentityConnector, KubernetesConnector, LinuxProcessConnector,
};
pub use credentials::{compute_hmac_sha256, CredentialIntelligenceStore};
pub use drift::IdentityDriftDetector;
pub use graph::{EdgeDirection, IdentityGraph, IdentityNode};
pub use spiffe::{RevokedCertificate, SpiffeAuthority, SpiffeCrl, SpiffeId, SpiffeSvid};
pub use types::*;

use badger_common::{
    BadgerError, BadgerResult, CredentialMetadata, Principal as CommonPrincipal,
    PrincipalType as CommonPrincipalType, SensorHealthStatus as CommonSensorHealth,
    Tenant as CommonTenant, Workload as CommonWorkload, WorkloadState as CommonWorkloadState,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct WorkloadRegistration {
    pub tenant_id: String,
    pub principal_id: String,
    pub workload_name: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct IdentityStore {
    tenants: Arc<RwLock<HashMap<String, CommonTenant>>>,
    principals: Arc<RwLock<HashMap<String, CommonPrincipal>>>,
    workloads: Arc<RwLock<HashMap<String, CommonWorkload>>>,
    credentials: Arc<RwLock<HashMap<String, Vec<CredentialMetadata>>>>,
}

impl Default for IdentityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityStore {
    pub fn new() -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
            principals: Arc::new(RwLock::new(HashMap::new())),
            workloads: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register_tenant(&self, id: &str, name: &str) -> BadgerResult<CommonTenant> {
        let tenant = CommonTenant {
            id: id.to_string(),
            name: name.to_string(),
            created_at: Utc::now(),
        };
        let mut map = self.tenants.write().unwrap();
        map.insert(id.to_string(), tenant.clone());
        Ok(tenant)
    }

    pub fn register_principal(
        &self,
        tenant_id: &str,
        name: &str,
        p_type: CommonPrincipalType,
        labels: HashMap<String, String>,
    ) -> BadgerResult<CommonPrincipal> {
        {
            let tenants = self.tenants.read().unwrap();
            if !tenants.contains_key(tenant_id) {
                return Err(BadgerError::Identity(format!(
                    "Tenant '{}' does not exist",
                    tenant_id
                )));
            }
        }

        let principal_id = format!("prn:{}:{}", tenant_id, Uuid::new_v4());
        let principal = CommonPrincipal {
            id: principal_id.clone(),
            tenant_id: tenant_id.to_string(),
            name: name.to_string(),
            principal_type: p_type,
            labels,
            created_at: Utc::now(),
        };

        let mut map = self.principals.write().unwrap();
        map.insert(principal_id, principal.clone());
        Ok(principal)
    }

    pub fn register_workload(&self, reg: WorkloadRegistration) -> BadgerResult<CommonWorkload> {
        {
            let tenants = self.tenants.read().unwrap();
            if !tenants.contains_key(&reg.tenant_id) {
                return Err(BadgerError::Identity(format!(
                    "Tenant '{}' not found",
                    reg.tenant_id
                )));
            }
        }

        {
            let principals = self.principals.read().unwrap();
            if !principals.contains_key(&reg.principal_id) {
                return Err(BadgerError::Identity(format!(
                    "Principal '{}' not found",
                    reg.principal_id
                )));
            }
        }

        let uuid = Uuid::new_v4();
        let workload_id = format!("wkl_{}", uuid.simple());
        let spiffe_id = format!(
            "spiffe://badger.local/ns/{}/workload/{}",
            reg.tenant_id, workload_id
        );

        let mut meta = reg.metadata;
        meta.insert("spiffe_id".to_string(), spiffe_id);
        meta.insert("registered_by".to_string(), "badger-identity-engine".to_string());

        let now = Utc::now();
        let workload = CommonWorkload {
            id: workload_id.clone(),
            tenant_id: reg.tenant_id,
            principal_id: reg.principal_id,
            name: reg.workload_name,
            state: CommonWorkloadState::Registered,
            policy_id: reg.policy_id,
            policy_version: reg.policy_version,
            metadata: meta,
            registered_at: now,
            updated_at: now,
            sensor_status: CommonSensorHealth::Unknown,
        };

        let mut map = self.workloads.write().unwrap();
        map.insert(workload_id, workload.clone());
        Ok(workload)
    }

    pub fn get_workload(&self, id: &str) -> Option<CommonWorkload> {
        let map = self.workloads.read().unwrap();
        map.get(id).cloned()
    }

    pub fn list_workloads(&self) -> Vec<CommonWorkload> {
        let map = self.workloads.read().unwrap();
        map.values().cloned().collect()
    }

    pub fn update_workload_state(&self, id: &str, state: CommonWorkloadState) -> BadgerResult<()> {
        let mut map = self.workloads.write().unwrap();
        if let Some(w) = map.get_mut(id) {
            w.state = state;
            w.updated_at = Utc::now();
            Ok(())
        } else {
            Err(BadgerError::Identity(format!("Workload '{}' not found", id)))
        }
    }

    pub fn update_sensor_status(&self, id: &str, status: CommonSensorHealth) -> BadgerResult<()> {
        let mut map = self.workloads.write().unwrap();
        if let Some(w) = map.get_mut(id) {
            w.sensor_status = status;
            w.updated_at = Utc::now();
            Ok(())
        } else {
            Err(BadgerError::Identity(format!("Workload '{}' not found", id)))
        }
    }

    pub fn attach_credential(
        &self,
        tenant_id: &str,
        workload_id: &str,
        cred_type: &str,
        issuer: &str,
        audience: &str,
        expires_at: chrono::DateTime<Utc>,
        raw_token_for_fingerprint_only: &[u8],
    ) -> BadgerResult<CredentialMetadata> {
        let mut hasher = Sha256::new();
        hasher.update(raw_token_for_fingerprint_only);
        let fingerprint = format!("{:x}", hasher.finalize());

        let meta = CredentialMetadata {
            id: format!("crd_{}", Uuid::new_v4().simple()),
            tenant_id: tenant_id.to_string(),
            workload_id: workload_id.to_string(),
            credential_type: cred_type.to_string(),
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            issued_at: Utc::now(),
            expires_at,
            is_revoked: false,
            fingerprint_sha256: fingerprint,
        };

        let mut map = self.credentials.write().unwrap();
        map.entry(workload_id.to_string())
            .or_default()
            .push(meta.clone());

        Ok(meta)
    }

    pub fn get_credentials(&self, workload_id: &str) -> Vec<CredentialMetadata> {
        let map = self.credentials.read().unwrap();
        map.get(workload_id).cloned().unwrap_or_default()
    }

    pub fn revoke_credential(&self, workload_id: &str, cred_id: &str) -> BadgerResult<()> {
        let mut map = self.credentials.write().unwrap();
        if let Some(creds) = map.get_mut(workload_id) {
            for c in creds {
                if c.id == cred_id {
                    c.is_revoked = true;
                    return Ok(());
                }
            }
        }
        Err(BadgerError::Identity(format!(
            "Credential '{}' not found for workload '{}'",
            cred_id, workload_id
        )))
    }

    pub fn detect_drift(
        &self,
        workload_id: &str,
        observed_tenant: &str,
        observed_policy_version: u32,
    ) -> Option<String> {
        if let Some(w) = self.get_workload(workload_id) {
            if w.tenant_id != observed_tenant {
                return Some(format!(
                    "Tenant drift: expected '{}', observed '{}'",
                    w.tenant_id, observed_tenant
                ));
            }
            if w.policy_version != observed_policy_version {
                return Some(format!(
                    "Policy version drift: registered version {}, observed version {}",
                    w.policy_version, observed_policy_version
                ));
            }
        } else {
            return Some(format!("Unregistered workload: '{}'", workload_id));
        }
        None
    }
}

/// Unified Identity Intelligence Subsystem coordinating discovery, graph correlation,
/// SPIFFE credentials, effective access, and drift analysis.
pub struct IdentityIntelligenceSubsystem {
    pub store: Arc<IdentityStore>,
    pub graph: Arc<RwLock<IdentityGraph>>,
    pub connectors: Arc<RwLock<ConnectorRegistry>>,
    pub spiffe: Arc<SpiffeAuthority>,
    pub credentials: Arc<CredentialIntelligenceStore>,
    pub access: Arc<RwLock<EffectiveAccessAnalyzer>>,
    pub drift: Arc<IdentityDriftDetector>,
}

impl IdentityIntelligenceSubsystem {
    pub fn new(trust_domain: &str) -> Self {
        let mut connectors = ConnectorRegistry::new();
        connectors.register(Box::new(LinuxProcessConnector::default()));
        connectors.register(Box::new(DockerConnector::default()));
        connectors.register(Box::new(KubernetesConnector::default()));

        Self {
            store: Arc::new(IdentityStore::new()),
            graph: Arc::new(RwLock::new(IdentityGraph::new())),
            connectors: Arc::new(RwLock::new(connectors)),
            spiffe: Arc::new(SpiffeAuthority::new(trust_domain)),
            credentials: Arc::new(CredentialIntelligenceStore::new()),
            access: Arc::new(RwLock::new(EffectiveAccessAnalyzer::new())),
            drift: Arc::new(IdentityDriftDetector::default()),
        }
    }

    /// Discovers runtime identities via all available connectors
    pub fn discover_identities(&self, tenant_id: &str) -> Vec<IdentityObservation> {
        let connectors = self.connectors.read().unwrap();
        connectors.run_discovery(tenant_id)
    }

    /// Synchronizes registered workloads and principals from store into the typed Identity Graph
    pub fn sync_graph_from_store(&self, tenant_id: &str) {
        let mut graph = self.graph.write().unwrap();
        let workloads = self.store.list_workloads();

        for w in &workloads {
            if w.tenant_id == tenant_id {
                // Add principal node
                graph.add_node(IdentityNode {
                    id: w.principal_id.clone(),
                    tenant_id: tenant_id.to_string(),
                    entity_type: "Principal".to_string(),
                    label: format!("Principal {}", w.principal_id),
                    properties: HashMap::new(),
                });

                // Add workload node
                let mut w_props = HashMap::new();
                w_props.insert("name".to_string(), w.name.clone());
                w_props.insert("policy_id".to_string(), w.policy_id.clone());
                w_props.insert("spiffe_id".to_string(), w.metadata.get("spiffe_id").cloned().unwrap_or_default());

                graph.add_node(IdentityNode {
                    id: w.id.clone(),
                    tenant_id: tenant_id.to_string(),
                    entity_type: "Workload".to_string(),
                    label: w.name.clone(),
                    properties: w_props,
                });

                // Add OWNS edge: Principal -> Workload
                graph.add_relationship(Relationship {
                    id: format!("rel_owns_{}_{}", w.principal_id, w.id),
                    tenant_id: tenant_id.to_string(),
                    source_id: w.principal_id.clone(),
                    target_id: w.id.clone(),
                    relationship_type: RelationshipType::OWNS,
                    kind: RelationshipKind::Direct,
                    confidence: 1.0,
                    source_attribution: "control_plane".to_string(),
                    valid_from: Utc::now(),
                    valid_to: None,
                    metadata: HashMap::new(),
                });
            }
        }
    }

    /// Evaluates identity drift across the environment
    pub fn evaluate_drift(&self, tenant_id: &str) -> Vec<IdentityFinding> {
        let graph = self.graph.read().unwrap();
        let common_workloads = self.store.list_workloads();
        let workloads: Vec<Workload> = common_workloads
            .into_iter()
            .map(|cw| Workload {
                id: cw.id,
                tenant_id: cw.tenant_id,
                principal_id: cw.principal_id,
                name: cw.name,
                state: match cw.state {
                    CommonWorkloadState::Registered => WorkloadState::Registered,
                    CommonWorkloadState::Staging => WorkloadState::Staging,
                    CommonWorkloadState::Running => WorkloadState::Running,
                    CommonWorkloadState::Suspended => WorkloadState::Suspended,
                    CommonWorkloadState::Contained => WorkloadState::Contained,
                    CommonWorkloadState::Terminated => WorkloadState::Terminated,
                    CommonWorkloadState::Failed => WorkloadState::Failed,
                },
                spiffe_id: cw.metadata.get("spiffe_id").cloned().unwrap_or_default(),
                cgroup_path: None,
                pid: None,
                policy_id: cw.policy_id,
                policy_version: cw.policy_version,
                metadata: cw.metadata,
                registered_at: cw.registered_at,
                updated_at: cw.updated_at,
                sensor_status: match cw.sensor_status {
                    CommonSensorHealth::Protected => SensorHealthStatus::Protected,
                    CommonSensorHealth::Degraded => SensorHealthStatus::Degraded,
                    CommonSensorHealth::Unprotected => SensorHealthStatus::Unprotected,
                    CommonSensorHealth::Unknown => SensorHealthStatus::Unknown,
                },
            })
            .collect();

        self.drift.evaluate(tenant_id, &graph, &workloads, &self.credentials)
    }

    /// Computes transitive effective access for an entity
    pub fn compute_effective_access(&self, entity_id: &str) -> Vec<EffectivePermission> {
        let graph = self.graph.read().unwrap();
        let access = self.access.read().unwrap();
        access.compute_effective_access(&graph, entity_id)
    }

    /// Exports the graph visualization JSON
    pub fn export_visualization(&self, tenant_id: &str) -> serde_json::Value {
        let graph = self.graph.read().unwrap();
        let filtered = graph.filter_by_tenant(tenant_id);
        filtered.to_visualization_json()
    }
}
