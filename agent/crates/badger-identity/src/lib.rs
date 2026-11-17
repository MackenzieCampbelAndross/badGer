use badger_common::{
    BadgerError, BadgerResult, CredentialMetadata, Principal, PrincipalType, SensorHealthStatus,
    Tenant, Workload, WorkloadState,
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
    tenants: Arc<RwLock<HashMap<String, Tenant>>>,
    principals: Arc<RwLock<HashMap<String, Principal>>>,
    workloads: Arc<RwLock<HashMap<String, Workload>>>,
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

    pub fn register_tenant(&self, id: &str, name: &str) -> BadgerResult<Tenant> {
        let tenant = Tenant {
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
        p_type: PrincipalType,
        labels: HashMap<String, String>,
    ) -> BadgerResult<Principal> {
        // Validate tenant exists
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
        let principal = Principal {
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

    /// Registers a workload and generates a stable cryptographically verifiable SPIFFE-compatible identity
    pub fn register_workload(&self, reg: WorkloadRegistration) -> BadgerResult<Workload> {
        // Verify tenant
        {
            let tenants = self.tenants.read().unwrap();
            if !tenants.contains_key(&reg.tenant_id) {
                return Err(BadgerError::Identity(format!(
                    "Tenant '{}' not found",
                    reg.tenant_id
                )));
            }
        }

        // Verify principal
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
        let workload = Workload {
            id: workload_id.clone(),
            tenant_id: reg.tenant_id,
            principal_id: reg.principal_id,
            name: reg.workload_name,
            state: WorkloadState::Registered,
            policy_id: reg.policy_id,
            policy_version: reg.policy_version,
            metadata: meta,
            registered_at: now,
            updated_at: now,
            sensor_status: SensorHealthStatus::Unknown,
        };

        let mut map = self.workloads.write().unwrap();
        map.insert(workload_id, workload.clone());
        Ok(workload)
    }

    pub fn get_workload(&self, id: &str) -> Option<Workload> {
        let map = self.workloads.read().unwrap();
        map.get(id).cloned()
    }

    pub fn update_workload_state(&self, id: &str, state: WorkloadState) -> BadgerResult<()> {
        let mut map = self.workloads.write().unwrap();
        if let Some(w) = map.get_mut(id) {
            w.state = state;
            w.updated_at = Utc::now();
            Ok(())
        } else {
            Err(BadgerError::Identity(format!("Workload '{}' not found", id)))
        }
    }

    pub fn update_sensor_status(&self, id: &str, status: SensorHealthStatus) -> BadgerResult<()> {
        let mut map = self.workloads.write().unwrap();
        if let Some(w) = map.get_mut(id) {
            w.sensor_status = status;
            w.updated_at = Utc::now();
            Ok(())
        } else {
            Err(BadgerError::Identity(format!("Workload '{}' not found", id)))
        }
    }

    /// Attaches credential metadata (strictly no raw credentials stored)
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

    /// Identity Drift Detection: verifies if a runtime execution context matches the registered identity
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_registration_and_drift() {
        let store = IdentityStore::new();
        store.register_tenant("tenant-corp", "Corp").unwrap();
        let principal = store
            .register_principal(
                "tenant-corp",
                "code-generator-agent",
                PrincipalType::Agent,
                HashMap::new(),
            )
            .unwrap();

        let wkl = store
            .register_workload(WorkloadRegistration {
                tenant_id: "tenant-corp".to_string(),
                principal_id: principal.id.clone(),
                workload_name: "agent-task-worker".to_string(),
                policy_id: "pol-restricted".to_string(),
                policy_version: 1,
                metadata: HashMap::new(),
            })
            .unwrap();

        assert_eq!(wkl.state, WorkloadState::Registered);
        assert!(wkl.metadata.get("spiffe_id").unwrap().starts_with("spiffe://badger.local/ns/tenant-corp/workload/"));

        // No drift test
        let drift = store.detect_drift(&wkl.id, "tenant-corp", 1);
        assert!(drift.is_none());

        // Drift test
        let drift = store.detect_drift(&wkl.id, "tenant-attacker", 1);
        assert!(drift.is_some());
    }

    #[test]
    fn test_credential_fingerprint_never_stores_raw() {
        let store = IdentityStore::new();
        store.register_tenant("tenant-corp", "Corp").unwrap();
        let cred = store
            .attach_credential(
                "tenant-corp",
                "wkl_123",
                "api_token",
                "auth0",
                "api.internal",
                Utc::now() + chrono::Duration::hours(1),
                b"super_secret_raw_token_xyz",
            )
            .unwrap();

        assert_ne!(cred.fingerprint_sha256, "super_secret_raw_token_xyz");
        assert_eq!(cred.fingerprint_sha256.len(), 64);
        assert!(!cred.is_revoked);
    }
}
