use crate::types::{Credential, CredentialType};
use badger_common::{BadgerError, BadgerResult};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Implements standard RFC 2104 HMAC-SHA256 without requiring external crates
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hash = hasher.finalize();
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = [0x5cu8; BLOCK_SIZE];
    let mut i_key_pad = [0x36u8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        o_key_pad[i] ^= key_block[i];
        i_key_pad[i] ^= key_block[i];
    }

    // Inner hash: H(i_key_pad || data)
    let mut inner = Sha256::new();
    inner.update(&i_key_pad);
    inner.update(data);
    let inner_hash = inner.finalize();

    // Outer hash: H(o_key_pad || inner_hash)
    let mut outer = Sha256::new();
    outer.update(&o_key_pad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

pub struct CredentialIntelligenceStore {
    tenant_salt_keys: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    credentials: Arc<RwLock<HashMap<String, Credential>>>, // cred_id -> Credential
    fingerprint_to_workloads: Arc<RwLock<HashMap<String, std::collections::HashSet<String>>>>,
    workload_credentials: Arc<RwLock<HashMap<String, Vec<String>>>>, // workload_id -> Vec<cred_id>
}

impl Default for CredentialIntelligenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialIntelligenceStore {
    pub fn new() -> Self {
        Self {
            tenant_salt_keys: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
            fingerprint_to_workloads: Arc::new(RwLock::new(HashMap::new())),
            workload_credentials: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Sets or gets the tenant's secret salt key for HMAC fingerprinting
    fn get_tenant_key(&self, tenant_id: &str) -> [u8; 32] {
        let mut keys = self.tenant_salt_keys.write().unwrap();
        *keys.entry(tenant_id.to_string()).or_insert_with(|| {
            let mut hasher = Sha256::new();
            hasher.update(tenant_id.as_bytes());
            hasher.update(b"badger-tenant-credential-hmac-salt");
            hasher.finalize().into()
        })
    }

    /// Generates a keyed HMAC-SHA256 fingerprint from a raw credential secret.
    /// The raw secret is never stored anywhere in memory or disk.
    pub fn fingerprint(&self, tenant_id: &str, raw_secret: &[u8]) -> String {
        let tenant_key = self.get_tenant_key(tenant_id);
        let hmac_bytes = compute_hmac_sha256(&tenant_key, raw_secret);
        format!("{:x}", Sha256::digest(hmac_bytes))
    }

    /// Registers a credential into the intelligence store using only metadata and raw secret for HMAC calculation
    pub fn register_credential(
        &self,
        tenant_id: &str,
        workload_id: &str,
        principal_id: &str,
        cred_type: CredentialType,
        issuer: &str,
        audience: &str,
        scope: Vec<String>,
        expires_at: DateTime<Utc>,
        raw_secret_for_fingerprint_only: &[u8],
    ) -> BadgerResult<Credential> {
        let fp = self.fingerprint(tenant_id, raw_secret_for_fingerprint_only);
        let cred_id = format!("cred_{}", Uuid::new_v4().simple());
        let now = Utc::now();

        let cred = Credential {
            id: cred_id.clone(),
            tenant_id: tenant_id.to_string(),
            credential_type: cred_type,
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            scope,
            fingerprint_hmac_sha256: fp.clone(),
            issued_at: now,
            expires_at,
            is_revoked: false,
            revoked_at: None,
            last_used_at: Some(now),
            use_count: 1,
            associated_principals: vec![principal_id.to_string()],
        };

        let mut creds = self.credentials.write().unwrap();
        creds.insert(cred_id.clone(), cred.clone());

        let mut fp_wkls = self.fingerprint_to_workloads.write().unwrap();
        fp_wkls
            .entry(fp.clone())
            .or_default()
            .insert(workload_id.to_string());

        let mut wkl_map = self.workload_credentials.write().unwrap();
        wkl_map
            .entry(workload_id.to_string())
            .or_default()
            .push(cred_id);

        Ok(cred)
    }

    pub fn get_credential(&self, id: &str) -> Option<Credential> {
        let creds = self.credentials.read().unwrap();
        creds.get(id).cloned()
    }

    pub fn list_credentials(&self, tenant_id: &str) -> Vec<Credential> {
        let creds = self.credentials.read().unwrap();
        creds
            .values()
            .filter(|c| c.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub fn record_usage(&self, cred_id: &str) -> BadgerResult<()> {
        let mut creds = self.credentials.write().unwrap();
        if let Some(c) = creds.get_mut(cred_id) {
            c.use_count += 1;
            c.last_used_at = Some(Utc::now());
            Ok(())
        } else {
            Err(BadgerError::Identity(format!(
                "Credential '{}' not found",
                cred_id
            )))
        }
    }

    pub fn revoke(&self, cred_id: &str) -> BadgerResult<()> {
        let mut creds = self.credentials.write().unwrap();
        if let Some(c) = creds.get_mut(cred_id) {
            c.is_revoked = true;
            c.revoked_at = Some(Utc::now());
            Ok(())
        } else {
            Err(BadgerError::Identity(format!(
                "Credential '{}' not found",
                cred_id
            )))
        }
    }

    /// Returns a list of workloads associated with a specific credential fingerprint
    pub fn get_workloads_sharing_credential(&self, fingerprint: &str) -> Vec<String> {
        let fp_wkls = self.fingerprint_to_workloads.read().unwrap();
        if let Some(wkl_set) = fp_wkls.get(fingerprint) {
            wkl_set.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_keyed_hmac_fingerprint_never_stores_raw() {
        let store = CredentialIntelligenceStore::new();
        let raw = b"super-secret-api-key-12345";
        let fp1 = store.fingerprint("tenant-1", raw);
        let fp2 = store.fingerprint("tenant-1", raw);
        let fp_other_tenant = store.fingerprint("tenant-2", raw);

        assert_eq!(fp1, fp2, "Fingerprint for same tenant and secret must match");
        assert_ne!(
            fp1, fp_other_tenant,
            "Fingerprint for different tenant must differ due to tenant salt"
        );
        assert!(!fp1.contains("super-secret"));
    }

    #[test]
    fn test_credential_lifecycle() {
        let store = CredentialIntelligenceStore::new();
        let cred = store
            .register_credential(
                "tenant-alpha",
                "wkl-1",
                "prn-1",
                CredentialType::ApiKey,
                "OpenAI",
                "api.openai.com",
                vec!["chat.completions".to_string()],
                Utc::now() + Duration::days(30),
                b"sk-antigravity-secret",
            )
            .unwrap();

        assert_eq!(cred.tenant_id, "tenant-alpha");
        assert_eq!(cred.use_count, 1);
        assert!(!cred.is_revoked);

        store.record_usage(&cred.id).unwrap();
        let updated = store.get_credential(&cred.id).unwrap();
        assert_eq!(updated.use_count, 2);

        store.revoke(&cred.id).unwrap();
        let revoked = store.get_credential(&cred.id).unwrap();
        assert!(revoked.is_revoked);
        assert!(revoked.revoked_at.is_some());
    }
}
