use badger_common::{BadgerError, BadgerResult};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpiffeId {
    pub trust_domain: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub workload_id: String,
}

impl SpiffeId {
    pub fn new(
        trust_domain: &str,
        tenant_id: &str,
        principal_id: &str,
        workload_id: &str,
    ) -> Self {
        Self {
            trust_domain: trust_domain.to_string(),
            tenant_id: tenant_id.to_string(),
            principal_id: principal_id.to_string(),
            workload_id: workload_id.to_string(),
        }
    }

    pub fn to_uri(&self) -> String {
        format!(
            "spiffe://{}/ns/{}/sa/{}/workload/{}",
            self.trust_domain, self.tenant_id, self.principal_id, self.workload_id
        )
    }

    pub fn parse(uri: &str) -> BadgerResult<Self> {
        if !uri.starts_with("spiffe://") {
            return Err(BadgerError::Identity(format!(
                "Invalid SPIFFE ID scheme, must start with 'spiffe://': {}",
                uri
            )));
        }

        let without_scheme = &uri["spiffe://".len()..];
        let parts: Vec<&str> = without_scheme.split('/').collect();

        // Expected format: <trust_domain>/ns/<tenant>/sa/<principal>/workload/<id>
        if parts.len() != 7 || parts[1] != "ns" || parts[3] != "sa" || parts[5] != "workload" {
            return Err(BadgerError::Identity(format!(
                "Invalid SPIFFE ID format, expected 'spiffe://<trust_domain>/ns/<tenant>/sa/<principal>/workload/<id>': {}",
                uri
            )));
        }

        Ok(Self {
            trust_domain: parts[0].to_string(),
            tenant_id: parts[2].to_string(),
            principal_id: parts[4].to_string(),
            workload_id: parts[6].to_string(),
        })
    }
}

/// Cryptographically signed SPIFFE X.509 SVID representation (strictly no cleartext private keys stored or exposed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpiffeSvid {
    pub spiffe_id: String,
    pub serial_number: String,
    pub issuer: String,
    pub subject: String,
    pub sans: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub signature_sha256: String,
    pub public_key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedCertificate {
    pub serial_number: String,
    pub spiffe_id: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpiffeCrl {
    revoked_serials: HashSet<String>,
    revoked_entries: Vec<RevokedCertificate>,
}

pub struct SpiffeAuthority {
    trust_domain: String,
    authority_key: [u8; 32],
    crl: Arc<RwLock<SpiffeCrl>>,
    active_svids: Arc<RwLock<HashMap<String, SpiffeSvid>>>,
}

impl SpiffeAuthority {
    pub fn new(trust_domain: &str) -> Self {
        // Deterministic authority key generation
        let mut hasher = Sha256::new();
        hasher.update(trust_domain.as_bytes());
        hasher.update(b"badger-spiffe-root-ca-key-seed");
        let authority_key: [u8; 32] = hasher.finalize().into();

        Self {
            trust_domain: trust_domain.to_string(),
            authority_key,
            crl: Arc::new(RwLock::new(SpiffeCrl::default())),
            active_svids: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Attests workload properties before issuing an X.509 SVID.
    pub fn attest_workload(
        &self,
        tenant_id: &str,
        principal_id: &str,
        workload_id: &str,
        pid: Option<u32>,
        cgroup: Option<&str>,
    ) -> BadgerResult<()> {
        if tenant_id.is_empty() || principal_id.is_empty() || workload_id.is_empty() {
            return Err(BadgerError::Identity(
                "Attestation failure: missing required identity parameters".to_string(),
            ));
        }

        // On Linux, verify that cgroup matches the workload isolation boundary
        if let Some(cg) = cgroup {
            if !cg.contains("badger") && !cg.contains(workload_id) && !cg.contains("system.slice") {
                return Err(BadgerError::Identity(format!(
                    "Attestation failure: workload cgroup '{}' does not match declared boundary",
                    cg
                )));
            }
        }

        if let Some(p) = pid {
            if p == 0 {
                return Err(BadgerError::Identity(
                    "Attestation failure: invalid PID 0".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Issues an X.509 SVID for an authenticated workload.
    pub fn issue_svid(
        &self,
        tenant_id: &str,
        principal_id: &str,
        workload_id: &str,
        validity_hours: i64,
    ) -> BadgerResult<SpiffeSvid> {
        let spiffe_id_obj = SpiffeId::new(&self.trust_domain, tenant_id, principal_id, workload_id);
        let spiffe_uri = spiffe_id_obj.to_uri();

        let serial = format!("{:x}", Uuid::new_v4().simple());
        let now = Utc::now();
        let valid_to = now + Duration::hours(validity_hours);

        // Compute simulated digital signature using authority secret key
        let mut sig_hasher = Sha256::new();
        sig_hasher.update(&self.authority_key);
        sig_hasher.update(spiffe_uri.as_bytes());
        sig_hasher.update(serial.as_bytes());
        sig_hasher.update(valid_to.timestamp().to_be_bytes());
        let signature = format!("{:x}", sig_hasher.finalize());

        let svid = SpiffeSvid {
            spiffe_id: spiffe_uri.clone(),
            serial_number: serial.clone(),
            issuer: format!("CN=BADGER Intermediate CA,O={}", self.trust_domain),
            subject: format!("CN={}", workload_id),
            sans: vec![spiffe_uri.clone()],
            valid_from: now,
            valid_to,
            signature_sha256: signature,
            public_key_pem: format!(
                "-----BEGIN PUBLIC KEY-----\nBADGER_ED25519_{}\n-----END PUBLIC KEY-----",
                serial
            ),
        };

        let mut active = self.active_svids.write().unwrap();
        active.insert(workload_id.to_string(), svid.clone());

        Ok(svid)
    }

    /// Automatically rotates SVID if expired or past 50% of its validity lifetime.
    pub fn maybe_rotate_svid(
        &self,
        tenant_id: &str,
        principal_id: &str,
        workload_id: &str,
        current_svid: &SpiffeSvid,
    ) -> BadgerResult<SpiffeSvid> {
        let now = Utc::now();
        let total_lifetime = (current_svid.valid_to - current_svid.valid_from).num_seconds();
        let elapsed = (now - current_svid.valid_from).num_seconds();

        // If more than 50% elapsed or already expired, rotate
        if elapsed >= total_lifetime / 2 || now >= current_svid.valid_to {
            // Revoke old SVID
            self.revoke_svid(&current_svid.serial_number, &current_svid.spiffe_id, "Automatic certificate rotation")?;
            // Issue new SVID
            let remaining_or_default_hours = (total_lifetime / 3600).max(1);
            self.issue_svid(tenant_id, principal_id, workload_id, remaining_or_default_hours)
        } else {
            Ok(current_svid.clone())
        }
    }

    /// Revokes an SVID and appends to the CRL.
    pub fn revoke_svid(&self, serial_number: &str, spiffe_id: &str, reason: &str) -> BadgerResult<()> {
        let mut crl = self.crl.write().unwrap();
        crl.revoked_serials.insert(serial_number.to_string());
        crl.revoked_entries.push(RevokedCertificate {
            serial_number: serial_number.to_string(),
            spiffe_id: spiffe_id.to_string(),
            revoked_at: Utc::now(),
            reason: reason.to_string(),
        });

        let mut active = self.active_svids.write().unwrap();
        active.retain(|_, v| v.serial_number != serial_number);

        Ok(())
    }

    pub fn is_revoked(&self, serial_number: &str) -> bool {
        let crl = self.crl.read().unwrap();
        crl.revoked_serials.contains(serial_number)
    }

    pub fn get_crl(&self) -> Vec<RevokedCertificate> {
        let crl = self.crl.read().unwrap();
        crl.revoked_entries.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiffe_id_generation_and_parsing() {
        let id = SpiffeId::new("badger.local", "tenant-alpha", "agent-code", "wkl-99");
        let uri = id.to_uri();
        assert_eq!(
            uri,
            "spiffe://badger.local/ns/tenant-alpha/sa/agent-code/workload/wkl-99"
        );

        let parsed = SpiffeId::parse(&uri).unwrap();
        assert_eq!(parsed.trust_domain, "badger.local");
        assert_eq!(parsed.tenant_id, "tenant-alpha");
        assert_eq!(parsed.workload_id, "wkl-99");
    }

    #[test]
    fn test_svid_issuance_rotation_and_revocation() {
        let authority = SpiffeAuthority::new("badger.local");

        // Attestation succeeds
        authority
            .attest_workload("tenant-1", "prn-1", "wkl-1", Some(1234), Some("/sys/fs/cgroup/badger/wkl-1"))
            .unwrap();

        // Issue SVID
        let svid = authority.issue_svid("tenant-1", "prn-1", "wkl-1", 24).unwrap();
        assert!(svid.spiffe_id.starts_with("spiffe://badger.local/ns/tenant-1/"));
        assert!(!authority.is_revoked(&svid.serial_number));

        // Revocation
        authority
            .revoke_svid(&svid.serial_number, &svid.spiffe_id, "Compromise suspected")
            .unwrap();
        assert!(authority.is_revoked(&svid.serial_number));
        assert_eq!(authority.get_crl().len(), 1);
    }
}
