use crate::model::Policy;
use badger_common::{BadgerError, BadgerResult};
use sha2::{Digest, Sha256};

pub struct PolicySigner;

impl PolicySigner {
    /// Computes canonical digest of the policy specification
    pub fn compute_digest(policy: &Policy) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(policy.id.as_bytes());
        hasher.update(b"|");
        hasher.update(policy.tenant_id.as_bytes());
        hasher.update(b"|");
        hasher.update(policy.name.as_bytes());
        hasher.update(b"|");
        hasher.update(policy.version.to_be_bytes());
        hasher.update(b"|");
        hasher.update(policy.priority.to_be_bytes());
        hasher.update(b"|");
        hasher.update(policy.valid_from_unix.to_be_bytes());
        hasher.update(b"|");
        hasher.update(policy.valid_until_unix.to_be_bytes());
        hasher.update(b"|");

        for s in &policy.principal_selectors {
            hasher.update(s.as_bytes());
        }
        for s in &policy.workload_selectors {
            hasher.update(s.as_bytes());
        }
        for s in &policy.resource_selectors {
            hasher.update(s.as_bytes());
        }

        let allowed_json = serde_json::to_string(&policy.allowed_capabilities).unwrap_or_default();
        hasher.update(allowed_json.as_bytes());

        let denied_json = serde_json::to_string(&policy.denied_capabilities).unwrap_or_default();
        hasher.update(denied_json.as_bytes());

        let cond_json = serde_json::to_string(&policy.context_conditions).unwrap_or_default();
        hasher.update(cond_json.as_bytes());

        hasher.finalize().into()
    }

    /// Signs policy using secret key
    pub fn sign(policy: &Policy, secret_key: &[u8]) -> String {
        let digest = Self::compute_digest(policy);
        let mut h = Sha256::new();
        h.update(secret_key);
        h.update(digest);
        h.update(b"badger-capability-policy-sig");
        format!("{:x}", h.finalize())
    }

    /// Verifies policy signature
    pub fn verify(policy: &Policy, secret_key: &[u8]) -> BadgerResult<()> {
        if policy.signature.is_empty() {
            return Err(BadgerError::PolicyInvalid(format!(
                "Policy '{}' is unsigned",
                policy.id
            )));
        }

        let expected = Self::sign(policy, secret_key);
        if policy.signature != expected {
            return Err(BadgerError::PolicyInvalid(format!(
                "Cryptographic signature verification failed for policy '{}' v{}",
                policy.id, policy.version
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Policy;

    #[test]
    fn test_signature_and_tampering_detection() {
        let mut pol = Policy {
            id: "pol-sec".to_string(),
            tenant_id: "tenant-corp".to_string(),
            name: "Secure Policy".to_string(),
            version: 1,
            priority: 5,
            principal_selectors: vec!["agent-*".to_string()],
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
            provenance: "control_plane".to_string(),
        };

        let key = b"my-master-signing-secret";
        pol.signature = PolicySigner::sign(&pol, key);
        assert!(PolicySigner::verify(&pol, key).is_ok());

        // Tamper with policy
        pol.version = 2;
        assert!(PolicySigner::verify(&pol, key).is_err());
    }
}
