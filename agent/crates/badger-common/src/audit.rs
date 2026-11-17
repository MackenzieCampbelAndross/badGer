use crate::error::BadgerResult;
use crate::types::AuditRecord;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use uuid::Uuid;

pub struct AuditLogger {
    prev_hash: Mutex<String>,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new("0000000000000000000000000000000000000000000000000000000000000000")
    }
}

impl AuditLogger {
    pub fn new(genesis_hash: &str) -> Self {
        Self {
            prev_hash: Mutex::new(genesis_hash.to_string()),
        }
    }

    pub fn record(
        &self,
        actor: &str,
        action: &str,
        entity_id: &str,
        entity_type: &str,
        details_json: &str,
    ) -> BadgerResult<AuditRecord> {
        let mut prev = self.prev_hash.lock().unwrap();
        let record_id = Uuid::new_v4().to_string();
        let timestamp_unix = Utc::now().timestamp();

        // Compute SHA-256 over fields including prev_hash
        let mut hasher = Sha256::new();
        hasher.update(record_id.as_bytes());
        hasher.update(timestamp_unix.to_string().as_bytes());
        hasher.update(actor.as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(entity_id.as_bytes());
        hasher.update(entity_type.as_bytes());
        hasher.update(details_json.as_bytes());
        hasher.update(prev.as_bytes());
        let hash_result = format!("{:x}", hasher.finalize());

        let record = AuditRecord {
            record_id,
            timestamp_unix,
            actor: actor.to_string(),
            action: action.to_string(),
            entity_id: entity_id.to_string(),
            entity_type: entity_type.to_string(),
            details_json: details_json.to_string(),
            sha256_prev_record: prev.clone(),
            signature: hash_result.clone(),
        };

        // Advance the chain
        *prev = hash_result;

        Ok(record)
    }

    pub fn verify_chain(records: &[AuditRecord]) -> bool {
        let mut expected_prev = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        for r in records {
            if r.sha256_prev_record != expected_prev {
                return false;
            }
            let mut hasher = Sha256::new();
            hasher.update(r.record_id.as_bytes());
            hasher.update(r.timestamp_unix.to_string().as_bytes());
            hasher.update(r.actor.as_bytes());
            hasher.update(r.action.as_bytes());
            hasher.update(r.entity_id.as_bytes());
            hasher.update(r.entity_type.as_bytes());
            hasher.update(r.details_json.as_bytes());
            hasher.update(r.sha256_prev_record.as_bytes());
            let computed = format!("{:x}", hasher.finalize());
            if computed != r.signature {
                return false;
            }
            expected_prev = computed;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_hash_chaining() {
        let logger = AuditLogger::default();
        let r1 = logger.record("system", "workload_register", "wl-101", "workload", "{}").unwrap();
        let r2 = logger.record("badger-sensor", "policy_blocked", "wl-101", "event", "{\"syscall\":\"connect\"}").unwrap();
        let r3 = logger.record("badger-containment", "suspend_workload", "wl-101", "workload", "{}").unwrap();

        let chain = vec![r1, r2, r3];
        assert!(AuditLogger::verify_chain(&chain));

        // Tamper test
        let mut tampered = chain.clone();
        tampered[1].details_json = "{\"tampered\":true}".to_string();
        assert!(!AuditLogger::verify_chain(&tampered));
    }
}
