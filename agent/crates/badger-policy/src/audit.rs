use crate::model::EvaluationDecision;
use badger_common::{BadgerError, BadgerResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyAuditRecord {
    pub record_id: String,
    pub timestamp_unix: i64,
    pub event_type: String, // "EVALUATION", "ACTIVATION", "ROLLBACK", "REVOCATION"
    pub actor: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub details_json: String,
    pub prev_hash: String,
    pub record_hash: String,
}

pub struct PolicyAuditService {
    records: Arc<RwLock<Vec<PolicyAuditRecord>>>,
    latest_hash: Arc<RwLock<String>>,
}

impl Default for PolicyAuditService {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyAuditService {
    pub fn new() -> Self {
        const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
        Self {
            records: Arc::new(RwLock::new(Vec::new())),
            latest_hash: Arc::new(RwLock::new(GENESIS_HASH.to_string())),
        }
    }

    /// Appends an audit entry into the cryptographically verifiable hash chain
    pub fn record_event(
        &self,
        event_type: &str,
        actor: &str,
        policy_id: &str,
        policy_version: u32,
        details_json: &str,
    ) -> BadgerResult<PolicyAuditRecord> {
        let mut prev = self.latest_hash.write().unwrap();
        let mut recs = self.records.write().unwrap();

        let record_id = format!("paud_{}", Uuid::new_v4().simple());
        let now = Utc::now().timestamp();

        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        hasher.update(record_id.as_bytes());
        hasher.update(now.to_be_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(actor.as_bytes());
        hasher.update(policy_id.as_bytes());
        hasher.update(policy_version.to_be_bytes());
        hasher.update(details_json.as_bytes());
        let record_hash = format!("{:x}", hasher.finalize());

        let record = PolicyAuditRecord {
            record_id,
            timestamp_unix: now,
            event_type: event_type.to_string(),
            actor: actor.to_string(),
            policy_id: policy_id.to_string(),
            policy_version,
            details_json: details_json.to_string(),
            prev_hash: prev.clone(),
            record_hash: record_hash.clone(),
        };

        *prev = record_hash;
        recs.push(record.clone());

        Ok(record)
    }

    pub fn record_decision(&self, decision: &EvaluationDecision) -> BadgerResult<PolicyAuditRecord> {
        let details = serde_json::to_string(decision).unwrap_or_default();
        self.record_event(
            "EVALUATION",
            &decision.principal,
            &decision.policy_id,
            decision.policy_version,
            &details,
        )
    }

    /// Verifies the integrity of the entire audit chain
    pub fn verify_integrity(&self) -> BadgerResult<()> {
        let recs = self.records.read().unwrap();
        let mut expected_prev = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        for (idx, r) in recs.iter().enumerate() {
            if r.prev_hash != expected_prev {
                return Err(BadgerError::Audit(format!(
                    "Audit hash chain broken at index {}: expected prev '{}', found '{}'",
                    idx, expected_prev, r.prev_hash
                )));
            }

            let mut hasher = Sha256::new();
            hasher.update(r.prev_hash.as_bytes());
            hasher.update(r.record_id.as_bytes());
            hasher.update(r.timestamp_unix.to_be_bytes());
            hasher.update(r.event_type.as_bytes());
            hasher.update(r.actor.as_bytes());
            hasher.update(r.policy_id.as_bytes());
            hasher.update(r.policy_version.to_be_bytes());
            hasher.update(r.details_json.as_bytes());
            let computed = format!("{:x}", hasher.finalize());

            if computed != r.record_hash {
                return Err(BadgerError::Audit(format!(
                    "Audit record hash tampered at index {}: expected '{}', found '{}'",
                    idx, computed, r.record_hash
                )));
            }

            expected_prev = r.record_hash.clone();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_hash_chain_verification() {
        let audit = PolicyAuditService::new();
        audit.record_event("ACTIVATION", "admin", "pol-1", 1, "{}").unwrap();
        audit.record_event("EVALUATION", "agent-1", "pol-1", 1, "{}").unwrap();
        audit.record_event("ROLLBACK", "admin", "pol-1", 1, "{}").unwrap();

        assert!(audit.verify_integrity().is_ok());
    }
}
