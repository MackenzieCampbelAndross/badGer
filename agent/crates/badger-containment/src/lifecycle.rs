use crate::types::{LifecycleState, ResponseActionType, ResponseExecutionRecord};
use badger_common::{BadgerError, BadgerResult};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct ResponseStateMachine {
    records: Arc<RwLock<HashMap<String, ResponseExecutionRecord>>>,
}

impl Default for ResponseStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseStateMachine {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initializes a response lifecycle upon finding receipt
    pub fn start_response(
        &self,
        action_id: &str,
        tenant_id: &str,
        initiating_identity: &str,
        target_workload: &str,
        triggering_finding_id: &str,
        action_type: ResponseActionType,
    ) -> ResponseExecutionRecord {
        let now = Utc::now().timestamp();
        let record = ResponseExecutionRecord {
            action_id: action_id.to_string(),
            tenant_id: tenant_id.to_string(),
            initiating_identity: initiating_identity.to_string(),
            target_workload: target_workload.to_string(),
            triggering_finding_id: triggering_finding_id.to_string(),
            action_type,
            lifecycle_state: LifecycleState::FindingReceived,
            requested_at_unix: now,
            completed_at_unix: None,
            verified: false,
            verification_evidence: String::new(),
            rollback_status: None,
            failure_reason: None,
        };

        let mut map = self.records.write().unwrap();
        map.insert(action_id.to_string(), record.clone());
        record
    }

    /// Advances the lifecycle state with validation
    pub fn advance_state(
        &self,
        action_id: &str,
        next_state: LifecycleState,
    ) -> BadgerResult<ResponseExecutionRecord> {
        let mut map = self.records.write().unwrap();
        if let Some(record) = map.get_mut(action_id) {
            record.lifecycle_state = next_state.clone();
            if let LifecycleState::OutcomeVerified = next_state {
                record.verified = true;
                record.completed_at_unix = Some(Utc::now().timestamp());
            } else if let LifecycleState::Failed { ref reason } = next_state {
                record.verified = false;
                record.failure_reason = Some(reason.clone());
                record.completed_at_unix = Some(Utc::now().timestamp());
            }
            Ok(record.clone())
        } else {
            Err(BadgerError::Containment(format!(
                "Response action '{}' not found in state machine",
                action_id
            )))
        }
    }

    pub fn set_verification_evidence(
        &self,
        action_id: &str,
        evidence: &str,
    ) -> BadgerResult<()> {
        let mut map = self.records.write().unwrap();
        if let Some(record) = map.get_mut(action_id) {
            record.verification_evidence = evidence.to_string();
            Ok(())
        } else {
            Err(BadgerError::Containment(format!(
                "Response action '{}' not found",
                action_id
            )))
        }
    }

    pub fn get_record(&self, action_id: &str) -> Option<ResponseExecutionRecord> {
        let map = self.records.read().unwrap();
        map.get(action_id).cloned()
    }

    pub fn list_records_for_tenant(&self, tenant_id: &str) -> Vec<ResponseExecutionRecord> {
        let map = self.records.read().unwrap();
        map.values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_state_transitions() {
        let sm = ResponseStateMachine::new();
        let record = sm.start_response(
            "act-1",
            "tenant-corp",
            "badger-sensor",
            "wkl-100",
            "fnd-200",
            ResponseActionType::SuspendWorkload,
        );
        assert_eq!(record.lifecycle_state, LifecycleState::FindingReceived);

        sm.advance_state("act-1", LifecycleState::FindingValidated).unwrap();
        sm.advance_state("act-1", LifecycleState::ResponseExecuted).unwrap();
        let verified = sm.advance_state("act-1", LifecycleState::OutcomeVerified).unwrap();

        assert!(verified.verified);
        assert!(verified.completed_at_unix.is_some());
    }
}
