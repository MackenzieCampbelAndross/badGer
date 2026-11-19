use crate::orchestrator::ContainmentOrchestrator;
use crate::types::ResponseExecutionRecord;
use badger_common::{BadgerError, BadgerResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub workload_id: String,
    pub tenant_id: String,
    pub approved_by: String,
    pub reason: String,
    pub findings_acknowledged: bool,
    pub baseline_policy_version: u32,
}

pub struct RecoveryManager {
    orchestrator: ContainmentOrchestrator,
}

impl RecoveryManager {
    pub fn new(orchestrator: ContainmentOrchestrator) -> Self {
        Self { orchestrator }
    }

    /// Safely evaluates and executes controlled recovery of a contained workload
    pub fn execute_recovery(
        &self,
        req: &RecoveryRequest,
    ) -> BadgerResult<ResponseExecutionRecord> {
        // 1. Pre-recovery gate: Operator approval and finding acknowledgment
        if req.approved_by.trim().is_empty() {
            return Err(BadgerError::Containment(
                "Recovery rejected: explicit operator approval identity required".to_string(),
            ));
        }

        if !req.findings_acknowledged {
            return Err(BadgerError::Containment(
                "Recovery rejected: triggering security findings must be acknowledged or remediated before recovery".to_string(),
            ));
        }

        if req.baseline_policy_version == 0 {
            return Err(BadgerError::Containment(
                "Recovery rejected: invalid baseline policy version".to_string(),
            ));
        }

        // 2. Execute controlled recovery via orchestrator
        self.orchestrator.controlled_recovery(
            &req.tenant_id,
            &req.workload_id,
            &req.approved_by,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::ResponseStateMachine;
    use badger_common::AuditLogger;
    use std::sync::Arc;

    #[test]
    fn test_recovery_requires_operator_approval_and_findings_acknowledgment() {
        let logger = Arc::new(AuditLogger::default());
        let sm = Arc::new(ResponseStateMachine::new());
        let orchestrator = ContainmentOrchestrator::new(logger, sm);
        let mgr = RecoveryManager::new(orchestrator);

        let unapproved_req = RecoveryRequest {
            workload_id: "wkl-10".to_string(),
            tenant_id: "tenant-a".to_string(),
            approved_by: "".to_string(), // Empty!
            reason: "test".to_string(),
            findings_acknowledged: true,
            baseline_policy_version: 1,
        };
        assert!(mgr.execute_recovery(&unapproved_req).is_err());

        let unack_req = RecoveryRequest {
            workload_id: "wkl-10".to_string(),
            tenant_id: "tenant-a".to_string(),
            approved_by: "sec-admin".to_string(),
            reason: "test".to_string(),
            findings_acknowledged: false, // Unacknowledged!
            baseline_policy_version: 1,
        };
        assert!(mgr.execute_recovery(&unack_req).is_err());
    }
}
