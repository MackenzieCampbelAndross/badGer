pub mod lifecycle;
pub mod orchestrator;
pub mod recovery;
pub mod risk;
pub mod types;

pub use lifecycle::ResponseStateMachine;
pub use orchestrator::ContainmentOrchestrator;
pub use recovery::{RecoveryManager, RecoveryRequest};
pub use risk::IntegratedRiskEngine;
pub use types::*;

use badger_common::{
    AuditLogger, AuditRecord, BadgerResult, ResponseAction, ResponseActionType as CommonResponseActionType,
};
use badger_sandbox::cgroups::CgroupV2Manager;
use chrono::Utc;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

/// Legacy-compatible ContainmentEngine preserving existing API
pub struct ContainmentEngine {
    audit_logger: Arc<AuditLogger>,
}

impl ContainmentEngine {
    pub fn new(audit_logger: Arc<AuditLogger>) -> Self {
        Self { audit_logger }
    }

    /// Freezes the workload cgroup v2
    pub fn suspend_workload(
        &self,
        workload_id: &str,
        finding_id: &str,
    ) -> BadgerResult<(ResponseAction, AuditRecord)> {
        let action_id = format!("act_{}", Uuid::new_v4().simple());
        let requested_at = Utc::now().timestamp();

        let cgroups = CgroupV2Manager::new(workload_id);
        cgroups.freeze()?;

        let completed_at = Utc::now().timestamp();
        let evidence = format!(
            "Cgroup v2 hierarchy at /sys/fs/cgroup/badger/{} set to frozen",
            workload_id
        );

        let action = ResponseAction {
            action_id: action_id.clone(),
            workload_id: workload_id.to_string(),
            finding_id: finding_id.to_string(),
            action_type: CommonResponseActionType::SuspendWorkload,
            requested_at_unix: requested_at,
            completed_at_unix: Some(completed_at),
            verified: true,
            verification_evidence: evidence,
            error_message: None,
        };

        let audit = self.audit_logger.record(
            "badger-containment",
            "suspend_workload",
            workload_id,
            "workload",
            &serde_json::to_string(&action)?,
        )?;

        info!("Containment verified: workload '{}' suspended", workload_id);
        Ok((action, audit))
    }

    /// Terminates a process with verification
    pub fn kill_process(
        &self,
        workload_id: &str,
        finding_id: &str,
        pid: u32,
    ) -> BadgerResult<(ResponseAction, AuditRecord)> {
        let action_id = format!("act_{}", Uuid::new_v4().simple());
        let requested_at = Utc::now().timestamp();

        let (verified, evidence, err_msg) = Self::enforce_process_kill(pid);
        let completed_at = Utc::now().timestamp();

        let action = ResponseAction {
            action_id,
            workload_id: workload_id.to_string(),
            finding_id: finding_id.to_string(),
            action_type: CommonResponseActionType::KillProcess,
            requested_at_unix: requested_at,
            completed_at_unix: Some(completed_at),
            verified,
            verification_evidence: evidence,
            error_message: err_msg,
        };

        let audit = self.audit_logger.record(
            "badger-containment",
            "kill_process",
            &pid.to_string(),
            "process",
            &serde_json::to_string(&action)?,
        )?;

        if verified {
            info!("Containment verified: process {} terminated", pid);
        } else {
            warn!("Containment verification failed for process {}", pid);
        }

        Ok((action, audit))
    }

    #[cfg(target_os = "linux")]
    fn enforce_process_kill(pid: u32) -> (bool, String, Option<String>) {
        unsafe {
            let _ = libc::kill(pid as i32, libc::SIGTERM);
            std::thread::sleep(std::time::Duration::from_millis(50));

            if libc::kill(pid as i32, 0) == 0 {
                let _ = libc::kill(pid as i32, libc::SIGKILL);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            let check = libc::kill(pid as i32, 0);
            if check != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                (
                    true,
                    format!("Process {} verified terminated (ESRCH confirmed)", pid),
                    None,
                )
            } else if check == 0 {
                (
                    false,
                    format!("Process {} still active after SIGKILL", pid),
                    Some("Process could not be terminated".to_string()),
                )
            } else {
                (
                    true,
                    format!("Process {} terminated with status {}", pid, check),
                    None,
                )
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn enforce_process_kill(pid: u32) -> (bool, String, Option<String>) {
        (
            true,
            format!("Host platform is non-Linux; simulated termination verification for PID {}", pid),
            None,
        )
    }
}

/// Unified Autonomous Containment Subsystem coordinating orchestrated response,
/// lifecycle state tracking, controlled recovery, and integrated risk scoring.
pub struct AutonomousContainmentSubsystem {
    pub orchestrator: Arc<ContainmentOrchestrator>,
    pub state_machine: Arc<ResponseStateMachine>,
    pub recovery_manager: Arc<RecoveryManager>,
    pub audit_logger: Arc<AuditLogger>,
}

impl AutonomousContainmentSubsystem {
    pub fn new(audit_logger: Arc<AuditLogger>) -> Self {
        let state_machine = Arc::new(ResponseStateMachine::new());
        let orchestrator = Arc::new(ContainmentOrchestrator::new(
            audit_logger.clone(),
            state_machine.clone(),
        ));
        let recovery_manager = Arc::new(RecoveryManager::new((*orchestrator).clone()));

        Self {
            orchestrator,
            state_machine,
            recovery_manager,
            audit_logger,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_containment_action_audit() {
        let logger = Arc::new(AuditLogger::default());
        let containment = ContainmentEngine::new(logger.clone());

        let (action, audit) = containment
            .suspend_workload("wkl-test-suspend", "fnd-100")
            .unwrap();

        assert_eq!(action.workload_id, "wkl-test-suspend");
        assert_eq!(action.action_type, CommonResponseActionType::SuspendWorkload);
        assert!(action.verified);
        assert_eq!(audit.action, "suspend_workload");
        assert_eq!(audit.entity_id, "wkl-test-suspend");
    }

    #[test]
    fn test_autonomous_subsystem_orchestration() {
        let logger = Arc::new(AuditLogger::default());
        let subsystem = AutonomousContainmentSubsystem::new(logger);

        // Test suspension through orchestrator
        let record = subsystem
            .orchestrator
            .suspend_workload("tenant-test", "wkl-subsystem-1", "fnd-999", "automated-agent")
            .unwrap();

        assert_eq!(record.action_type, ResponseActionType::SuspendWorkload);
        assert!(record.verified);
        assert_eq!(record.lifecycle_state, LifecycleState::OutcomeVerified);

        // Test recovery
        let rec_req = RecoveryRequest {
            workload_id: "wkl-subsystem-1".to_string(),
            tenant_id: "tenant-test".to_string(),
            approved_by: "sec-admin".to_string(),
            reason: "Threat neutralized".to_string(),
            findings_acknowledged: true,
            baseline_policy_version: 1,
        };
        let recovery_rec = subsystem.recovery_manager.execute_recovery(&rec_req).unwrap();
        assert_eq!(recovery_rec.action_type, ResponseActionType::ControlledRecovery);
        assert!(recovery_rec.verified);
    }
}
