use badger_common::{
    EnforcementOutcome, EventType, RuntimeEvent, SecurityFinding, Severity,
};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

pub struct ThreatDetectionEngine;

impl Default for ThreatDetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatDetectionEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates a RuntimeEvent against deterministic detection rules
    pub fn evaluate_event(&self, event: &RuntimeEvent) -> Option<SecurityFinding> {
        let mut evidence = HashMap::new();
        evidence.insert("resource".to_string(), event.resource.clone());
        evidence.insert("outcome".to_string(), format!("{:?}", event.outcome));
        evidence.insert("provenance".to_string(), event.sensor_provenance.clone());
        evidence.insert("process_id".to_string(), event.process_id.to_string());
        for (k, v) in &event.attributes {
            evidence.insert(k.clone(), v.clone());
        }

        // Rule DET-FS-001: Unauthorized Filesystem Access
        if (event.event_type == EventType::FileOpen || event.event_type == EventType::FileWrite)
            && event.outcome == EnforcementOutcome::Blocked
        {
            return Some(SecurityFinding {
                finding_id: format!("fnd_{}", Uuid::new_v4().simple()),
                workload_id: event.workload_id.clone(),
                detection_rule: "DET-FS-001".to_string(),
                severity: Severity::High,
                confidence: 1.0,
                timestamp_unix: Utc::now().timestamp(),
                summary: format!(
                    "Workload '{}' attempted unauthorized filesystem access to '{}'",
                    event.workload_id, event.resource
                ),
                trigger_event_ids: vec![event.event_id.clone()],
                recommended_response: "Enforce filesystem boundary; suspend workload if repeated"
                    .to_string(),
                evidence,
            });
        }

        // Rule DET-NET-002: Unauthorized Network Access
        if event.event_type == EventType::NetConnect && event.outcome == EnforcementOutcome::Blocked
        {
            return Some(SecurityFinding {
                finding_id: format!("fnd_{}", Uuid::new_v4().simple()),
                workload_id: event.workload_id.clone(),
                detection_rule: "DET-NET-002".to_string(),
                severity: Severity::High,
                confidence: 1.0,
                timestamp_unix: Utc::now().timestamp(),
                summary: format!(
                    "Workload '{}' attempted prohibited network connection to '{}'",
                    event.workload_id, event.resource
                ),
                trigger_event_ids: vec![event.event_id.clone()],
                recommended_response: "Restrict network namespace or terminate workload"
                    .to_string(),
                evidence,
            });
        }

        // Rule DET-PROC-003: Prohibited Executable Invocation
        if event.event_type == EventType::ProcessExec && event.outcome == EnforcementOutcome::Blocked
        {
            return Some(SecurityFinding {
                finding_id: format!("fnd_{}", Uuid::new_v4().simple()),
                workload_id: event.workload_id.clone(),
                detection_rule: "DET-PROC-003".to_string(),
                severity: Severity::Critical,
                confidence: 1.0,
                timestamp_unix: Utc::now().timestamp(),
                summary: format!(
                    "Workload '{}' attempted execution of unauthorized binary '{}'",
                    event.workload_id, event.resource
                ),
                trigger_event_ids: vec![event.event_id.clone()],
                recommended_response: "Kill process immediately and review workload integrity"
                    .to_string(),
                evidence,
            });
        }

        // Rule DET-SYSCALL-005: Blocked Forbidden System Call (e.g. ptrace, bpf, mount)
        if event.event_type == EventType::SyscallBlocked {
            return Some(SecurityFinding {
                finding_id: format!("fnd_{}", Uuid::new_v4().simple()),
                workload_id: event.workload_id.clone(),
                detection_rule: "DET-SYSCALL-005".to_string(),
                severity: Severity::Critical,
                confidence: 1.0,
                timestamp_unix: Utc::now().timestamp(),
                summary: format!(
                    "Workload '{}' attempted forbidden system call '{}' blocked by Seccomp-BPF",
                    event.workload_id, event.resource
                ),
                trigger_event_ids: vec![event.event_id.clone()],
                recommended_response: "Terminate workload; possible container breakout attempt"
                    .to_string(),
                evidence,
            });
        }

        // Rule DET-INTEG-006: Sensor Status Degradation or Shutdown
        if event.event_type == EventType::SensorStatusChange {
            if let Some(status) = event.attributes.get("status") {
                if status == "Unprotected" {
                    return Some(SecurityFinding {
                        finding_id: format!("fnd_{}", Uuid::new_v4().simple()),
                        workload_id: event.workload_id.clone(),
                        detection_rule: "DET-INTEG-006".to_string(),
                        severity: Severity::Critical,
                        confidence: 1.0,
                        timestamp_unix: Utc::now().timestamp(),
                        summary: format!(
                            "Security telemetry lost for workload '{}': sensor status changed to Unprotected",
                            event.workload_id
                        ),
                        trigger_event_ids: vec![event.event_id.clone()],
                        recommended_response: "Suspend workload execution until sensor is restored".to_string(),
                        evidence,
                    });
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_violation_detection() {
        let engine = ThreatDetectionEngine::new();
        let evt = RuntimeEvent {
            event_id: "evt-1".to_string(),
            timestamp_unix_nanos: 1000,
            workload_id: "wkl-agent".to_string(),
            principal_id: "prn-1".to_string(),
            process_id: 1234,
            parent_process_id: 1,
            event_type: EventType::FileOpen,
            resource: "/etc/shadow".to_string(),
            outcome: EnforcementOutcome::Blocked,
            severity: Severity::High,
            sensor_provenance: "landlock-lsm".to_string(),
            attributes: HashMap::new(),
        };

        let finding = engine.evaluate_event(&evt).expect("Finding expected");
        assert_eq!(finding.detection_rule, "DET-FS-001");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, 1.0);
        assert!(finding.summary.contains("/etc/shadow"));
    }

    #[test]
    fn test_network_violation_detection() {
        let engine = ThreatDetectionEngine::new();
        let evt = RuntimeEvent {
            event_id: "evt-net".to_string(),
            timestamp_unix_nanos: 2000,
            workload_id: "wkl-agent".to_string(),
            principal_id: "prn-1".to_string(),
            process_id: 1234,
            parent_process_id: 1,
            event_type: EventType::NetConnect,
            resource: "192.168.1.100:4444".to_string(),
            outcome: EnforcementOutcome::Blocked,
            severity: Severity::High,
            sensor_provenance: "net-monitor".to_string(),
            attributes: HashMap::new(),
        };

        let finding = engine.evaluate_event(&evt).expect("Finding expected");
        assert_eq!(finding.detection_rule, "DET-NET-002");
        assert_eq!(finding.severity, Severity::High);
    }
}
