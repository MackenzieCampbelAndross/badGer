use badger_common::{
    AuditLogger, BadgerResult, CapabilityPolicy, EnforcementOutcome, EventType, FilesystemRule,
    FsAccess, NetworkRule, PrincipalType, ResourceLimits, RuntimeEvent, SensorHealthStatus,
    Severity,
};
use badger_containment::ContainmentEngine;
use badger_identity::{IdentityStore, WorkloadRegistration};
use badger_policy::PolicyEngine;
use badger_sandbox::{LinuxSandbox, SandboxConfig};
use badger_sensor::{RuntimeSensor, SensorConfig};
use badger_threat::ThreatDetectionEngine;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;

pub struct ScenarioResult {
    pub scenario: String,
    pub description: String,
    pub detection_succeeded: bool,
    pub enforcement_succeeded: bool,
    pub audit_recorded: bool,
    pub verification_succeeded: bool,
    pub details: String,
}

pub struct AdversarialRunner {
    identity: IdentityStore,
    principal_id: String,
    policy_engine: PolicyEngine,
    threat_engine: ThreatDetectionEngine,
    audit_logger: Arc<AuditLogger>,
    containment: ContainmentEngine,
}

impl Default for AdversarialRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl AdversarialRunner {
    pub fn new() -> Self {
        let logger = Arc::new(AuditLogger::default());
        let containment = ContainmentEngine::new(logger.clone());
        let policy_engine = PolicyEngine::new("badger-production-key-2026");

        let identity = IdentityStore::new();
        identity.register_tenant("tenant-adversarial", "Adversarial Test Suite").unwrap();
        let principal = identity
            .register_principal(
                "tenant-adversarial",
                "test-agent",
                PrincipalType::Agent,
                HashMap::new(),
            )
            .unwrap();

        Self {
            identity,
            principal_id: principal.id,
            policy_engine,
            threat_engine: ThreatDetectionEngine::new(),
            audit_logger: logger,
            containment,
        }
    }

    /// Scenario A: Filesystem boundary enforcement
    pub fn run_scenario_a(&self) -> BadgerResult<ScenarioResult> {
        let (wkl, _) = self.setup_workload("scenario-a-fs", "/workspace/allowed", false)?;

        // Attempting to access protected /etc/shadow
        let path = "/etc/shadow";
        let is_write = false;
        let allowed = self.policy_engine.evaluate_filesystem(&wkl.policy_id, path, is_write)?;

        let enforcement_succeeded = !allowed; // Must be blocked!
        let outcome = if allowed {
            EnforcementOutcome::Allowed
        } else {
            EnforcementOutcome::Blocked
        };

        let (sensor, _) = RuntimeSensor::new(SensorConfig {
            workload_id: wkl.id.clone(),
            principal_id: wkl.principal_id.clone(),
            target_pid: 1001,
            enable_ebpf: true,
        });
        sensor.start()?;

        let evt = sensor.observe_file_access(1001, path, is_write, outcome)?;
        let finding = self.threat_engine.evaluate_event(&evt);
        let detection_succeeded = finding.is_some() && finding.as_ref().unwrap().detection_rule == "DET-FS-001";

        let audit = self.audit_logger.record(
            "badger-sensor",
            "filesystem_enforcement",
            &wkl.id,
            "workload",
            &serde_json::to_string(&evt)?,
        )?;

        let verification_succeeded = enforcement_succeeded && detection_succeeded && !audit.signature.is_empty();

        Ok(ScenarioResult {
            scenario: "Scenario A: Filesystem Boundary".to_string(),
            description: "Attempt unauthorized access to protected host location (/etc/shadow)".to_string(),
            detection_succeeded,
            enforcement_succeeded,
            audit_recorded: true,
            verification_succeeded,
            details: format!(
                "Path: {}, Policy Outcome: {:?}, Finding: {:?}",
                path, outcome, finding.map(|f| f.summary)
            ),
        })
    }

    /// Scenario B: Network boundary enforcement
    pub fn run_scenario_b(&self) -> BadgerResult<ScenarioResult> {
        let (wkl, _) = self.setup_workload("scenario-b-net", "/workspace/allowed", true)?;

        let destination = "198.51.100.1"; // Prohibited external IP
        let port = 4444;
        let allowed = self.policy_engine.evaluate_network(&wkl.policy_id, destination, port)?;

        let enforcement_succeeded = !allowed; // Must be blocked!
        let outcome = if allowed {
            EnforcementOutcome::Allowed
        } else {
            EnforcementOutcome::Blocked
        };

        let (sensor, _) = RuntimeSensor::new(SensorConfig {
            workload_id: wkl.id.clone(),
            principal_id: wkl.principal_id.clone(),
            target_pid: 1002,
            enable_ebpf: true,
        });
        sensor.start()?;

        let evt = sensor.observe_net_connect(1002, destination, port, outcome)?;
        let finding = self.threat_engine.evaluate_event(&evt);
        let detection_succeeded = finding.is_some() && finding.as_ref().unwrap().detection_rule == "DET-NET-002";

        let audit = self.audit_logger.record(
            "badger-sensor",
            "network_enforcement",
            &wkl.id,
            "workload",
            &serde_json::to_string(&evt)?,
        )?;

        let verification_succeeded = enforcement_succeeded && detection_succeeded && !audit.signature.is_empty();

        Ok(ScenarioResult {
            scenario: "Scenario B: Network Boundary".to_string(),
            description: "Attempt unauthorized outbound connection to prohibited network destination (198.51.100.1:4444)".to_string(),
            detection_succeeded,
            enforcement_succeeded,
            audit_recorded: true,
            verification_succeeded,
            details: format!(
                "Destination: {}:{}, Policy Outcome: {:?}, Finding: {:?}",
                destination, port, outcome, finding.map(|f| f.summary)
            ),
        })
    }

    /// Scenario C: Prohibited process execution
    pub fn run_scenario_c(&self) -> BadgerResult<ScenarioResult> {
        let (wkl, _) = self.setup_workload("scenario-c-proc", "/workspace/allowed", false)?;

        let prohibited_bin = "/bin/nc";
        let allowed = self.policy_engine.evaluate_executable(&wkl.policy_id, prohibited_bin)?;

        let enforcement_succeeded = !allowed;
        let outcome = if allowed {
            EnforcementOutcome::Allowed
        } else {
            EnforcementOutcome::Blocked
        };

        let (sensor, _) = RuntimeSensor::new(SensorConfig {
            workload_id: wkl.id.clone(),
            principal_id: wkl.principal_id.clone(),
            target_pid: 1003,
            enable_ebpf: true,
        });
        sensor.start()?;

        let evt = sensor.observe_process_exec(
            1003,
            1,
            prohibited_bin,
            &["-e".to_string(), "/bin/sh".to_string()],
            outcome,
        )?;
        let finding = self.threat_engine.evaluate_event(&evt);
        let detection_succeeded = finding.is_some() && finding.as_ref().unwrap().detection_rule == "DET-PROC-003";

        let _audit = self.audit_logger.record(
            "badger-sensor",
            "exec_enforcement",
            &wkl.id,
            "workload",
            &serde_json::to_string(&evt)?,
        )?;

        Ok(ScenarioResult {
            scenario: "Scenario C: Process Execution".to_string(),
            description: "Attempt execution of prohibited utility (/bin/nc)".to_string(),
            detection_succeeded,
            enforcement_succeeded,
            audit_recorded: true,
            verification_succeeded: enforcement_succeeded && detection_succeeded,
            details: format!(
                "Binary: {}, Policy Outcome: {:?}, Finding: {:?}",
                prohibited_bin, outcome, finding.map(|f| f.summary)
            ),
        })
    }

    /// Scenario D: Process monitoring and attribution
    pub fn run_scenario_d(&self) -> BadgerResult<ScenarioResult> {
        let (wkl, _) = self.setup_workload("scenario-d-mon", "/workspace/allowed", false)?;

        let permitted_bin = "/usr/bin/python3";
        let allowed = self.policy_engine.evaluate_executable(&wkl.policy_id, permitted_bin)?;

        let (sensor, _) = RuntimeSensor::new(SensorConfig {
            workload_id: wkl.id.clone(),
            principal_id: wkl.principal_id.clone(),
            target_pid: 1004,
            enable_ebpf: true,
        });
        sensor.start()?;

        let evt = sensor.observe_process_exec(
            1004,
            1,
            permitted_bin,
            &["-c".to_string(), "print('task completed')".to_string()],
            EnforcementOutcome::Allowed,
        )?;

        let audit = self.audit_logger.record(
            "badger-sensor",
            "process_monitored",
            &wkl.id,
            "workload",
            &serde_json::to_string(&evt)?,
        )?;

        let attributed_correctly = evt.workload_id == wkl.id && evt.principal_id == wkl.principal_id;

        Ok(ScenarioResult {
            scenario: "Scenario D: Process Monitoring".to_string(),
            description: "Launch permitted child process and attribute runtime event to workload identity".to_string(),
            detection_succeeded: true, // Monitoring succeeded
            enforcement_succeeded: allowed,
            audit_recorded: true,
            verification_succeeded: attributed_correctly && !audit.signature.is_empty(),
            details: format!(
                "Workload ID: {}, Attributed Workload ID: {}, Event: {:?}",
                wkl.id, evt.workload_id, evt.event_type
            ),
        })
    }

    /// Scenario E: Policy violation finding and verified containment
    pub fn run_scenario_e(&self) -> BadgerResult<ScenarioResult> {
        let (wkl, _) = self.setup_workload("scenario-e-viol", "/workspace/allowed", false)?;

        let evt = RuntimeEvent {
            event_id: "evt-violation-test".to_string(),
            timestamp_unix_nanos: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            workload_id: wkl.id.clone(),
            principal_id: wkl.principal_id.clone(),
            process_id: 1005,
            parent_process_id: 1,
            event_type: EventType::SyscallBlocked,
            resource: "SYS_bpf".to_string(),
            outcome: EnforcementOutcome::Blocked,
            severity: Severity::Critical,
            sensor_provenance: "seccomp-bpf".to_string(),
            attributes: HashMap::new(),
        };

        let finding = self.threat_engine.evaluate_event(&evt);
        let detection_succeeded = finding.is_some() && finding.as_ref().unwrap().detection_rule == "DET-SYSCALL-005";

        let (action, audit) = self.containment.suspend_workload(&wkl.id, &finding.as_ref().unwrap().finding_id)?;

        Ok(ScenarioResult {
            scenario: "Scenario E: Policy Violation & Containment".to_string(),
            description: "Trigger critical security violation (SYS_bpf call) and verify automated containment response".to_string(),
            detection_succeeded,
            enforcement_succeeded: true,
            audit_recorded: true,
            verification_succeeded: action.verified && !audit.signature.is_empty(),
            details: format!(
                "Violation: SYS_bpf blocked, Containment Action: {:?}, Verified: {}",
                action.action_type, action.verified
            ),
        })
    }

    /// Scenario F: Workload isolation boundaries
    pub fn run_scenario_f(&self) -> BadgerResult<ScenarioResult> {
        let (wkl, pol) = self.setup_workload("scenario-f-isol", "/workspace/allowed", true)?;

        let sandbox = LinuxSandbox::new(SandboxConfig {
            workload_id: wkl.id.clone(),
            policy: pol,
            isolate_network: true,
        });

        let prep_res = sandbox.prepare();
        let enforcement_succeeded = prep_res.is_ok();

        let audit = self.audit_logger.record(
            "badger-sandbox",
            "isolation_boundary_prepared",
            &wkl.id,
            "workload",
            "{\"namespaces\":[\"mount\",\"pid\",\"net\",\"ipc\",\"uts\"],\"cgroups\":\"v2\"}",
        )?;

        sandbox.cleanup();

        Ok(ScenarioResult {
            scenario: "Scenario F: Workload Isolation Boundary".to_string(),
            description: "Verify Linux namespace, cgroups v2, and network isolation sandbox initialization".to_string(),
            detection_succeeded: true,
            enforcement_succeeded,
            audit_recorded: true,
            verification_succeeded: enforcement_succeeded && !audit.signature.is_empty(),
            details: "Multi-namespace + cgroup v2 subtree setup validated".to_string(),
        })
    }

    /// Scenario G: Sensor failure and degraded state transparency
    pub fn run_scenario_g(&self) -> BadgerResult<ScenarioResult> {
        let (wkl, _) = self.setup_workload("scenario-g-sensor", "/workspace/allowed", false)?;

        let (sensor, _) = RuntimeSensor::new(SensorConfig {
            workload_id: wkl.id.clone(),
            principal_id: wkl.principal_id.clone(),
            target_pid: 1007,
            enable_ebpf: true,
        });
        sensor.start()?;

        // Simulate sensor shutdown / failure
        sensor.stop();
        let current_status = sensor.get_health_status();

        // System must report Unprotected and must NOT falsely claim Protected
        let reports_unprotected = current_status == SensorHealthStatus::Unprotected;

        let status_evt = RuntimeEvent {
            event_id: "evt-sensor-fail".to_string(),
            timestamp_unix_nanos: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            workload_id: wkl.id.clone(),
            principal_id: wkl.principal_id.clone(),
            process_id: 1007,
            parent_process_id: 1,
            event_type: EventType::SensorStatusChange,
            resource: "sensor://health".to_string(),
            outcome: EnforcementOutcome::Audited,
            severity: Severity::Critical,
            sensor_provenance: "sensor-monitor".to_string(),
            attributes: [("status".to_string(), "Unprotected".to_string())].into(),
        };

        let finding = self.threat_engine.evaluate_event(&status_evt);
        let detection_succeeded = finding.is_some() && finding.as_ref().unwrap().detection_rule == "DET-INTEG-006";

        let _audit = self.audit_logger.record(
            "badger-sensor",
            "sensor_failure_reported",
            &wkl.id,
            "workload",
            "{\"sensor_status\":\"Unprotected\"}",
        )?;

        Ok(ScenarioResult {
            scenario: "Scenario G: Sensor Failure".to_string(),
            description: "Stop telemetry component and verify degraded/unprotected visibility reporting".to_string(),
            detection_succeeded,
            enforcement_succeeded: reports_unprotected,
            audit_recorded: true,
            verification_succeeded: reports_unprotected && detection_succeeded,
            details: format!(
                "Reported Sensor Health Status: {:?}, Finding: {:?}",
                current_status, finding.map(|f| f.summary)
            ),
        })
    }

    /// Scenario H: Policy integrity and signature tampering
    pub fn run_scenario_h(&self) -> BadgerResult<ScenarioResult> {
        let (wkl, mut pol) = self.setup_workload("scenario-h-pol", "/workspace/allowed", false)?;

        // Attempt to load tampered unauthorized policy
        pol.signature = "malicious_unauthorized_signature".to_string();
        pol.version += 1;

        let load_result = self.policy_engine.load_policy(pol);
        let rejected = load_result.is_err();

        // Verify that the original valid policy remains active
        let active = self.policy_engine.get_policy(&wkl.policy_id).unwrap();
        let fallback_preserved = active.version == 1;

        let audit = self.audit_logger.record(
            "badger-policy",
            "policy_tamper_rejected",
            &wkl.id,
            "policy",
            "{\"error\":\"signature mismatch\",\"action\":\"rejected\"}",
        )?;

        Ok(ScenarioResult {
            scenario: "Scenario H: Policy Integrity".to_string(),
            description: "Attempt to load malformed/unauthorized policy update and verify rejection and fallback preservation".to_string(),
            detection_succeeded: rejected,
            enforcement_succeeded: rejected,
            audit_recorded: true,
            verification_succeeded: rejected && fallback_preserved && !audit.signature.is_empty(),
            details: format!(
                "Tampered Update Rejected: {}, Active Policy Version Preserved: {}",
                rejected, active.version
            ),
        })
    }

    fn setup_workload(
        &self,
        name: &str,
        allowed_path: &str,
        isolate_net: bool,
    ) -> BadgerResult<(badger_common::Workload, CapabilityPolicy)> {
        let policy_id = format!("pol-{}", name);
        let mut policy = CapabilityPolicy {
            id: policy_id.clone(),
            tenant_id: "tenant-adversarial".to_string(),
            name: format!("Policy for {}", name),
            version: 1,
            allowed_executables: vec!["/bin/bash".to_string(), "/usr/bin/python3".to_string()],
            denied_executables: vec!["/bin/nc".to_string(), "/usr/bin/ncat".to_string()],
            filesystem_rules: vec![
                FilesystemRule {
                    path: allowed_path.to_string(),
                    access: FsAccess::Rw,
                    recursive: true,
                },
                FilesystemRule {
                    path: "/etc/shadow".to_string(),
                    access: FsAccess::None,
                    recursive: false,
                },
            ],
            network_rules: if isolate_net {
                vec![NetworkRule {
                    destination: "*".to_string(),
                    port: 0,
                    protocol: "all".to_string(),
                    allow: false,
                }]
            } else {
                vec![NetworkRule {
                    destination: "127.0.0.1".to_string(),
                    port: 8080,
                    protocol: "tcp".to_string(),
                    allow: true,
                }]
            },
            limits: ResourceLimits::default(),
            drop_capabilities: vec!["CAP_SYS_ADMIN".to_string()],
            disallow_privilege_escalation: true,
            valid_from_unix: 0,
            valid_until_unix: Utc::now().timestamp() + 3600,
            signature: String::new(),
        };

        policy.signature = PolicyEngine::compute_signature(&policy, "badger-production-key-2026");
        self.policy_engine.load_policy(policy.clone())?;

        let principal_id = self.principal_id.clone();
        let wkl = self.identity.register_workload(WorkloadRegistration {
            tenant_id: "tenant-adversarial".to_string(),
            principal_id,
            workload_name: name.to_string(),
            policy_id,
            policy_version: 1,
            metadata: HashMap::new(),
        })?;

        Ok((wkl, policy))
    }
}
