use badger_common::{
    BadgerError, BadgerResult, EnforcementOutcome, EventType, RuntimeEvent, SensorHealthStatus,
    Severity,
};
use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SensorConfig {
    pub workload_id: String,
    pub principal_id: String,
    pub target_pid: u32,
    pub enable_ebpf: bool,
}

pub struct RuntimeSensor {
    config: SensorConfig,
    health_status: Arc<std::sync::RwLock<SensorHealthStatus>>,
    is_running: Arc<AtomicBool>,
    event_sender: broadcast::Sender<RuntimeEvent>,
}

impl RuntimeSensor {
    pub fn new(config: SensorConfig) -> (Self, broadcast::Receiver<RuntimeEvent>) {
        let (tx, rx) = broadcast::channel(1024);
        (
            Self {
                config,
                health_status: Arc::new(std::sync::RwLock::new(SensorHealthStatus::Unknown)),
                is_running: Arc::new(AtomicBool::new(false)),
                event_sender: tx,
            },
            rx,
        )
    }

    pub fn start(&self) -> BadgerResult<()> {
        self.is_running.store(true, Ordering::SeqCst);

        // Check telemetry capability
        let has_tracefs = Path::new("/sys/kernel/debug/tracing").exists()
            || Path::new("/sys/kernel/tracing").exists();
        let has_btf = Path::new("/sys/kernel/btf/vmlinux").exists();

        let initial_status = if self.config.enable_ebpf && has_tracefs && has_btf {
            info!("eBPF/CO-RE kernel telemetry available. Sensor running in PROTECTED mode.");
            SensorHealthStatus::Protected
        } else {
            warn!(
                "eBPF unavailable or disabled. Sensor running in DEGRADED procfs/audit telemetry mode. Full kernel visibility is not claimed."
            );
            SensorHealthStatus::Degraded
        };

        *self.health_status.write().unwrap() = initial_status;

        // Emit sensor status change event
        self.emit_event(
            EventType::SensorStatusChange,
            "sensor://health",
            EnforcementOutcome::Audited,
            Severity::Informational,
            if initial_status == SensorHealthStatus::Protected {
                "ebpf-telemetry"
            } else {
                "procfs-alternative"
            },
            [("status".to_string(), format!("{:?}", initial_status))].into(),
        )?;

        Ok(())
    }

    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
        *self.health_status.write().unwrap() = SensorHealthStatus::Unprotected;
        let _ = self.emit_event(
            EventType::SensorStatusChange,
            "sensor://health",
            EnforcementOutcome::Audited,
            Severity::High,
            "sensor-shutdown",
            [("status".to_string(), "Unprotected".to_string())].into(),
        );
        info!("Runtime sensor stopped for workload '{}'", self.config.workload_id);
    }

    pub fn get_health_status(&self) -> SensorHealthStatus {
        *self.health_status.read().unwrap()
    }

    pub fn emit_event(
        &self,
        event_type: EventType,
        resource: &str,
        outcome: EnforcementOutcome,
        severity: Severity,
        provenance: &str,
        attributes: HashMap<String, String>,
    ) -> BadgerResult<RuntimeEvent> {
        let event = RuntimeEvent {
            event_id: format!("evt_{}", Uuid::new_v4().simple()),
            timestamp_unix_nanos: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            workload_id: self.config.workload_id.clone(),
            principal_id: self.config.principal_id.clone(),
            process_id: self.config.target_pid,
            parent_process_id: 1,
            event_type,
            resource: resource.to_string(),
            outcome,
            severity,
            sensor_provenance: provenance.to_string(),
            attributes,
        };

        let _ = self.event_sender.send(event.clone());
        Ok(event)
    }

    /// Record process execution event
    pub fn observe_process_exec(
        &self,
        pid: u32,
        ppid: u32,
        binary_path: &str,
        args: &[String],
        outcome: EnforcementOutcome,
    ) -> BadgerResult<RuntimeEvent> {
        let mut attrs = HashMap::new();
        attrs.insert("args".to_string(), args.join(" "));
        attrs.insert("pid".to_string(), pid.to_string());
        attrs.insert("ppid".to_string(), ppid.to_string());

        let severity = match outcome {
            EnforcementOutcome::Blocked => Severity::High,
            _ => Severity::Informational,
        };

        let mut event = self.emit_event(
            EventType::ProcessExec,
            binary_path,
            outcome,
            severity,
            "exec-monitor",
            attrs,
        )?;
        event.process_id = pid;
        event.parent_process_id = ppid;
        Ok(event)
    }

    /// Record filesystem access attempt
    pub fn observe_file_access(
        &self,
        pid: u32,
        path: &str,
        is_write: bool,
        outcome: EnforcementOutcome,
    ) -> BadgerResult<RuntimeEvent> {
        let mut attrs = HashMap::new();
        attrs.insert("operation".to_string(), if is_write { "write" } else { "read" }.to_string());

        let severity = match outcome {
            EnforcementOutcome::Blocked => Severity::High,
            _ => Severity::Informational,
        };

        let event_type = if is_write {
            EventType::FileWrite
        } else {
            EventType::FileOpen
        };

        let mut event = self.emit_event(
            event_type,
            path,
            outcome,
            severity,
            "fs-monitor",
            attrs,
        )?;
        event.process_id = pid;
        Ok(event)
    }

    /// Record network connection attempt
    pub fn observe_net_connect(
        &self,
        pid: u32,
        destination: &str,
        port: u16,
        outcome: EnforcementOutcome,
    ) -> BadgerResult<RuntimeEvent> {
        let mut attrs = HashMap::new();
        attrs.insert("destination".to_string(), destination.to_string());
        attrs.insert("port".to_string(), port.to_string());

        let severity = match outcome {
            EnforcementOutcome::Blocked => Severity::High,
            _ => Severity::Informational,
        };

        let mut event = self.emit_event(
            EventType::NetConnect,
            &format!("{}:{}", destination, port),
            outcome,
            severity,
            "net-monitor",
            attrs,
        )?;
        event.process_id = pid;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensor_lifecycle_and_events() {
        let config = SensorConfig {
            workload_id: "wkl-test-1".to_string(),
            principal_id: "prn-agent-1".to_string(),
            target_pid: 4321,
            enable_ebpf: false, // will use fallback
        };

        let (sensor, mut rx) = RuntimeSensor::new(config);
        sensor.start().unwrap();

        // Must report Degraded, not Protected, when eBPF is disabled
        assert_eq!(sensor.get_health_status(), SensorHealthStatus::Degraded);

        // Receive initial status event
        let evt = rx.try_recv().unwrap();
        assert_eq!(evt.event_type, EventType::SensorStatusChange);

        // Emit process exec
        sensor
            .observe_process_exec(
                4321,
                1,
                "/bin/bash",
                &["-c".to_string(), "whoami".to_string()],
                EnforcementOutcome::Allowed,
            )
            .unwrap();

        let evt2 = rx.try_recv().unwrap();
        assert_eq!(evt2.event_type, EventType::ProcessExec);
        assert_eq!(evt2.resource, "/bin/bash");
        assert_eq!(evt2.workload_id, "wkl-test-1");

        // Stop sensor -> must report Unprotected
        sensor.stop();
        assert_eq!(sensor.get_health_status(), SensorHealthStatus::Unprotected);
    }
}
