pub mod attributor;
pub mod bpf_types;
pub mod capabilities;
pub mod health;
pub mod loader;
pub mod normalizer;
pub mod probes;
pub mod ring_buffer;

use attributor::WorkloadAttributor;
use bpf_types::{BadgerBpfEvent, ProbeType};
use capabilities::KernelCapabilityDetector;
use health::{CapabilityHealthReport, TelemetryHealthMonitor};
use loader::ProbeLoader;
use normalizer::EventNormalizer;
use probes::ProbeManager;
use ring_buffer::EventRingBufferReader;

use badger_common::{
    BadgerResult, EnforcementOutcome, EventType, RuntimeEvent, SensorHealthStatus, Severity,
};
use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAttachmentState {
    Detached,
    AttachedFallbackProcfs,
    AttachedEbpf,
}

#[derive(Debug, Clone)]
pub struct SensorConfig {
    pub workload_id: String,
    pub principal_id: String,
    pub target_pid: u32,
    pub cgroup_id: u64,
    pub enable_ebpf: bool,
}

pub struct RuntimeSensor {
    config: SensorConfig,
    health_status: Arc<std::sync::RwLock<SensorHealthStatus>>,
    probe_state: Arc<std::sync::RwLock<ProbeAttachmentState>>,
    health_monitor: Arc<TelemetryHealthMonitor>,
    attributor: Arc<WorkloadAttributor>,
    ring_reader: Arc<EventRingBufferReader>,
    probe_manager: Arc<std::sync::RwLock<ProbeManager>>,
    #[cfg(target_os = "linux")]
    ebpf_holder: Arc<Mutex<Option<aya::Ebpf>>>,
    is_running: Arc<AtomicBool>,
    event_sender: broadcast::Sender<RuntimeEvent>,
    dropped_events: Arc<AtomicU64>,
}

impl RuntimeSensor {
    pub fn new(config: SensorConfig) -> (Self, broadcast::Receiver<RuntimeEvent>) {
        let (tx, rx) = broadcast::channel(4096);
        let health_monitor = Arc::new(TelemetryHealthMonitor::new());
        let attributor = Arc::new(WorkloadAttributor::new());
        let ring_reader = Arc::new(EventRingBufferReader::new());
        let probe_manager = Arc::new(std::sync::RwLock::new(ProbeManager::new()));

        // Register initial workload target with attributor
        attributor.register_workload(
            config.workload_id.clone(),
            config.principal_id.clone(),
            config.cgroup_id,
            config.target_pid,
        );

        (
            Self {
                config,
                health_status: Arc::new(std::sync::RwLock::new(SensorHealthStatus::Unknown)),
                probe_state: Arc::new(std::sync::RwLock::new(ProbeAttachmentState::Detached)),
                health_monitor,
                attributor,
                ring_reader,
                probe_manager,
                #[cfg(target_os = "linux")]
                ebpf_holder: Arc::new(Mutex::new(None)),
                is_running: Arc::new(AtomicBool::new(false)),
                event_sender: tx,
                dropped_events: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Verifies capability-based telemetry attachment.
    /// Operates native eBPF if kernel capabilities support it, or gracefully degrades to procfs.
    pub fn start(&self) -> BadgerResult<()> {
        self.is_running.store(true, Ordering::SeqCst);

        // 1. Verify target process existence if target_pid > 0
        let target_pid = self.config.target_pid;
        let proc_path = format!("/proc/{}", target_pid);
        let pid_exists = if cfg!(target_os = "linux") {
            target_pid == 0 || Path::new(&proc_path).exists()
        } else {
            target_pid != 9999999
        };

        if !pid_exists {
            warn!(
                "Target PID {} not found at /proc/{}. Sensor entering UNPROTECTED state.",
                target_pid, target_pid
            );
            *self.health_status.write().unwrap() = SensorHealthStatus::Unprotected;
            *self.probe_state.write().unwrap() = ProbeAttachmentState::Detached;

            self.emit_event(
                EventType::SensorStatusChange,
                "sensor://health",
                EnforcementOutcome::Audited,
                Severity::Critical,
                "probe-manager",
                [
                    ("status".to_string(), "Unprotected".to_string()),
                    (
                        "error".to_string(),
                        format!("Target PID {} not found", target_pid),
                    ),
                ]
                .into(),
            )?;
            return Ok(());
        }

        // 2. Detect kernel capabilities
        let caps = KernelCapabilityDetector::detect();

        // 3. Attempt native eBPF attachment if enabled and supported
        #[cfg(target_os = "linux")]
        let ebpf_started = if self.config.enable_ebpf && caps.supports_ebpf {
            self.start_ebpf_pipeline()
        } else {
            false
        };

        #[cfg(not(target_os = "linux"))]
        let ebpf_started = false;

        // 4. Set state and launch fallback if eBPF is inactive
        if ebpf_started {
            *self.health_status.write().unwrap() = SensorHealthStatus::Protected;
            *self.probe_state.write().unwrap() = ProbeAttachmentState::AttachedEbpf;
            info!(
                "Native eBPF telemetry engine ACTIVE for workload '{}' (cgroup={}). Sensor PROTECTED.",
                self.config.workload_id, self.config.cgroup_id
            );
        } else {
            *self.health_status.write().unwrap() = SensorHealthStatus::Degraded;
            *self.probe_state.write().unwrap() = ProbeAttachmentState::AttachedFallbackProcfs;
            self.health_monitor.set_degraded_procfs();

            info!(
                "Active process monitor attached to PID {}. Running in DEGRADED mode (procfs fallback).",
                target_pid
            );

            // Launch background procfs watcher thread
            if target_pid > 0 && target_pid != std::process::id() {
                self.spawn_procfs_watcher(target_pid);
            }
        }

        let report = self.health_monitor.get_report(pid_exists);
        self.emit_event(
            EventType::SensorStatusChange,
            "sensor://health",
            EnforcementOutcome::Audited,
            Severity::Informational,
            if ebpf_started {
                "ebpf-pipeline"
            } else {
                "procfs-fallback"
            },
            [
                ("status".to_string(), format!("{:?}", report.overall_status)),
                (
                    "process_telemetry".to_string(),
                    format!("{:?}", report.process_telemetry),
                ),
                (
                    "network_telemetry".to_string(),
                    format!("{:?}", report.network_telemetry),
                ),
                (
                    "filesystem_telemetry".to_string(),
                    format!("{:?}", report.filesystem_telemetry),
                ),
                (
                    "target_pid".to_string(),
                    target_pid.to_string(),
                ),
            ]
            .into(),
        )?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn start_ebpf_pipeline(&self) -> bool {
        let mut ebpf = match ProbeLoader::load() {
            Ok(ebpf) => ebpf,
            Err(e) => {
                warn!("Failed to load eBPF bytecode: {}. Falling back to procfs.", e);
                return false;
            }
        };

        {
            let mut probe_mgr = self.probe_manager.write().unwrap();
            if let Err(e) = probe_mgr.attach_all(&mut ebpf) {
                warn!("Failed to attach eBPF tracepoints: {}. Falling back to procfs.", e);
                return false;
            }

            self.health_monitor.update_probes(&probe_mgr.get_registry().get_attached_probes());
        }

        let ring_map = match ebpf.take_map("events_ringbuf") {
            Some(m) => m,
            None => {
                warn!("BPF Ring buffer map 'events_ringbuf' not found in object.");
                return false;
            }
        };

        // Channel connecting RingBufferReader to Event Processing Worker
        let (tx, mut rx) = mpsc::channel::<BadgerBpfEvent>(4096);

        if let Err(e) = self.ring_reader.start_polling(ring_map, tx) {
            warn!("Failed to start ring buffer polling: {}", e);
            return false;
        }

        // Spawn asynchronous event processing worker
        let attributor = self.attributor.clone();
        let event_sender = self.event_sender.clone();
        let running_flag = self.is_running.clone();
        let default_workload = self.config.workload_id.clone();
        let default_principal = self.config.principal_id.clone();
        let target_pid = self.config.target_pid;
        let target_comm = if target_pid > 0 {
            std::fs::read_to_string(format!("/proc/{}/comm", target_pid))
                .ok()
                .map(|s| s.trim().to_string())
        } else {
            None
        };

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to create tokio runtime for bpf worker: {}", e);
                    return;
                }
            };
            rt.block_on(async move {
                while running_flag.load(Ordering::SeqCst) {
                    match rx.recv().await {
                        Some(raw_event) => {
                            // Workload Attribution: Match cgroup_id, PID, or comm across namespace boundary
                            let (wkl_id, prn_id) = match attributor.attribute(raw_event.cgroup_id, raw_event.host_pid) {
                                Some((w, p)) => (w, p),
                                None => {
                                    let comm = raw_event.get_comm();
                                    let is_match = target_pid == 0
                                        || raw_event.host_pid == target_pid
                                        || raw_event.parent_pid == target_pid
                                        || (target_comm.is_some() && target_comm.as_ref() == Some(&comm));

                                    if is_match {
                                        (default_workload.clone(), default_principal.clone())
                                    } else {
                                        // Event outside monitored workloads; ignore or attribute to system
                                        continue;
                                    }
                                }
                            };

                            // If this was a fork event for an attributed process, dynamically register the child PID
                            if raw_event.event_type == crate::bpf_types::EVENT_TYPE_FORK && raw_event.host_pid > 0 {
                                attributor.register_workload(wkl_id.clone(), prn_id.clone(), 0, raw_event.host_pid);
                            }

                            let normalized = EventNormalizer::normalize(&raw_event, wkl_id, prn_id);
                            let _ = event_sender.send(normalized);
                        }
                        None => break,
                    }
                }
            });
        });

        // Retain eBPF instance for the lifetime of RuntimeSensor to keep kernel tracepoint attachments active
        *self.ebpf_holder.lock().unwrap() = Some(ebpf);

        true
    }

    /// Background watcher monitoring target process lifecycle via procfs (degraded fallback)
    fn spawn_procfs_watcher(&self, pid: u32) {
        let workload_id = self.config.workload_id.clone();
        let principal_id = self.config.principal_id.clone();
        let sender = self.event_sender.clone();
        let running_flag = self.is_running.clone();
        let health_lock = self.health_status.clone();
        let probe_lock = self.probe_state.clone();

        std::thread::spawn(move || {
            let proc_stat_path = format!("/proc/{}/stat", pid);
            let mut last_seen_alive = true;

            while running_flag.load(Ordering::SeqCst) {
                let exists = Path::new(&proc_stat_path).exists();
                if exists && !last_seen_alive {
                    last_seen_alive = true;
                } else if !exists && last_seen_alive {
                    let _ = sender.send(RuntimeEvent {
                        event_id: format!("evt_exit_{}", Uuid::new_v4().simple()),
                        timestamp_unix_nanos: Utc::now().timestamp_nanos_opt().unwrap_or(0),
                        workload_id: workload_id.clone(),
                        principal_id: principal_id.clone(),
                        process_id: pid,
                        parent_process_id: 1,
                        event_type: EventType::ProcessExit,
                        resource: "process://exited".to_string(),
                        outcome: EnforcementOutcome::Audited,
                        severity: Severity::Informational,
                        sensor_provenance: "procfs-watcher".to_string(),
                        attributes: HashMap::new(),
                    });

                    *health_lock.write().unwrap() = SensorHealthStatus::Unprotected;
                    *probe_lock.write().unwrap() = ProbeAttachmentState::Detached;
                    break;
                }

                std::thread::sleep(Duration::from_millis(50));
            }
        });
    }

    pub fn stop(&self) -> BadgerResult<()> {
        self.is_running.store(false, Ordering::SeqCst);
        self.ring_reader.stop();
        self.probe_manager.write().unwrap().clear();

        #[cfg(target_os = "linux")]
        {
            *self.ebpf_holder.lock().unwrap() = None;
        }

        *self.health_status.write().unwrap() = SensorHealthStatus::Unprotected;
        *self.probe_state.write().unwrap() = ProbeAttachmentState::Detached;

        self.emit_event(
            EventType::SensorStatusChange,
            "sensor://shutdown",
            EnforcementOutcome::Audited,
            Severity::Informational,
            "sensor-lifecycle",
            [("status".to_string(), "Stopped".to_string())].into(),
        )?;

        info!("Runtime sensor stopped for workload '{}'", self.config.workload_id);
        Ok(())
    }

    pub fn get_health_report(&self) -> CapabilityHealthReport {
        let target_pid = self.config.target_pid;
        let proc_path = format!("/proc/{}", target_pid);
        let pid_alive = if cfg!(target_os = "linux") {
            target_pid == 0 || Path::new(&proc_path).exists()
        } else {
            target_pid != 9999999
        };
        self.health_monitor.get_report(pid_alive)
    }

    pub fn get_health_status(&self) -> SensorHealthStatus {
        *self.health_status.read().unwrap()
    }

    pub fn get_probe_state(&self) -> ProbeAttachmentState {
        *self.probe_state.read().unwrap()
    }

    pub fn get_dropped_events_count(&self) -> u64 {
        self.ring_reader.get_dropped_count()
    }

    pub fn get_attached_probes(&self) -> Vec<ProbeType> {
        let mgr = self.probe_manager.read().unwrap();
        mgr.get_registry()
            .get_attached_probes()
            .into_iter()
            .filter(|(_, v)| *v)
            .map(|(k, _)| k)
            .collect()
    }

    pub fn register_workload_attribution(&self, workload_id: String, principal_id: String, cgroup_id: u64, pid: u32) {
        self.attributor.register_workload(workload_id, principal_id, cgroup_id, pid);
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

        if self.event_sender.receiver_count() > 0 {
            if let Err(tokio::sync::broadcast::error::SendError(_)) = self.event_sender.send(event.clone()) {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
                self.health_monitor.record_event_loss(1);
            }
        }

        Ok(event)
    }

    pub fn observe_file_access(
        &self,
        _pid: u32,
        path: &str,
        is_write: bool,
        outcome: EnforcementOutcome,
    ) -> BadgerResult<RuntimeEvent> {
        let mut attributes = HashMap::new();
        attributes.insert(
            "operation".to_string(),
            if is_write {
                "write".to_string()
            } else {
                "read".to_string()
            },
        );
        let severity = if outcome == EnforcementOutcome::Blocked {
            Severity::High
        } else {
            Severity::Informational
        };
        self.emit_event(
            if is_write {
                EventType::FileWrite
            } else {
                EventType::FileOpen
            },
            path,
            outcome,
            severity,
            "landlock-lsm",
            attributes,
        )
    }

    pub fn observe_net_connect(
        &self,
        _pid: u32,
        destination: &str,
        port: u16,
        outcome: EnforcementOutcome,
    ) -> BadgerResult<RuntimeEvent> {
        let mut attributes = HashMap::new();
        attributes.insert("destination".to_string(), destination.to_string());
        attributes.insert("port".to_string(), port.to_string());
        let severity = if outcome == EnforcementOutcome::Blocked {
            Severity::High
        } else {
            Severity::Informational
        };
        self.emit_event(
            EventType::NetConnect,
            &format!("{}:{}", destination, port),
            outcome,
            severity,
            "netfilter-boundary",
            attributes,
        )
    }

    pub fn observe_process_exec(
        &self,
        pid: u32,
        parent_pid: u32,
        executable: &str,
        args: &[String],
        outcome: EnforcementOutcome,
    ) -> BadgerResult<RuntimeEvent> {
        let mut attributes = HashMap::new();
        attributes.insert("args".to_string(), args.join(" "));
        attributes.insert("parent_pid".to_string(), parent_pid.to_string());
        attributes.insert("pid".to_string(), pid.to_string());
        let severity = if outcome == EnforcementOutcome::Blocked {
            Severity::High
        } else {
            Severity::Informational
        };
        self.emit_event(
            EventType::ProcessExec,
            executable,
            outcome,
            severity,
            "exec-monitor",
            attributes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensor_reports_unprotected_if_pid_does_not_exist() {
        let config = SensorConfig {
            workload_id: "wkl-dead".to_string(),
            principal_id: "prn-test".to_string(),
            target_pid: 9999999, // Non-existent PID
            cgroup_id: 0,
            enable_ebpf: true,
        };

        let (sensor, _rx) = RuntimeSensor::new(config);
        let _ = sensor.start();

        assert_eq!(sensor.get_health_status(), SensorHealthStatus::Unprotected);
        assert_eq!(sensor.get_probe_state(), ProbeAttachmentState::Detached);
    }

    #[test]
    fn test_sensor_capability_detection_and_reporting() {
        let config = SensorConfig {
            workload_id: "wkl-live".to_string(),
            principal_id: "prn-test".to_string(),
            target_pid: std::process::id(),
            cgroup_id: 1,
            enable_ebpf: true,
        };

        let (sensor, _rx) = RuntimeSensor::new(config);
        let _ = sensor.start();

        let report = sensor.get_health_report();
        assert_eq!(report.overall_status, sensor.get_health_status());
        assert_eq!(report.event_loss_count, 0);
        let _ = sensor.stop();
    }
}
