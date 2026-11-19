use crate::bpf_types::ProbeType;
use badger_common::{BadgerError, BadgerResult};
use std::collections::HashMap;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use aya::programs::trace_point::TracePointLinkId;
#[cfg(target_os = "linux")]
use aya::programs::TracePoint;

pub struct ProbeAttachmentRegistry {
    #[cfg(target_os = "linux")]
    links: HashMap<ProbeType, TracePointLinkId>,
    attached_probes: HashMap<ProbeType, bool>,
}

impl Default for ProbeAttachmentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeAttachmentRegistry {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            links: HashMap::new(),
            attached_probes: HashMap::new(),
        }
    }

    pub fn record_attached(&mut self, probe: ProbeType) {
        self.attached_probes.insert(probe, true);
    }

    pub fn is_attached(&self, probe: &ProbeType) -> bool {
        *self.attached_probes.get(probe).unwrap_or(&false)
    }

    pub fn get_attached_probes(&self) -> HashMap<ProbeType, bool> {
        self.attached_probes.clone()
    }
}

pub struct ProbeManager {
    registry: ProbeAttachmentRegistry,
}

impl Default for ProbeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeManager {
    pub fn new() -> Self {
        Self {
            registry: ProbeAttachmentRegistry::new(),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn attach_all(&mut self, ebpf: &mut aya::Ebpf) -> BadgerResult<()> {
        let probe_specs: Vec<(ProbeType, &str, &str, &str)> = vec![
            (
                ProbeType::ProcessExec,
                "handle_process_exec",
                "sched",
                "sched_process_exec",
            ),
            (
                ProbeType::ProcessExit,
                "handle_process_exit",
                "sched",
                "sched_process_exit",
            ),
            (
                ProbeType::ProcessFork,
                "handle_process_fork",
                "sched",
                "sched_process_fork",
            ),
            (
                ProbeType::NetworkConnect,
                "handle_sys_connect",
                "syscalls",
                "sys_enter_connect",
            ),
            (
                ProbeType::FilesystemOpen,
                "handle_sys_openat",
                "syscalls",
                "sys_enter_openat",
            ),
            (
                ProbeType::PrivilegeSetuid,
                "handle_sys_setuid",
                "syscalls",
                "sys_enter_setuid",
            ),
        ];

        for (pt, prog_name, category, tp_name) in probe_specs {
            match self.attach_tracepoint(ebpf, prog_name, category, tp_name) {
                Ok(link_id) => {
                    self.registry.links.insert(pt.clone(), link_id);
                    self.registry.record_attached(pt);
                    info!(
                        "Tracepoint probe attached: category='{}', name='{}'",
                        category, tp_name
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to attach tracepoint '{}/{}': {}. Telemetry degraded.",
                        category, tp_name, e
                    );
                }
            }
        }

        if self.registry.attached_probes.is_empty() {
            return Err(BadgerError::Sensor(
                "Failed to attach any eBPF kernel tracepoints".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn attach_tracepoint(
        &self,
        ebpf: &mut aya::Ebpf,
        prog_name: &str,
        category: &str,
        tp_name: &str,
    ) -> BadgerResult<TracePointLinkId> {
        let program: &mut TracePoint = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| BadgerError::Sensor(format!("Program '{}' not found in eBPF ELF", prog_name)))?
            .try_into()
            .map_err(|e| BadgerError::Sensor(format!("Failed to downcast program '{}': {}", prog_name, e)))?;

        program
            .load()
            .map_err(|e| BadgerError::Sensor(format!("Failed to load '{}': {}", prog_name, e)))?;

        program
            .attach(category, tp_name)
            .map_err(|e| BadgerError::Sensor(format!("Failed to attach '{}/{}': {}", category, tp_name, e)))
    }

    pub fn get_registry(&self) -> &ProbeAttachmentRegistry {
        &self.registry
    }

    pub fn clear(&mut self) {
        #[cfg(target_os = "linux")]
        self.registry.links.clear();
        self.registry.attached_probes.clear();
    }
}
