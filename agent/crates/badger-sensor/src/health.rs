use crate::bpf_types::{ProbeType, TelemetryCapabilityStatus};
use badger_common::SensorHealthStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityHealthReport {
    pub process_telemetry: TelemetryCapabilityStatus,
    pub network_telemetry: TelemetryCapabilityStatus,
    pub filesystem_telemetry: TelemetryCapabilityStatus,
    pub privilege_telemetry: TelemetryCapabilityStatus,
    pub event_transport: TelemetryCapabilityStatus,
    pub event_loss_count: u64,
    pub overall_status: SensorHealthStatus,
    pub degradation_reason: Option<String>,
}

pub struct TelemetryHealthMonitor {
    status_map: RwLock<HashMap<String, TelemetryCapabilityStatus>>,
    event_loss: RwLock<u64>,
}

impl Default for TelemetryHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryHealthMonitor {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert("process".to_string(), TelemetryCapabilityStatus::Unsupported);
        map.insert("network".to_string(), TelemetryCapabilityStatus::Unsupported);
        map.insert("filesystem".to_string(), TelemetryCapabilityStatus::Unsupported);
        map.insert("privilege".to_string(), TelemetryCapabilityStatus::Unsupported);
        map.insert("transport".to_string(), TelemetryCapabilityStatus::Unsupported);

        Self {
            status_map: RwLock::new(map),
            event_loss: RwLock::new(0),
        }
    }

    pub fn update_probes(&self, attached: &HashMap<ProbeType, bool>) {
        let mut map = self.status_map.write().unwrap();

        let proc_ok = attached.get(&ProbeType::ProcessExec).copied().unwrap_or(false)
            && attached.get(&ProbeType::ProcessExit).copied().unwrap_or(false);
        map.insert(
            "process".to_string(),
            if proc_ok {
                TelemetryCapabilityStatus::Active
            } else {
                TelemetryCapabilityStatus::Degraded
            },
        );

        let net_ok = attached.get(&ProbeType::NetworkConnect).copied().unwrap_or(false);
        map.insert(
            "network".to_string(),
            if net_ok {
                TelemetryCapabilityStatus::Active
            } else {
                TelemetryCapabilityStatus::Unsupported
            },
        );

        let fs_ok = attached.get(&ProbeType::FilesystemOpen).copied().unwrap_or(false);
        map.insert(
            "filesystem".to_string(),
            if fs_ok {
                TelemetryCapabilityStatus::Active
            } else {
                TelemetryCapabilityStatus::Unsupported
            },
        );

        let priv_ok = attached.get(&ProbeType::PrivilegeSetuid).copied().unwrap_or(false);
        map.insert(
            "privilege".to_string(),
            if priv_ok {
                TelemetryCapabilityStatus::Active
            } else {
                TelemetryCapabilityStatus::Unsupported
            },
        );

        map.insert("transport".to_string(), TelemetryCapabilityStatus::Active);
    }

    pub fn set_degraded_procfs(&self) {
        let mut map = self.status_map.write().unwrap();
        map.insert("process".to_string(), TelemetryCapabilityStatus::Degraded);
        map.insert("network".to_string(), TelemetryCapabilityStatus::Unsupported);
        map.insert("filesystem".to_string(), TelemetryCapabilityStatus::Unsupported);
        map.insert("privilege".to_string(), TelemetryCapabilityStatus::Unsupported);
        map.insert("transport".to_string(), TelemetryCapabilityStatus::Degraded);
    }

    pub fn record_event_loss(&self, count: u64) {
        *self.event_loss.write().unwrap() += count;
    }

    pub fn get_report(&self, target_alive: bool) -> CapabilityHealthReport {
        let map = self.status_map.read().unwrap();
        let loss = *self.event_loss.read().unwrap();

        let proc_stat = *map.get("process").unwrap_or(&TelemetryCapabilityStatus::Unsupported);
        let net_stat = *map.get("network").unwrap_or(&TelemetryCapabilityStatus::Unsupported);
        let fs_stat = *map.get("filesystem").unwrap_or(&TelemetryCapabilityStatus::Unsupported);
        let priv_stat = *map.get("privilege").unwrap_or(&TelemetryCapabilityStatus::Unsupported);
        let trans_stat = *map.get("transport").unwrap_or(&TelemetryCapabilityStatus::Unsupported);

        let (overall, reason) = if !target_alive {
            (SensorHealthStatus::Unprotected, Some("Target process is not running or missing from /proc".to_string()))
        } else if proc_stat == TelemetryCapabilityStatus::Active && trans_stat == TelemetryCapabilityStatus::Active {
            (SensorHealthStatus::Protected, None)
        } else if proc_stat == TelemetryCapabilityStatus::Degraded {
            (SensorHealthStatus::Degraded, Some("Operating in procfs fallback mode (no eBPF attached)".to_string()))
        } else {
            (SensorHealthStatus::Degraded, Some("Partial telemetry probe coverage".to_string()))
        };

        CapabilityHealthReport {
            process_telemetry: proc_stat,
            network_telemetry: net_stat,
            filesystem_telemetry: fs_stat,
            privilege_telemetry: priv_stat,
            event_transport: trans_stat,
            event_loss_count: loss,
            overall_status: overall,
            degradation_reason: reason,
        }
    }
}
