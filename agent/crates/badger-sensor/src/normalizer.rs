use crate::bpf_types::{
    BadgerBpfEvent, EVENT_TYPE_CONNECT, EVENT_TYPE_EXEC, EVENT_TYPE_EXIT, EVENT_TYPE_FORK,
    EVENT_TYPE_OPENAT, EVENT_TYPE_SETUID, EVENT_TYPE_UNLINKAT,
};
use badger_common::{EnforcementOutcome, EventType, RuntimeEvent, Severity};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

pub struct EventNormalizer;

impl EventNormalizer {
    pub fn normalize(
        raw: &BadgerBpfEvent,
        workload_id: String,
        principal_id: String,
    ) -> RuntimeEvent {
        let (event_type, severity, outcome) = match raw.event_type {
            EVENT_TYPE_EXEC => (
                EventType::ProcessExec,
                Severity::Informational,
                EnforcementOutcome::Audited,
            ),
            EVENT_TYPE_EXIT => (
                EventType::ProcessExit,
                Severity::Informational,
                EnforcementOutcome::Audited,
            ),
            EVENT_TYPE_FORK => (
                EventType::ProcessExec, // Fork/creation normalized to ProcessExec event with parent info
                Severity::Informational,
                EnforcementOutcome::Audited,
            ),
            EVENT_TYPE_CONNECT => (
                EventType::NetConnect,
                Severity::Low,
                EnforcementOutcome::Audited,
            ),
            EVENT_TYPE_OPENAT => (
                EventType::FileOpen,
                Severity::Informational,
                EnforcementOutcome::Audited,
            ),
            EVENT_TYPE_UNLINKAT => (
                EventType::FileWrite,
                Severity::Medium,
                EnforcementOutcome::Audited,
            ),
            EVENT_TYPE_SETUID => (
                EventType::PrivilegeChange,
                Severity::High,
                EnforcementOutcome::Audited,
            ),
            _ => (
                EventType::SensorStatusChange,
                Severity::Informational,
                EnforcementOutcome::Audited,
            ),
        };

        let mut attributes = HashMap::new();
        attributes.insert("schema_version".to_string(), "1.0.0".to_string());
        attributes.insert("cpu_id".to_string(), raw.cpu_id.to_string());
        attributes.insert("cgroup_id".to_string(), raw.cgroup_id.to_string());
        attributes.insert("host_tid".to_string(), raw.host_tid.to_string());
        attributes.insert("parent_pid".to_string(), raw.parent_pid.to_string());
        attributes.insert("uid".to_string(), raw.uid.to_string());
        attributes.insert("gid".to_string(), raw.gid.to_string());
        attributes.insert("comm".to_string(), raw.get_comm());
        attributes.insert(
            "monotonic_timestamp_ns".to_string(),
            raw.timestamp_ns.to_string(),
        );

        let event_id = format!("evt_ebpf_{}", Uuid::new_v4().simple());
        let now_nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0);

        RuntimeEvent {
            event_id,
            timestamp_unix_nanos: now_nanos,
            workload_id,
            principal_id,
            process_id: raw.host_pid,
            parent_process_id: raw.parent_pid,
            event_type,
            resource: raw.get_resource(),
            outcome,
            severity,
            sensor_provenance: "ebpf-tracepoint".to_string(),
            attributes,
        }
    }
}
