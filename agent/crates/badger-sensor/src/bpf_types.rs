use serde::{Deserialize, Serialize};

pub const EVENT_TYPE_EXEC: u32 = 1;
pub const EVENT_TYPE_EXIT: u32 = 2;
pub const EVENT_TYPE_FORK: u32 = 3;
pub const EVENT_TYPE_CONNECT: u32 = 4;
pub const EVENT_TYPE_SETUID: u32 = 5;
pub const EVENT_TYPE_OPENAT: u32 = 6;
pub const EVENT_TYPE_UNLINKAT: u32 = 7;

pub const COMM_MAX_LEN: usize = 16;
pub const RESOURCE_MAX_LEN: usize = 128;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BadgerBpfEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub host_pid: u32,
    pub host_tid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cpu_id: u32,
    pub event_type: u32,
    pub comm: [u8; COMM_MAX_LEN],
    pub resource: [u8; RESOURCE_MAX_LEN],
}

impl BadgerBpfEvent {
    pub fn get_comm(&self) -> String {
        String::from_utf8_lossy(&self.comm)
            .trim_matches('\0')
            .trim()
            .to_string()
    }

    pub fn get_resource(&self) -> String {
        String::from_utf8_lossy(&self.resource)
            .trim_matches('\0')
            .trim()
            .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeType {
    ProcessExec,
    ProcessExit,
    ProcessFork,
    NetworkConnect,
    FilesystemOpen,
    PrivilegeSetuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetryCapabilityStatus {
    Active,
    Degraded,
    Unsupported,
    Failed,
}
