use badger_common::{BadgerError, BadgerResult, ResourceLimits};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub struct CgroupV2Manager {
    cgroup_path: PathBuf,
}

impl CgroupV2Manager {
    pub fn new(workload_id: &str) -> Self {
        let base = Path::new("/sys/fs/cgroup/badger");
        let path = base.join(workload_id);
        Self { cgroup_path: path }
    }

    pub fn setup(&self, limits: &ResourceLimits) -> BadgerResult<()> {
        if !Path::new("/sys/fs/cgroup").exists() {
            warn!("cgroups v2 not available at /sys/fs/cgroup; resource limits will be degraded");
            return Ok(());
        }

        // Create cgroup hierarchy
        if let Err(e) = fs::create_dir_all(&self.cgroup_path) {
            warn!("Failed to create cgroup path {:?}: {}", self.cgroup_path, e);
            return Ok(());
        }

        // Apply memory.max
        let mem_file = self.cgroup_path.join("memory.max");
        if mem_file.exists() {
            let val = format!("{}", limits.max_memory_bytes);
            let _ = fs::write(&mem_file, val);
        }

        // Apply pids.max
        let pids_file = self.cgroup_path.join("pids.max");
        if pids_file.exists() {
            let val = format!("{}", limits.max_pids);
            let _ = fs::write(&pids_file, val);
        }

        // Apply cpu.max
        let cpu_file = self.cgroup_path.join("cpu.max");
        if cpu_file.exists() {
            let val = format!("{} {}", limits.cpu_quota_us, limits.cpu_period_us);
            let _ = fs::write(&cpu_file, val);
        }

        info!("cgroups v2 configured at {:?}", self.cgroup_path);
        Ok(())
    }

    pub fn attach_pid(&self, pid: u32) -> BadgerResult<()> {
        let procs_file = self.cgroup_path.join("cgroup.procs");
        if procs_file.exists() {
            fs::write(&procs_file, format!("{}", pid)).map_err(|e| {
                BadgerError::Sandbox(format!("Failed to attach PID {} to cgroup: {}", pid, e))
            })?;
        }
        Ok(())
    }

    pub fn freeze(&self) -> BadgerResult<()> {
        let freeze_file = self.cgroup_path.join("cgroup.freeze");
        if freeze_file.exists() {
            fs::write(&freeze_file, "1").map_err(|e| {
                BadgerError::Containment(format!("Failed to freeze cgroup: {}", e))
            })?;
            info!("Workload cgroup frozen at {:?}", self.cgroup_path);
        }
        Ok(())
    }

    pub fn unfreeze(&self) -> BadgerResult<()> {
        let freeze_file = self.cgroup_path.join("cgroup.freeze");
        if freeze_file.exists() {
            fs::write(&freeze_file, "0").map_err(|e| {
                BadgerError::Containment(format!("Failed to unfreeze cgroup: {}", e))
            })?;
            info!("Workload cgroup thawed at {:?}", self.cgroup_path);
        }
        Ok(())
    }

    pub fn read_stats(&self) -> (u64, u32) {
        let mut mem_current = 0u64;
        let mut pids_current = 0u32;

        let mem_file = self.cgroup_path.join("memory.current");
        if let Ok(content) = fs::read_to_string(mem_file) {
            mem_current = content.trim().parse().unwrap_or(0);
        }

        let pids_file = self.cgroup_path.join("pids.current");
        if let Ok(content) = fs::read_to_string(pids_file) {
            pids_current = content.trim().parse().unwrap_or(0);
        }

        (mem_current, pids_current)
    }

    pub fn cleanup(&self) {
        if self.cgroup_path.exists() {
            let _ = fs::remove_dir(&self.cgroup_path);
        }
    }
}
