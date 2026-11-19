use std::collections::HashMap;
use std::sync::RwLock;

pub struct WorkloadAttributor {
    cgroup_to_workload: RwLock<HashMap<u64, (String, String)>>,
    pid_to_workload: RwLock<HashMap<u32, (String, String)>>,
}

impl Default for WorkloadAttributor {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkloadAttributor {
    pub fn new() -> Self {
        Self {
            cgroup_to_workload: RwLock::new(HashMap::new()),
            pid_to_workload: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a workload by its cgroup v2 inode ID and target PID.
    /// Note: cgroup_id 1 is the Linux root cgroup (`/sys/fs/cgroup`) which contains all host processes;
    /// only isolated workload cgroups (inode > 1) are registered for cgroup attribution.
    pub fn register_workload(
        &self,
        workload_id: String,
        principal_id: String,
        cgroup_id: u64,
        pid: u32,
    ) {
        if cgroup_id > 1 {
            self.cgroup_to_workload
                .write()
                .unwrap()
                .insert(cgroup_id, (workload_id.clone(), principal_id.clone()));
        }
        if pid > 0 {
            self.pid_to_workload
                .write()
                .unwrap()
                .insert(pid, (workload_id, principal_id));
        }
    }

    pub fn unregister_workload(&self, cgroup_id: u64, pid: u32) {
        if cgroup_id > 1 {
            self.cgroup_to_workload.write().unwrap().remove(&cgroup_id);
        }
        if pid > 0 {
            self.pid_to_workload.write().unwrap().remove(&pid);
        }
    }

    /// Primary attribution: cgroup_id match (immune to PID reuse attacks!)
    /// Secondary fallback: pid match
    pub fn attribute(&self, cgroup_id: u64, pid: u32) -> Option<(String, String)> {
        if cgroup_id > 1 {
            if let Some(res) = self.cgroup_to_workload.read().unwrap().get(&cgroup_id) {
                return Some(res.clone());
            }
        }
        if pid > 0 {
            if let Some(res) = self.pid_to_workload.read().unwrap().get(&pid) {
                return Some(res.clone());
            }
        }
        None
    }
}
