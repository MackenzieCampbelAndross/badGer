pub mod cgroups;
pub mod landlock;
pub mod seccomp;

use badger_common::{BadgerError, BadgerResult, CapabilityPolicy};
use cgroups::CgroupV2Manager;
use landlock::LandlockEnforcer;
use seccomp::SeccompEnforcer;
use std::process::{Child, Command, ExitStatus};
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

pub struct SandboxConfig {
    pub workload_id: String,
    pub policy: CapabilityPolicy,
    pub isolate_network: bool,
}

pub struct LinuxSandbox {
    config: SandboxConfig,
    cgroups: CgroupV2Manager,
}

impl LinuxSandbox {
    pub fn new(config: SandboxConfig) -> Self {
        let cgroups = CgroupV2Manager::new(&config.workload_id);
        Self { config, cgroups }
    }

    /// Prepares cgroup v2 resource limits
    pub fn prepare(&self) -> BadgerResult<()> {
        self.cgroups.setup(&self.config.policy.limits)
    }

    /// Spawns the workload inside the restricted containment boundary
    #[cfg(target_os = "linux")]
    pub fn spawn(&self, program: &str, args: &[&str]) -> BadgerResult<Child> {
        let landlock = LandlockEnforcer::new(self.config.policy.filesystem_rules.clone());
        let seccomp = SeccompEnforcer::default();
        let isolate_net = self.config.isolate_network;

        let mut cmd = Command::new(program);
        cmd.args(args);

        // Pre-exec hook executes in child process after fork, before exec
        unsafe {
            cmd.pre_exec(move || {
                // 1. Unshare namespaces
                // CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | (CLONE_NEWNET if requested)
                let mut flags = nix::sched::CloneFlags::CLONE_NEWNS
                    | nix::sched::CloneFlags::CLONE_NEWPID
                    | nix::sched::CloneFlags::CLONE_NEWIPC
                    | nix::sched::CloneFlags::CLONE_NEWUTS;

                if isolate_net {
                    flags |= nix::sched::CloneFlags::CLONE_NEWNET;
                }

                if let Err(e) = nix::sched::unshare(flags) {
                    eprintln!("Failed to unshare namespaces: {}", e);
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }

                // 2. Set NO_NEW_PRIVS
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // 3. Apply Landlock LSM filesystem restriction
                if let Err(e) = landlock.apply() {
                    eprintln!("Landlock apply error: {}", e);
                }

                // 4. Apply Seccomp-BPF syscall filter
                if let Err(e) = seccomp.apply() {
                    eprintln!("Seccomp apply error: {}", e);
                }

                Ok(())
            });
        }

        let child = cmd.spawn().map_err(|e| {
            BadgerError::Sandbox(format!("Failed to spawn sandboxed process '{}': {}", program, e))
        })?;

        // Attach child PID to cgroup v2
        let _ = self.cgroups.attach_pid(child.id());

        info!(
            "Spawned sandboxed workload '{}' (PID {})",
            self.config.workload_id,
            child.id()
        );
        Ok(child)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn spawn(&self, program: &str, args: &[&str]) -> BadgerResult<Child> {
        warn!(
            "Non-Linux platform detected. Linux kernel namespaces, Landlock, and cgroups v2 are unavailable on Windows host. Running under degraded host execution."
        );
        let mut cmd = Command::new(program);
        cmd.args(args);
        let child = cmd.spawn().map_err(|e| {
            BadgerError::Sandbox(format!("Failed to spawn process '{}': {}", program, e))
        })?;
        Ok(child)
    }

    pub fn freeze(&self) -> BadgerResult<()> {
        self.cgroups.freeze()
    }

    pub fn unfreeze(&self) -> BadgerResult<()> {
        self.cgroups.unfreeze()
    }

    pub fn get_metrics(&self) -> (u64, u32) {
        self.cgroups.read_stats()
    }

    pub fn cleanup(&self) {
        self.cgroups.cleanup();
    }
}
