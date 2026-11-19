pub mod cgroups;
pub mod landlock;
pub mod seccomp;

use badger_common::{BadgerError, BadgerResult, CapabilityPolicy};
use cgroups::CgroupV2Manager;
use landlock::LandlockEnforcer;
use seccomp::SeccompEnforcer;
use std::process::{Child, Command};
use tracing::info;

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

pub struct SandboxConfig {
    pub workload_id: String,
    pub policy: CapabilityPolicy,
    pub isolate_network: bool,
    pub network_policy: Option<badger_network::NetworkPolicy>,
}

pub struct LinuxSandbox {
    config: SandboxConfig,
    cgroups: CgroupV2Manager,
    network_enforcer: std::sync::Mutex<Option<std::sync::Arc<badger_network::NetworkEnforcer>>>,
}

impl LinuxSandbox {
    pub fn new(config: SandboxConfig) -> Self {
        let cgroups = CgroupV2Manager::new(&config.workload_id);
        Self {
            config,
            cgroups,
            network_enforcer: std::sync::Mutex::new(None),
        }
    }

    /// Prepares cgroup v2 resource limits and attaches network enforcer if configured
    pub fn prepare(&self) -> BadgerResult<()> {
        self.cgroups.setup(&self.config.policy.limits)?;

        #[cfg(target_os = "linux")]
        if !self.config.isolate_network {
            if let Some(ref net_pol) = self.config.network_policy {
                let enforcer = std::sync::Arc::new(badger_network::NetworkEnforcer::new(
                    &self.config.workload_id,
                    self.cgroups.get_path().to_path_buf(),
                ));
                enforcer.attach(net_pol)?;
                *self.network_enforcer.lock().unwrap() = Some(enforcer);
            }
        }

        Ok(())
    }

    pub fn get_network_enforcer(&self) -> Option<std::sync::Arc<badger_network::NetworkEnforcer>> {
        self.network_enforcer.lock().unwrap().clone()
    }

    /// Spawns the workload inside verified Linux containment boundaries
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
                // 1. Unshare namespaces: Mount, PID, IPC, UTS, and optionally Network
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

                // 2. Make mount propagation private
                if let Err(e) = nix::mount::mount(
                    None::<&str>,
                    "/",
                    None::<&str>,
                    nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
                    None::<&str>,
                ) {
                    eprintln!("Failed to make root mount private: {}", e);
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }

                // 3. Proper PID namespace lifecycle:
                // Because unshare(CLONE_NEWPID) only moves future children into the new PID namespace,
                // we must fork here. The intermediate parent process waits for the child workload and exits
                // with its status code, while the child runs as PID 1 in the isolated PID namespace.
                let child_pid = libc::fork();
                if child_pid < 0 {
                    eprintln!("Failed to fork into new PID namespace: {}", std::io::Error::last_os_error());
                    return Err(std::io::Error::last_os_error());
                }

                if child_pid > 0 {
                    // Intermediate parent: wait for sandboxed child process and forward exit code
                    let mut status: i32 = 0;
                    libc::waitpid(child_pid, &mut status, 0);
                    let exit_code = if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else if libc::WIFSIGNALED(status) {
                        128 + libc::WTERMSIG(status)
                    } else {
                        1
                    };
                    libc::_exit(exit_code);
                }

                // --- Inside the isolated workload child (now PID 1 in the new namespace) ---

                // 4. Mount private procfs so host processes are completely invisible
                let _ = nix::mount::mount(
                    Some("proc"),
                    "/proc",
                    Some("proc"),
                    nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV | nix::mount::MsFlags::MS_NOEXEC,
                    None::<&str>,
                );

                // 5. Apply filesystem mount masks over denied subpaths
                if let Err(e) = landlock.apply_mount_masks() {
                    eprintln!("Failed to apply mount masks: {}", e);
                    return Err(std::io::Error::from_raw_os_error(libc::EACCES));
                }

                // 6. Set PR_SET_NO_NEW_PRIVS (locks privilege escalation)
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    eprintln!("Failed to set PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error());
                    return Err(std::io::Error::last_os_error());
                }

                // 7. Apply Landlock LSM filesystem restriction
                if let Err(e) = landlock.apply() {
                    eprintln!("Landlock containment enforcement failed: {}", e);
                    return Err(std::io::Error::from_raw_os_error(libc::EACCES));
                }

                // 8. Apply Seccomp-BPF syscall filter
                if let Err(e) = seccomp.apply() {
                    eprintln!("Seccomp containment enforcement failed: {}", e);
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
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
            "Spawned sandboxed workload '{}' (Parent PID {})",
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
