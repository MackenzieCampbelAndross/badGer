use badger_common::{BadgerError, BadgerResult};
use tracing::{info, warn};

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

pub struct SeccompEnforcer {
    pub blocked_syscalls: Vec<u32>,
}

impl Default for SeccompEnforcer {
    fn default() -> Self {
        // High-risk syscalls denied by default for autonomous agents
        Self {
            blocked_syscalls: vec![
                101, // ptrace
                321, // bpf
                165, // mount
                166, // umount2
                155, // pivot_root
                246, // kexec_load
                169, // reboot
            ],
        }
    }
}

impl SeccompEnforcer {
    pub fn new(additional_blocked: Vec<u32>) -> Self {
        let mut def = Self::default();
        def.blocked_syscalls.extend(additional_blocked);
        def
    }

    #[cfg(target_os = "linux")]
    pub fn apply(&self) -> BadgerResult<bool> {
        const BPF_LD: u16 = 0x00;
        const BPF_W: u16 = 0x00;
        const BPF_ABS: u16 = 0x20;
        const BPF_JMP: u16 = 0x05;
        const BPF_JEQ: u16 = 0x10;
        const BPF_K: u16 = 0x00;
        const BPF_RET: u16 = 0x06;

        const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
        const SECCOMP_RET_ERRNO: u32 = 0x00050000 | (libc::EPERM as u32);
        const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
        const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(BadgerError::Sandbox(
                    "Failed to set PR_SET_NO_NEW_PRIVS for Seccomp".to_string(),
                ));
            }

            let mut filter: Vec<SockFilter> = Vec::new();

            // 1. Validate architecture: Load arch
            filter.push(SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 4, // offsetof(struct seccomp_data, arch)
            });
            // If arch != X86_64, kill process
            filter.push(SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH_X86_64,
            });
            filter.push(SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            });

            // 2. Load syscall number: offsetof(struct seccomp_data, nr) = 0
            filter.push(SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            });

            // 3. For each blocked syscall, if equal return EPERM
            for &syscall_nr in &self.blocked_syscalls {
                filter.push(SockFilter {
                    code: BPF_JMP | BPF_JEQ | BPF_K,
                    jt: 0,
                    jf: 1,
                    k: syscall_nr,
                });
                filter.push(SockFilter {
                    code: BPF_RET | BPF_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ERRNO,
                });
            }

            // 4. Default: ALLOW
            filter.push(SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            });

            let prog = SockFprog {
                len: filter.len() as u16,
                filter: filter.as_ptr(),
            };

            // Syscall 317: seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)
            let res = libc::syscall(317, 1, 0, &prog as *const SockFprog);
            if res != 0 {
                return Err(BadgerError::Sandbox(format!(
                    "Failed to install seccomp filter: {}",
                    std::io::Error::last_os_error()
                )));
            }

            info!(
                "Seccomp-BPF syscall containment installed ({} blocked syscalls)",
                self.blocked_syscalls.len()
            );
            Ok(true)
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(&self) -> BadgerResult<bool> {
        warn!("Seccomp-BPF is only supported on Linux. Host is non-Linux.");
        Ok(false)
    }
}
