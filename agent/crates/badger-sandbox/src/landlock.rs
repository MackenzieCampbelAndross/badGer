use badger_common::{BadgerError, BadgerResult, FilesystemRule, FsAccess};
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

#[repr(C)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
}

#[repr(C)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

pub struct LandlockEnforcer {
    rules: Vec<FilesystemRule>,
}

impl LandlockEnforcer {
    pub fn new(rules: Vec<FilesystemRule>) -> Self {
        Self { rules }
    }

    #[cfg(target_os = "linux")]
    pub fn apply(&self) -> BadgerResult<bool> {
        unsafe {
            // Check prctl(PR_SET_NO_NEW_PRIVS)
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(BadgerError::Sandbox(
                    "Failed to set PR_SET_NO_NEW_PRIVS for Landlock".to_string(),
                ));
            }

            let full_access_mask = LANDLOCK_ACCESS_FS_EXECUTE
                | LANDLOCK_ACCESS_FS_WRITE_FILE
                | LANDLOCK_ACCESS_FS_READ_FILE
                | LANDLOCK_ACCESS_FS_READ_DIR
                | LANDLOCK_ACCESS_FS_REMOVE_DIR
                | LANDLOCK_ACCESS_FS_REMOVE_FILE
                | LANDLOCK_ACCESS_FS_MAKE_DIR
                | LANDLOCK_ACCESS_FS_MAKE_REG
                | LANDLOCK_ACCESS_FS_MAKE_SYM;

            let attr = LandlockRulesetAttr {
                handled_access_fs: full_access_mask,
            };

            // Syscall 444: landlock_create_ruleset
            let ruleset_fd = libc::syscall(
                444, // SYS_landlock_create_ruleset
                &attr as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0u32,
            ) as i32;

            if ruleset_fd < 0 {
                let err = std::io::Error::last_os_error();
                warn!("Landlock not supported by current kernel: {}", err);
                return Ok(false);
            }

            // Populate rules
            for rule in &self.rules {
                let allowed_access = match rule.access {
                    FsAccess::None => 0,
                    FsAccess::Ro => {
                        LANDLOCK_ACCESS_FS_READ_FILE
                            | LANDLOCK_ACCESS_FS_READ_DIR
                            | LANDLOCK_ACCESS_FS_EXECUTE
                    }
                    FsAccess::Rw => full_access_mask,
                };

                if allowed_access == 0 {
                    continue; // Denied by exclusion from ruleset
                }

                if let Ok(c_path) = CString::new(rule.path.as_str()) {
                    let fd = libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
                    if fd >= 0 {
                        let path_beneath = LandlockPathBeneathAttr {
                            allowed_access,
                            parent_fd: fd,
                        };

                        // Syscall 445: landlock_add_rule
                        let add_res = libc::syscall(
                            445, // SYS_landlock_add_rule
                            ruleset_fd,
                            LANDLOCK_RULE_PATH_BENEATH,
                            &path_beneath as *const LandlockPathBeneathAttr,
                            0u32,
                        );

                        libc::close(fd);

                        if add_res != 0 {
                            warn!("Failed to add landlock rule for {:?}: {}", rule.path, std::io::Error::last_os_error());
                        }
                    }
                }
            }

            // Syscall 446: landlock_restrict_self
            let res = libc::syscall(446, ruleset_fd, 0u32);
            libc::close(ruleset_fd);

            if res != 0 {
                return Err(BadgerError::Sandbox(format!(
                    "Failed to enforce Landlock restrictions: {}",
                    std::io::Error::last_os_error()
                )));
            }

            info!("Landlock filesystem containment actively enforced by Linux kernel LSM");
            Ok(true)
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(&self) -> BadgerResult<bool> {
        warn!("Landlock filesystem containment is only supported on Linux kernels (>= 5.13). Host is non-Linux.");
        Ok(false)
    }
}
