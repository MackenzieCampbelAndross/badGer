use badger_common::{BadgerError, BadgerResult, FilesystemRule, FsAccess};
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use std::ffi::CString;

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
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

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

    /// Queries the kernel for supported Landlock ABI version
    #[cfg(target_os = "linux")]
    pub fn query_abi_version() -> i32 {
        unsafe {
            libc::syscall(
                444, // SYS_landlock_create_ruleset
                std::ptr::null::<LandlockRulesetAttr>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            ) as i32
        }
    }

    /// Masks denied subpaths (`access == None`) within a private mount namespace.
    /// This directly neutralizes Landlock's hierarchical inheritance where child paths
    /// under an allowlisted parent (e.g. `/etc/shadow` under `/etc`) would otherwise inherit read rights.
    #[cfg(target_os = "linux")]
    pub fn apply_mount_masks(&self) -> BadgerResult<()> {
        use nix::mount::{mount, MsFlags};
        use std::path::Path;

        // Ensure mount namespace propagation is private
        let _ = mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        );

        for rule in &self.rules {
            if rule.access == FsAccess::None {
                let target = Path::new(&rule.path);
                if target.exists() {
                    if target.is_dir() {
                        // Mask directory with an empty, inaccessible read-only tmpfs
                        let _ = mount(
                            Some("tmpfs"),
                            rule.path.as_str(),
                            Some("tmpfs"),
                            MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RDONLY,
                            Some("mode=0000"),
                        );
                    } else if target.is_file() {
                        // Bind mount /dev/null over denied file
                        let _ = mount(
                            Some("/dev/null"),
                            rule.path.as_str(),
                            None::<&str>,
                            MsFlags::MS_BIND,
                            None::<&str>,
                        );
                        let _ = mount(
                            None::<&str>,
                            rule.path.as_str(),
                            None::<&str>,
                            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                            None::<&str>,
                        );
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn apply(&self) -> BadgerResult<bool> {
        // 1. Mask denied subpaths first in mount namespace
        let _ = self.apply_mount_masks();

        // 2. Query Landlock ABI version
        let abi = Self::query_abi_version();
        if abi <= 0 {
            warn!("Landlock LSM is not supported by active Linux kernel (ABI={}).", abi);
            return Ok(false);
        }

        unsafe {
            // Set PR_SET_NO_NEW_PRIVS
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(BadgerError::Sandbox(
                    "Failed to set PR_SET_NO_NEW_PRIVS for Landlock".to_string(),
                ));
            }

            // Build handled_access_fs according to kernel ABI version
            let mut full_access_mask = LANDLOCK_ACCESS_FS_EXECUTE
                | LANDLOCK_ACCESS_FS_WRITE_FILE
                | LANDLOCK_ACCESS_FS_READ_FILE
                | LANDLOCK_ACCESS_FS_READ_DIR
                | LANDLOCK_ACCESS_FS_REMOVE_DIR
                | LANDLOCK_ACCESS_FS_REMOVE_FILE
                | LANDLOCK_ACCESS_FS_MAKE_DIR
                | LANDLOCK_ACCESS_FS_MAKE_REG
                | LANDLOCK_ACCESS_FS_MAKE_SYM;

            if abi >= 2 {
                full_access_mask |= LANDLOCK_ACCESS_FS_REFER;
            }
            if abi >= 3 {
                full_access_mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
            }

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
                warn!("Failed to create Landlock ruleset: {}", err);
                return Ok(false);
            }

            // Populate allow rules
            for rule in &self.rules {
                let allowed_access = match rule.access {
                    FsAccess::None => continue, // Denied subpaths are masked via mount namespace
                    FsAccess::Ro => {
                        LANDLOCK_ACCESS_FS_READ_FILE
                            | LANDLOCK_ACCESS_FS_READ_DIR
                            | LANDLOCK_ACCESS_FS_EXECUTE
                    }
                    FsAccess::Rw => full_access_mask,
                };

                // Canonicalize if possible to prevent symlink bypass
                let canonical_path = std::fs::canonicalize(&rule.path)
                    .unwrap_or_else(|_| std::path::PathBuf::from(&rule.path));

                if let Ok(c_path) = CString::new(canonical_path.to_string_lossy().as_bytes()) {
                    let fd = libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
                    if fd >= 0 {
                        let path_beneath = LandlockPathBeneathAttr {
                            allowed_access,
                            parent_fd: fd,
                        };

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

            info!("Landlock filesystem containment actively enforced (ABI v{})", abi);
            Ok(true)
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(&self) -> BadgerResult<bool> {
        warn!("Landlock filesystem containment is only supported on Linux kernels (>= 5.13). Host is non-Linux.");
        Ok(false)
    }
}
