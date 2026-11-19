use crate::capability::Capability;
use crate::model::EnforcementPath;
use std::path::Path;

pub struct EnforcementBridge;

impl EnforcementBridge {
    /// Determines the concrete operating system enforcement mechanism backing a capability.
    /// Returns Unsupported if no real OS enforcement mechanism is active.
    pub fn resolve_enforcement_path(cap: &Capability) -> EnforcementPath {
        match cap {
            Capability::FsRead { .. } | Capability::FsWrite { .. } => {
                // Landlock LSM is supported on Linux kernels >= 5.13
                #[cfg(target_os = "linux")]
                {
                    EnforcementPath::Landlock
                }
                #[cfg(not(target_os = "linux"))]
                {
                    EnforcementPath::Unsupported {
                        reason: "Landlock filesystem containment only supported on Linux".to_string(),
                    }
                }
            }
            Capability::ProcessExec { .. } | Capability::PrivilegeChange { .. } => {
                #[cfg(target_os = "linux")]
                {
                    EnforcementPath::Seccomp
                }
                #[cfg(not(target_os = "linux"))]
                {
                    EnforcementPath::Unsupported {
                        reason: "Seccomp-BPF filter only supported on Linux".to_string(),
                    }
                }
            }
            Capability::NetConnect { .. } => {
                #[cfg(target_os = "linux")]
                {
                    EnforcementPath::EbpfCgroupSocket
                }
                #[cfg(not(target_os = "linux"))]
                {
                    EnforcementPath::Unsupported {
                        reason: "eBPF cgroup socket hooks only supported on Linux".to_string(),
                    }
                }
            }
            Capability::ResourceLimit { .. } => {
                #[cfg(target_os = "linux")]
                {
                    EnforcementPath::CgroupsV2
                }
                #[cfg(not(target_os = "linux"))]
                {
                    EnforcementPath::Unsupported {
                        reason: "cgroups v2 resource controller only supported on Linux".to_string(),
                    }
                }
            }
            Capability::CredentialUse { .. } => {
                EnforcementPath::CredentialIntelligence
            }
            Capability::ContainerManage { .. } => {
                if Path::new("/var/run/docker.sock").exists() {
                    EnforcementPath::Unsupported {
                        reason: "Container runtime socket exists but container confinement daemon hook not configured".to_string(),
                    }
                } else {
                    EnforcementPath::Unsupported {
                        reason: "Docker container socket /var/run/docker.sock not present on host".to_string(),
                    }
                }
            }
            Capability::DbAccess { .. } | Capability::ApiAccess { .. } | Capability::DeploymentOp { .. } => {
                EnforcementPath::Unsupported {
                    reason: "Application-layer capability requires upstream API gateway or proxy enforcement".to_string(),
                }
            }
            Capability::Delegation { .. } => {
                EnforcementPath::Unsupported {
                    reason: "Delegation capability enforced by control-plane policy authority, not kernel primitive".to_string(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsupported_enforcement_detected_for_container_manage() {
        let cap = Capability::ContainerManage {
            action: "start".to_string(),
            image_pattern: Some("evil:*".to_string()),
        };

        let path = EnforcementBridge::resolve_enforcement_path(&cap);
        match path {
            EnforcementPath::Unsupported { reason } => {
                assert!(!reason.is_empty(), "Unsupported enforcement must provide explicit reason");
            }
            _ => panic!("Expected Unsupported enforcement path for container management on default host"),
        }
    }
}
