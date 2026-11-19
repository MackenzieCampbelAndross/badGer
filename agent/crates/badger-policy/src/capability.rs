use serde::{Deserialize, Serialize};

/// Strongly typed, extensible taxonomy of capabilities governed by BADGER.
/// Prevents reliance on flat, arbitrary string permissions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "spec")]
pub enum Capability {
    /// Read access to filesystem paths
    FsRead {
        path: String,
        recursive: bool,
    },
    /// Write or modify access to filesystem paths
    FsWrite {
        path: String,
        append_only: bool,
    },
    /// Execution of binaries and commands
    ProcessExec {
        binary: String,
        args_pattern: Option<String>,
    },
    /// Outbound or inbound network connectivity
    NetConnect {
        destination: String, // IP, CIDR, or domain
        min_port: u16,
        max_port: u16,
        protocol: String, // "tcp", "udp", "any"
    },
    /// Container runtime management (Docker, containerd)
    ContainerManage {
        action: String, // "create", "start", "stop", "exec"
        image_pattern: Option<String>,
    },
    /// Database query and schema access
    DbAccess {
        target: String,
        operations: Vec<String>, // "SELECT", "INSERT", "UPDATE", "DELETE", "ADMIN"
    },
    /// External or internal API invocation
    ApiAccess {
        endpoint: String,
        methods: Vec<String>, // "GET", "POST", "PUT", "DELETE"
    },
    /// Usage of cryptographic credentials or tokens
    CredentialUse {
        credential_type: String, // "ApiKey", "OAuthToken", "SpiffeX509Svid"
        scope: Vec<String>,
    },
    /// Infrastructure and application deployment operations
    DeploymentOp {
        target: String,
        action: String, // "deploy", "rollback", "scale"
    },
    /// Operating system privilege transitions
    PrivilegeChange {
        target_uid: u32,
        target_gid: u32,
    },
    /// Resource consumption limits (cgroups v2)
    ResourceLimit {
        cpu_max_pct: u32,
        memory_max_bytes: u64,
    },
    /// Capability delegation to another principal
    Delegation {
        target_principal: String,
        capabilities: Vec<Capability>,
        max_depth: u32,
    },
}

impl Capability {
    /// Returns the high-level category of the capability
    pub fn category(&self) -> &'static str {
        match self {
            Capability::FsRead { .. } => "filesystem:read",
            Capability::FsWrite { .. } => "filesystem:write",
            Capability::ProcessExec { .. } => "process:exec",
            Capability::NetConnect { .. } => "network:connect",
            Capability::ContainerManage { .. } => "container:manage",
            Capability::DbAccess { .. } => "database:access",
            Capability::ApiAccess { .. } => "api:access",
            Capability::CredentialUse { .. } => "credential:use",
            Capability::DeploymentOp { .. } => "deployment:op",
            Capability::PrivilegeChange { .. } => "privilege:change",
            Capability::ResourceLimit { .. } => "resource:limit",
            Capability::Delegation { .. } => "delegation",
        }
    }

    /// Evaluates whether `self` subsumes (is a superset of or covers) the `requested` capability
    pub fn subsumes(&self, requested: &Capability) -> bool {
        match (self, requested) {
            (
                Capability::FsRead { path: p1, recursive: r1 },
                Capability::FsRead { path: p2, .. },
            ) => {
                if *r1 {
                    p2.starts_with(p1) || p1 == "*"
                } else {
                    p1 == p2 || p1 == "*"
                }
            }
            (
                Capability::FsWrite { path: p1, append_only: a1 },
                Capability::FsWrite { path: p2, append_only: a2 },
            ) => {
                let path_match = p1 == "*" || p1 == p2 || p2.starts_with(p1);
                let append_ok = if *a1 { *a2 } else { true };
                path_match && append_ok
            }
            (
                Capability::ProcessExec { binary: b1, .. },
                Capability::ProcessExec { binary: b2, .. },
            ) => b1 == "*" || b1 == b2,
            (
                Capability::NetConnect { destination: d1, min_port: min1, max_port: max1, protocol: pr1 },
                Capability::NetConnect { destination: d2, min_port: min2, max_port: max2, protocol: pr2 },
            ) => {
                let dest_match = d1 == "*" || d1 == d2;
                let port_match = min2 >= min1 && max2 <= max1;
                let proto_match = pr1 == "any" || pr1 == pr2;
                dest_match && port_match && proto_match
            }
            (
                Capability::ContainerManage { action: a1, image_pattern: i1 },
                Capability::ContainerManage { action: a2, image_pattern: i2 },
            ) => {
                let act_match = a1 == "*" || a1 == a2;
                let img_match = match (i1, i2) {
                    (Some(pat1), Some(pat2)) => pat1 == "*" || pat1 == pat2,
                    (Some(_), None) => false,
                    (None, _) => true,
                };
                act_match && img_match
            }
            (
                Capability::DbAccess { target: t1, operations: op1 },
                Capability::DbAccess { target: t2, operations: op2 },
            ) => {
                let target_match = t1 == "*" || t1 == t2;
                let ops_match = op2.iter().all(|o| op1.contains(o) || op1.contains(&"*".to_string()));
                target_match && ops_match
            }
            (
                Capability::ApiAccess { endpoint: ep1, methods: m1 },
                Capability::ApiAccess { endpoint: ep2, methods: m2 },
            ) => {
                let ep_match = ep1 == "*" || ep2.starts_with(ep1);
                let methods_match = m2.iter().all(|m| m1.contains(m) || m1.contains(&"*".to_string()));
                ep_match && methods_match
            }
            (
                Capability::CredentialUse { credential_type: ct1, scope: s1 },
                Capability::CredentialUse { credential_type: ct2, scope: s2 },
            ) => {
                let type_match = ct1 == "*" || ct1 == ct2;
                let scope_match = s2.iter().all(|s| s1.contains(s) || s1.contains(&"*".to_string()));
                type_match && scope_match
            }
            (
                Capability::PrivilegeChange { target_uid: u1, target_gid: g1 },
                Capability::PrivilegeChange { target_uid: u2, target_gid: g2 },
            ) => u1 == u2 && g1 == g2,
            (
                Capability::ResourceLimit { cpu_max_pct: c1, memory_max_bytes: m1 },
                Capability::ResourceLimit { cpu_max_pct: c2, memory_max_bytes: m2 },
            ) => c2 <= c1 && m2 <= m1,
            (
                Capability::Delegation { target_principal: p1, max_depth: d1, .. },
                Capability::Delegation { target_principal: p2, max_depth: d2, .. },
            ) => (p1 == "*" || p1 == p2) && d2 <= d1,
            _ => false,
        }
    }

    /// Computes capability intersection for delegation governance.
    /// Ensures a delegatee receives AT MOST the capabilities already held by the delegator.
    pub fn intersect(&self, other: &Capability) -> Option<Capability> {
        if self.subsumes(other) {
            Some(other.clone())
        } else if other.subsumes(self) {
            Some(self.clone())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_subsumption() {
        let parent = Capability::FsRead {
            path: "/workspace".to_string(),
            recursive: true,
        };
        let child = Capability::FsRead {
            path: "/workspace/src/lib.rs".to_string(),
            recursive: false,
        };
        let outside = Capability::FsRead {
            path: "/etc/passwd".to_string(),
            recursive: false,
        };

        assert!(parent.subsumes(&child));
        assert!(!parent.subsumes(&outside));
    }

    #[test]
    fn test_network_subsumption_and_intersection() {
        let broad = Capability::NetConnect {
            destination: "10.0.0.0/8".to_string(),
            min_port: 80,
            max_port: 443,
            protocol: "tcp".to_string(),
        };
        let narrow = Capability::NetConnect {
            destination: "10.0.0.0/8".to_string(),
            min_port: 443,
            max_port: 443,
            protocol: "tcp".to_string(),
        };

        assert!(broad.subsumes(&narrow));
        assert!(!narrow.subsumes(&broad));

        let intersection = broad.intersect(&narrow);
        assert_eq!(intersection, Some(narrow));
    }
}
