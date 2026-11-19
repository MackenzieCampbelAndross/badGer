use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAction {
    Allow,
    Deny,
}

impl Default for NetworkAction {
    fn default() -> Self {
        NetworkAction::Deny
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Any,
    Tcp,
    Udp,
}

impl Default for NetworkProtocol {
    fn default() -> Self {
        NetworkProtocol::Tcp
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDirection {
    Egress,
    Ingress,
}

impl Default for NetworkDirection {
    fn default() -> Self {
        NetworkDirection::Egress
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRule {
    pub rule_id: u32,
    #[serde(default)]
    pub direction: NetworkDirection,
    /// Destination IPv4/IPv6 CIDR (e.g., "10.20.0.0/16", "1.1.1.1/32", "::1/128")
    pub destination_cidr: String,
    pub min_port: u16,
    pub max_port: u16,
    #[serde(default)]
    pub protocol: NetworkProtocol,
    pub action: NetworkAction,
    /// Priority order: lower value = evaluated first
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub description: String,
}

impl NetworkRule {
    pub fn new_allow(rule_id: u32, cidr: &str, port: u16, protocol: NetworkProtocol) -> Self {
        Self {
            rule_id,
            direction: NetworkDirection::Egress,
            destination_cidr: cidr.to_string(),
            min_port: port,
            max_port: port,
            protocol,
            action: NetworkAction::Allow,
            priority: 100,
            description: format!("Allow {}:{} ({:?})", cidr, port, protocol),
        }
    }

    pub fn new_deny(rule_id: u32, cidr: &str, port: u16, protocol: NetworkProtocol) -> Self {
        Self {
            rule_id,
            direction: NetworkDirection::Egress,
            destination_cidr: cidr.to_string(),
            min_port: port,
            max_port: port,
            protocol,
            action: NetworkAction::Deny,
            priority: 10, // Higher precedence
            description: format!("Deny {}:{} ({:?})", cidr, port, protocol),
        }
    }

    pub fn new_allow_port_range(
        rule_id: u32,
        cidr: &str,
        min_port: u16,
        max_port: u16,
        protocol: NetworkProtocol,
        priority: u32,
    ) -> Self {
        Self {
            rule_id,
            direction: NetworkDirection::Egress,
            destination_cidr: cidr.to_string(),
            min_port,
            max_port,
            protocol,
            action: NetworkAction::Allow,
            priority,
            description: format!("Allow {}:{}-{} ({:?})", cidr, min_port, max_port, protocol),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub id: String,
    pub tenant_id: String,
    pub workload_id: String,
    pub version: u32,
    #[serde(default)]
    pub default_action: NetworkAction,
    #[serde(default = "default_true")]
    pub block_cloud_metadata: bool,
    #[serde(default)]
    pub rules: Vec<NetworkRule>,
    pub valid_from_unix: i64,
    pub valid_until_unix: i64,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub issuer: String,
}

fn default_true() -> bool {
    true
}

impl NetworkPolicy {
    pub fn is_expired(&self, current_unix_time: i64) -> bool {
        self.valid_until_unix > 0 && current_unix_time > self.valid_until_unix
    }

    pub fn is_valid_now(&self, current_unix_time: i64) -> bool {
        (self.valid_from_unix <= 0 || current_unix_time >= self.valid_from_unix)
            && (self.valid_until_unix <= 0 || current_unix_time <= self.valid_until_unix)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyBundle {
    pub bundle_id: String,
    pub tenant_id: String,
    pub policies: Vec<NetworkPolicy>,
    pub created_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_connections: u64,
    pub allowed_connections: u64,
    pub denied_connections: u64,
    pub violations_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDecisionEvent {
    pub event_id: String,
    pub timestamp_ns: u64,
    pub timestamp_utc: DateTime<Utc>,
    pub cgroup_id: u64,
    pub pid: u32,
    pub comm: String,
    pub source_workload: String,
    pub family: String,
    pub protocol: String,
    pub destination_ip: String,
    pub destination_port: u16,
    pub action: NetworkAction,
    pub matched_rule_id: Option<u32>,
    pub reason: String,
    pub probe_provenance: String,
}
