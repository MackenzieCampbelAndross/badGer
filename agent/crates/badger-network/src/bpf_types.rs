use crate::types::{NetworkAction, NetworkProtocol, NetworkRule};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const MAX_RULES: usize = 64;

pub const ACTION_DENY: u8 = 0;
pub const ACTION_ALLOW: u8 = 1;

pub const PROTO_ANY: u8 = 0;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const PROTO_TCP_U16: u16 = 6;
pub const PROTO_UDP_U16: u16 = 17;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct net_rule4_t {
    pub ip: u32,
    pub mask: u32,
    pub min_port: u16,
    pub max_port: u16,
    pub protocol: u8,
    pub action: u8,
    pub active: u8,
    pub pad: u8,
    pub priority: u32,
    pub rule_id: u32,
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for net_rule4_t {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct net_rule6_t {
    pub ip: [u32; 4],
    pub mask: [u32; 4],
    pub min_port: u16,
    pub max_port: u16,
    pub protocol: u8,
    pub action: u8,
    pub active: u8,
    pub pad: u8,
    pub priority: u32,
    pub rule_id: u32,
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for net_rule6_t {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct net_config_t {
    pub default_action: u32,
    pub rule_count4: u32,
    pub rule_count6: u32,
    pub block_cloud_metadata: u32,
    pub log_all_decisions: u32,
    pub policy_version: u32,
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for net_config_t {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct net_telemetry_event_t {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub family: u16,
    pub protocol: u16,
    pub dport: u16,
    pub action: u8,
    pub matched_rule: u8,
    pub rule_id: u32,
    pub dip4: u32,
    pub dip6: [u32; 4],
    pub comm: [u8; 16],
    pub pad: u32,
}

impl Default for net_telemetry_event_t {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            cgroup_id: 0,
            pid: 0,
            tgid: 0,
            uid: 0,
            family: 0,
            protocol: 0,
            dport: 0,
            action: 0,
            matched_rule: 0,
            rule_id: 0,
            dip4: 0,
            dip6: [0; 4],
            comm: [0; 16],
            pad: 0,
        }
    }
}

pub fn parse_ipv4_cidr(cidr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    let ip: Ipv4Addr = parts[0].trim().parse().ok()?;
    let prefix: u8 = if parts.len() > 1 {
        parts[1].trim().parse().ok()?
    } else {
        32
    };

    if prefix > 32 {
        return None;
    }

    let ip_bytes = ip.octets();
    let ip_u32 = u32::from_ne_bytes(ip_bytes);

    let mask_bytes = if prefix == 0 {
        [0, 0, 0, 0]
    } else {
        let mut b = [0u8; 4];
        let full_bytes = (prefix / 8) as usize;
        let rem_bits = prefix % 8;
        for i in 0..full_bytes {
            b[i] = 255;
        }
        if rem_bits > 0 && full_bytes < 4 {
            b[full_bytes] = !((1u8 << (8 - rem_bits)) - 1);
        }
        b
    };
    let mask_u32 = u32::from_ne_bytes(mask_bytes);

    Some((ip_u32, mask_u32))
}

pub fn parse_ipv6_cidr(cidr: &str) -> Option<([u32; 4], [u32; 4])> {
    let parts: Vec<&str> = cidr.split('/').collect();
    let ip: Ipv6Addr = parts[0].trim().parse().ok()?;
    let prefix: u8 = if parts.len() > 1 {
        parts[1].trim().parse().ok()?
    } else {
        128
    };

    if prefix > 128 {
        return None;
    }

    let octets = ip.octets();
    let mut ip_words = [0u32; 4];
    for i in 0..4 {
        let chunk: [u8; 4] = [
            octets[i * 4],
            octets[i * 4 + 1],
            octets[i * 4 + 2],
            octets[i * 4 + 3],
        ];
        ip_words[i] = u32::from_ne_bytes(chunk);
    }

    let mut mask_octets = [0u8; 16];
    let full_bytes = (prefix / 8) as usize;
    let rem_bits = prefix % 8;
    for i in 0..full_bytes.min(16) {
        mask_octets[i] = 255;
    }
    if rem_bits > 0 && full_bytes < 16 {
        mask_octets[full_bytes] = !((1u8 << (8 - rem_bits)) - 1);
    }

    let mut mask_words = [0u32; 4];
    for i in 0..4 {
        let chunk: [u8; 4] = [
            mask_octets[i * 4],
            mask_octets[i * 4 + 1],
            mask_octets[i * 4 + 2],
            mask_octets[i * 4 + 3],
        ];
        mask_words[i] = u32::from_ne_bytes(chunk);
    }

    Some((ip_words, mask_words))
}

pub fn rule_to_bpf4(rule: &NetworkRule) -> Option<net_rule4_t> {
    let (ip, mask) = parse_ipv4_cidr(&rule.destination_cidr)?;
    let proto = match rule.protocol {
        NetworkProtocol::Any => PROTO_ANY,
        NetworkProtocol::Tcp => PROTO_TCP,
        NetworkProtocol::Udp => PROTO_UDP,
    };
    let act = match rule.action {
        NetworkAction::Allow => ACTION_ALLOW,
        NetworkAction::Deny => ACTION_DENY,
    };

    Some(net_rule4_t {
        ip,
        mask,
        min_port: rule.min_port,
        max_port: rule.max_port,
        protocol: proto,
        action: act,
        active: 1,
        pad: 0,
        priority: rule.priority,
        rule_id: rule.rule_id,
    })
}

pub fn rule_to_bpf6(rule: &NetworkRule) -> Option<net_rule6_t> {
    let (ip, mask) = parse_ipv6_cidr(&rule.destination_cidr)?;
    let proto = match rule.protocol {
        NetworkProtocol::Any => PROTO_ANY,
        NetworkProtocol::Tcp => PROTO_TCP,
        NetworkProtocol::Udp => PROTO_UDP,
    };
    let act = match rule.action {
        NetworkAction::Allow => ACTION_ALLOW,
        NetworkAction::Deny => ACTION_DENY,
    };

    Some(net_rule6_t {
        ip,
        mask,
        min_port: rule.min_port,
        max_port: rule.max_port,
        protocol: proto,
        action: act,
        active: 1,
        pad: 0,
        priority: rule.priority,
        rule_id: rule.rule_id,
    })
}
