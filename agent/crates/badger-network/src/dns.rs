use crate::types::{NetworkAction, NetworkProtocol, NetworkRule};
use badger_common::{BadgerError, BadgerResult};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::{Arc, RwLock};

pub const CLOUD_METADATA_IPV4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

#[derive(Debug, Clone)]
pub struct ResolvedDestination {
    pub hostname: String,
    pub ipv4_addresses: Vec<Ipv4Addr>,
    pub ipv6_addresses: Vec<Ipv6Addr>,
    pub resolved_at: DateTime<Utc>,
    pub ttl_seconds: u64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DnsSecurityConfig {
    pub allow_localhost: bool,
    pub allow_private_networks: bool,
    pub block_cloud_metadata: bool,
    pub default_ttl_seconds: u64,
}

impl Default for DnsSecurityConfig {
    fn default() -> Self {
        Self {
            allow_localhost: false,
            allow_private_networks: false,
            block_cloud_metadata: true,
            default_ttl_seconds: 300,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsSecurityManager {
    config: DnsSecurityConfig,
    cache: Arc<RwLock<HashMap<String, ResolvedDestination>>>,
}

impl DnsSecurityManager {
    pub fn new(config: DnsSecurityConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Resolves a hostname with strict security filtering against DNS rebinding and metadata exfiltration
    pub fn resolve(&self, hostname: &str) -> BadgerResult<ResolvedDestination> {
        // 1. Check valid cached resolution
        let now = Utc::now();
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(hostname) {
                if now < cached.expires_at {
                    return Ok(cached.clone());
                }
            }
        }

        // 2. Perform system DNS resolution
        let socket_addr_str = format!("{}:80", hostname);
        let addrs = socket_addr_str.to_socket_addrs().map_err(|e| {
            BadgerError::Network(format!("DNS resolution failed for '{}': {}", hostname, e))
        })?;

        let mut v4_list = Vec::new();
        let mut v6_list = Vec::new();

        for sa in addrs {
            match sa.ip() {
                IpAddr::V4(v4) => {
                    self.validate_ipv4(hostname, v4)?;
                    if !v4_list.contains(&v4) {
                        v4_list.push(v4);
                    }
                }
                IpAddr::V6(v6) => {
                    self.validate_ipv6(hostname, v6)?;
                    if !v6_list.contains(&v6) {
                        v6_list.push(v6);
                    }
                }
            }
        }

        if v4_list.is_empty() && v6_list.is_empty() {
            return Err(BadgerError::Network(format!(
                "DNS resolution for '{}' returned no permitted IP addresses",
                hostname
            )));
        }

        let ttl = self.config.default_ttl_seconds;
        let expires_at = now + Duration::seconds(ttl as i64);

        let resolved = ResolvedDestination {
            hostname: hostname.to_string(),
            ipv4_addresses: v4_list,
            ipv6_addresses: v6_list,
            resolved_at: now,
            ttl_seconds: ttl,
            expires_at,
        };

        // Cache resolution
        let mut cache = self.cache.write().unwrap();
        cache.insert(hostname.to_string(), resolved.clone());

        Ok(resolved)
    }

    fn validate_ipv4(&self, hostname: &str, ip: Ipv4Addr) -> BadgerResult<()> {
        // Cloud metadata check
        if self.config.block_cloud_metadata && ip == CLOUD_METADATA_IPV4 {
            return Err(BadgerError::PolicyInvalid(format!(
                "SECURITY ALERT: Hostname '{}' resolved to cloud metadata IP 169.254.169.254 (Blocked)",
                hostname
            )));
        }

        // Localhost check (127.0.0.0/8)
        if !self.config.allow_localhost && ip.is_loopback() {
            return Err(BadgerError::PolicyInvalid(format!(
                "SECURITY ALERT: Hostname '{}' resolved to loopback IP {} (Blocked)",
                hostname, ip
            )));
        }

        // Private network RFC 1918 / link-local check
        if !self.config.allow_private_networks && (ip.is_private() || ip.is_link_local()) {
            return Err(BadgerError::PolicyInvalid(format!(
                "SECURITY ALERT (DNS Rebinding): Hostname '{}' resolved to private/internal IP {} (Blocked)",
                hostname, ip
            )));
        }

        Ok(())
    }

    fn validate_ipv6(&self, hostname: &str, ip: Ipv6Addr) -> BadgerResult<()> {
        // Cloud metadata IPv6 check: fd00:ec2::254
        let segments = ip.segments();
        if self.config.block_cloud_metadata
            && segments[0] == 0xfd00
            && segments[1] == 0x0ec2
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0
            && segments[6] == 0
            && segments[7] == 0x0254
        {
            return Err(BadgerError::PolicyInvalid(format!(
                "SECURITY ALERT: Hostname '{}' resolved to AWS cloud metadata IPv6 fd00:ec2::254 (Blocked)",
                hostname
            )));
        }

        // Localhost check (::1)
        if !self.config.allow_localhost && ip.is_loopback() {
            return Err(BadgerError::PolicyInvalid(format!(
                "SECURITY ALERT: Hostname '{}' resolved to IPv6 loopback ::1 (Blocked)",
                hostname
            )));
        }

        Ok(())
    }

    /// Converts a resolved hostname destination into discrete kernel CIDR rules
    pub fn to_network_rules(
        &self,
        dest: &ResolvedDestination,
        min_port: u16,
        max_port: u16,
        protocol: NetworkProtocol,
        action: NetworkAction,
        base_rule_id: u32,
    ) -> Vec<NetworkRule> {
        let mut rules = Vec::new();
        let mut rule_id = base_rule_id;

        for ip in &dest.ipv4_addresses {
            rules.push(NetworkRule {
                rule_id,
                direction: crate::types::NetworkDirection::Egress,
                destination_cidr: format!("{}/32", ip),
                min_port,
                max_port,
                protocol,
                action,
                priority: 100,
                description: format!("Resolved from '{}' (IPv4)", dest.hostname),
            });
            rule_id += 1;
        }

        for ip in &dest.ipv6_addresses {
            rules.push(NetworkRule {
                rule_id,
                direction: crate::types::NetworkDirection::Egress,
                destination_cidr: format!("{}/128", ip),
                min_port,
                max_port,
                protocol,
                action,
                priority: 100,
                description: format!("Resolved from '{}' (IPv6)", dest.hostname),
            });
            rule_id += 1;
        }

        rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_metadata_validation() {
        let mgr = DnsSecurityManager::new(DnsSecurityConfig::default());
        // 169.254.169.254 must be blocked
        assert!(mgr.validate_ipv4("imds.local", Ipv4Addr::new(169, 254, 169, 254)).is_err());
        // Normal public IP allowed
        assert!(mgr.validate_ipv4("example.com", Ipv4Addr::new(93, 184, 216, 34)).is_ok());
    }

    #[test]
    fn test_dns_rebinding_localhost_and_private_blocked() {
        let mgr = DnsSecurityManager::new(DnsSecurityConfig::default());
        // Localhost blocked
        assert!(mgr.validate_ipv4("malicious.com", Ipv4Addr::new(127, 0, 0, 1)).is_err());
        // Private network blocked
        assert!(mgr.validate_ipv4("internal.target", Ipv4Addr::new(192, 168, 1, 10)).is_err());
        assert!(mgr.validate_ipv4("internal.target", Ipv4Addr::new(10, 0, 0, 5)).is_err());
    }

    #[test]
    fn test_to_network_rules_translation() {
        let mgr = DnsSecurityManager::new(DnsSecurityConfig::default());
        let dest = ResolvedDestination {
            hostname: "api.service.com".to_string(),
            ipv4_addresses: vec![Ipv4Addr::new(104, 18, 20, 1), Ipv4Addr::new(104, 18, 21, 1)],
            ipv6_addresses: vec![],
            resolved_at: Utc::now(),
            ttl_seconds: 300,
            expires_at: Utc::now() + Duration::seconds(300),
        };

        let rules = mgr.to_network_rules(
            &dest,
            443,
            443,
            NetworkProtocol::Tcp,
            NetworkAction::Allow,
            1000,
        );

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].destination_cidr, "104.18.20.1/32");
        assert_eq!(rules[1].destination_cidr, "104.18.21.1/32");
        assert_eq!(rules[0].min_port, 443);
    }
}
