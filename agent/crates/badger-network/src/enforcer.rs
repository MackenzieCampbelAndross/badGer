use crate::bpf_types::{
    net_config_t, net_rule4_t, net_rule6_t, net_telemetry_event_t, rule_to_bpf4, rule_to_bpf6,
    ACTION_ALLOW, ACTION_DENY, AF_INET, MAX_RULES, PROTO_TCP_U16, PROTO_UDP_U16,
};
use crate::types::{
    NetworkAction, NetworkDecisionEvent, NetworkPolicy, NetworkStats,
};
use badger_common::{BadgerError, BadgerResult};
use chrono::Utc;
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tracing::{error, info};

pub const NETWORK_BPF_BYTECODE: &[u8] =
    include_bytes!("../bpf/badger_network.bpf.o");

pub struct NetworkEnforcer {
    workload_id: String,
    cgroup_path: PathBuf,
    is_running: Arc<AtomicBool>,
    broadcast_tx: broadcast::Sender<NetworkDecisionEvent>,
    #[cfg(target_os = "linux")]
    ebpf_holder: Arc<Mutex<Option<aya::Ebpf>>>,
    #[cfg(target_os = "linux")]
    cgroup_links: Arc<Mutex<Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLinkId>>>,
}

impl NetworkEnforcer {
    pub fn new(workload_id: &str, cgroup_path: PathBuf) -> Self {
        let (broadcast_tx, _) = broadcast::channel(1024);
        Self {
            workload_id: workload_id.to_string(),
            cgroup_path,
            is_running: Arc::new(AtomicBool::new(false)),
            broadcast_tx,
            #[cfg(target_os = "linux")]
            ebpf_holder: Arc::new(Mutex::new(None)),
            #[cfg(target_os = "linux")]
            cgroup_links: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NetworkDecisionEvent> {
        self.broadcast_tx.subscribe()
    }

    pub fn is_active(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Attaches in-kernel cgroup socket address programs and programs the policy maps
    #[cfg(target_os = "linux")]
    pub fn attach(&self, policy: &NetworkPolicy) -> BadgerResult<()> {
        if self.is_running.load(Ordering::SeqCst) {
            return self.update_policy(policy);
        }

        if !self.cgroup_path.exists() {
            return Err(BadgerError::Network(format!(
                "Workload cgroup directory does not exist: {}",
                self.cgroup_path.display()
            )));
        }

        let cgroup_file = File::open(&self.cgroup_path).map_err(|e| {
            BadgerError::Network(format!(
                "Failed to open cgroup file at '{}': {}",
                self.cgroup_path.display(),
                e
            ))
        })?;

        // Re-align embedded BPF bytecode into pointer-aligned Vec<u8>
        let aligned_bytecode = NETWORK_BPF_BYTECODE.to_vec();
        let mut ebpf = aya::Ebpf::load(&aligned_bytecode).map_err(|e| {
            BadgerError::Network(format!("Failed to parse eBPF network ELF bytecode: {}", e))
        })?;

        // 1. Attach cgroup/connect4
        let mut links = Vec::new();
        {
            use aya::programs::cgroup_sock_addr::CgroupSockAddr;
            use aya::programs::CgroupAttachMode;
            let prog_connect4: &mut CgroupSockAddr = ebpf
                .program_mut("badger_cgroup_connect4")
                .ok_or_else(|| {
                    BadgerError::Network("Program 'badger_cgroup_connect4' not found".to_string())
                })?
                .try_into()
                .map_err(|e| {
                    BadgerError::Network(format!("Failed to cast badger_cgroup_connect4: {}", e))
                })?;
            prog_connect4.load().map_err(|e| {
                BadgerError::Network(format!("Failed to load badger_cgroup_connect4: {}", e))
            })?;
            let link_id = prog_connect4
                .attach(&cgroup_file, CgroupAttachMode::Single)
                .map_err(|e| {
                    BadgerError::Network(format!(
                        "Failed to attach badger_cgroup_connect4 to cgroup: {}",
                        e
                    ))
                })?;
            links.push(link_id);
            info!("eBPF cgroup_connect4 attached to cgroup: {}", self.cgroup_path.display());
        }

        // 2. Attach cgroup/connect6
        {
            use aya::programs::cgroup_sock_addr::CgroupSockAddr;
            use aya::programs::CgroupAttachMode;
            let prog_connect6: &mut CgroupSockAddr = ebpf
                .program_mut("badger_cgroup_connect6")
                .ok_or_else(|| {
                    BadgerError::Network("Program 'badger_cgroup_connect6' not found".to_string())
                })?
                .try_into()
                .map_err(|e| {
                    BadgerError::Network(format!("Failed to cast badger_cgroup_connect6: {}", e))
                })?;
            prog_connect6.load().map_err(|e| {
                BadgerError::Network(format!("Failed to load badger_cgroup_connect6: {}", e))
            })?;
            let link_id = prog_connect6
                .attach(&cgroup_file, CgroupAttachMode::Single)
                .map_err(|e| {
                    BadgerError::Network(format!(
                        "Failed to attach badger_cgroup_connect6 to cgroup: {}",
                        e
                    ))
                })?;
            links.push(link_id);
            info!("eBPF cgroup_connect6 attached to cgroup: {}", self.cgroup_path.display());
        }

        // 3. Attach cgroup/sendmsg4 (UDP)
        {
            use aya::programs::cgroup_sock_addr::CgroupSockAddr;
            use aya::programs::CgroupAttachMode;
            let prog_sendmsg4: &mut CgroupSockAddr = ebpf
                .program_mut("badger_cgroup_sendmsg4")
                .ok_or_else(|| {
                    BadgerError::Network("Program 'badger_cgroup_sendmsg4' not found".to_string())
                })?
                .try_into()
                .map_err(|e| {
                    BadgerError::Network(format!("Failed to cast badger_cgroup_sendmsg4: {}", e))
                })?;
            prog_sendmsg4.load().map_err(|e| {
                BadgerError::Network(format!("Failed to load badger_cgroup_sendmsg4: {}", e))
            })?;
            let link_id = prog_sendmsg4
                .attach(&cgroup_file, CgroupAttachMode::Single)
                .map_err(|e| {
                    BadgerError::Network(format!(
                        "Failed to attach badger_cgroup_sendmsg4 to cgroup: {}",
                        e
                    ))
                })?;
            links.push(link_id);
            info!("eBPF cgroup_sendmsg4 attached to cgroup: {}", self.cgroup_path.display());
        }

        // 4. Attach cgroup/sendmsg6 (UDP)
        {
            use aya::programs::cgroup_sock_addr::CgroupSockAddr;
            use aya::programs::CgroupAttachMode;
            let prog_sendmsg6: &mut CgroupSockAddr = ebpf
                .program_mut("badger_cgroup_sendmsg6")
                .ok_or_else(|| {
                    BadgerError::Network("Program 'badger_cgroup_sendmsg6' not found".to_string())
                })?
                .try_into()
                .map_err(|e| {
                    BadgerError::Network(format!("Failed to cast badger_cgroup_sendmsg6: {}", e))
                })?;
            prog_sendmsg6.load().map_err(|e| {
                BadgerError::Network(format!("Failed to load badger_cgroup_sendmsg6: {}", e))
            })?;
            let link_id = prog_sendmsg6
                .attach(&cgroup_file, CgroupAttachMode::Single)
                .map_err(|e| {
                    BadgerError::Network(format!(
                        "Failed to attach badger_cgroup_sendmsg6 to cgroup: {}",
                        e
                    ))
                })?;
            links.push(link_id);
            info!("eBPF cgroup_sendmsg6 attached to cgroup: {}", self.cgroup_path.display());
        }

        // 5. Populate initial policy rules into BPF maps
        Self::apply_policy_to_maps(&mut ebpf, policy)?;

        // 6. Start asynchronous ring buffer reader
        let is_running = self.is_running.clone();
        is_running.store(true, Ordering::SeqCst);
        let broadcast_tx = self.broadcast_tx.clone();
        let workload_id = self.workload_id.clone();

        // Extract ring buffer map
        let ring_buf_map = ebpf.take_map("net_events_ringbuf").ok_or_else(|| {
            BadgerError::Network("Map 'net_events_ringbuf' not found in BPF object".to_string())
        })?;

        std::thread::spawn(move || {
            let mut ring_buf = match aya::maps::RingBuf::try_from(ring_buf_map) {
                Ok(rb) => rb,
                Err(e) => {
                    error!("Failed to initialize network RingBuf: {}", e);
                    return;
                }
            };

            info!("eBPF network ring buffer reader active for workload '{}'", workload_id);

            while is_running.load(Ordering::SeqCst) {
                let mut processed = 0;
                while let Some(item) = ring_buf.next() {
                    let data: &[u8] = &item;
                    if data.len() >= std::mem::size_of::<net_telemetry_event_t>() {
                        let event = unsafe {
                            std::ptr::read_unaligned(data.as_ptr() as *const net_telemetry_event_t)
                        };

                        let comm = String::from_utf8_lossy(&event.comm)
                            .trim_matches(char::from(0))
                            .to_string();

                        let dip_str = if event.family == AF_INET {
                            let octets = event.dip4.to_ne_bytes();
                            Ipv4Addr::from(octets).to_string()
                        } else {
                            let mut octets = [0u8; 16];
                            for i in 0..4 {
                                let chunk = event.dip6[i].to_ne_bytes();
                                octets[i * 4..(i + 1) * 4].copy_from_slice(&chunk);
                            }
                            Ipv6Addr::from(octets).to_string()
                        };

                        let proto_str = match event.protocol {
                            PROTO_TCP_U16 => "TCP",
                            PROTO_UDP_U16 => "UDP",
                            _ => "OTHER",
                        };

                        let action = if event.action == ACTION_ALLOW {
                            NetworkAction::Allow
                        } else {
                            NetworkAction::Deny
                        };

                        let decision_evt = NetworkDecisionEvent {
                            event_id: format!("net-evt-{}", uuid::Uuid::new_v4()),
                            timestamp_ns: event.timestamp_ns,
                            timestamp_utc: Utc::now(),
                            cgroup_id: event.cgroup_id,
                            pid: event.pid,
                            comm,
                            source_workload: workload_id.clone(),
                            family: if event.family == AF_INET { "IPv4" } else { "IPv6" }.to_string(),
                            protocol: proto_str.to_string(),
                            destination_ip: dip_str,
                            destination_port: event.dport,
                            action,
                            matched_rule_id: if event.matched_rule == 1 {
                                Some(event.rule_id)
                            } else {
                                None
                            },
                            reason: if event.matched_rule == 1 {
                                format!("Matched policy rule {}", event.rule_id)
                            } else {
                                "Default policy action".to_string()
                            },
                            probe_provenance: "cgroup_sock_addr".to_string(),
                        };

                        let _ = broadcast_tx.send(decision_evt);
                    }
                    processed += 1;
                    if processed >= 64 {
                        break;
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            info!("eBPF network ring buffer reader terminated for workload '{}'", workload_id);
        });

        *self.ebpf_holder.lock().unwrap() = Some(ebpf);
        *self.cgroup_links.lock().unwrap() = links;

        Ok(())
    }

    /// Atomically updates active network policy in the kernel BPF maps
    #[cfg(target_os = "linux")]
    pub fn update_policy(&self, policy: &NetworkPolicy) -> BadgerResult<()> {
        let mut holder = self.ebpf_holder.lock().unwrap();
        if let Some(ref mut ebpf) = *holder {
            Self::apply_policy_to_maps(ebpf, policy)?;
            info!(
                "Network policy for workload '{}' atomically updated to v{}",
                self.workload_id, policy.version
            );
            Ok(())
        } else {
            Err(BadgerError::Network(
                "Cannot update policy: network enforcer is not running".to_string(),
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn apply_policy_to_maps(ebpf: &mut aya::Ebpf, policy: &NetworkPolicy) -> BadgerResult<()> {
        use aya::maps::Array;

        // 1. Populate rules4_map
        let mut rules4_map = Array::try_from(ebpf.map_mut("rules4_map").ok_or_else(|| {
            BadgerError::Network("Map 'rules4_map' not found".to_string())
        })?)
        .map_err(|e| BadgerError::Network(format!("Failed to open rules4_map: {}", e)))?;

        let mut r4_count = 0u32;
        for r in &policy.rules {
            if let Some(bpf_r) = rule_to_bpf4(r) {
                if (r4_count as usize) < MAX_RULES {
                    rules4_map.set(r4_count, bpf_r, 0).map_err(|e| {
                        BadgerError::Network(format!("Failed to set rules4_map[{}]: {}", r4_count, e))
                    })?;
                    r4_count += 1;
                }
            }
        }
        // Invalidate remaining slots
        for i in r4_count..(MAX_RULES as u32) {
            let zero_rule = net_rule4_t::default();
            let _ = rules4_map.set(i, zero_rule, 0);
        }

        // 2. Populate rules6_map
        let mut rules6_map = Array::try_from(ebpf.map_mut("rules6_map").ok_or_else(|| {
            BadgerError::Network("Map 'rules6_map' not found".to_string())
        })?)
        .map_err(|e| BadgerError::Network(format!("Failed to open rules6_map: {}", e)))?;

        let mut r6_count = 0u32;
        for r in &policy.rules {
            if let Some(bpf_r) = rule_to_bpf6(r) {
                if (r6_count as usize) < MAX_RULES {
                    rules6_map.set(r6_count, bpf_r, 0).map_err(|e| {
                        BadgerError::Network(format!("Failed to set rules6_map[{}]: {}", r6_count, e))
                    })?;
                    r6_count += 1;
                }
            }
        }
        for i in r6_count..(MAX_RULES as u32) {
            let zero_rule = net_rule6_t::default();
            let _ = rules6_map.set(i, zero_rule, 0);
        }

        // 3. Populate config_map
        let mut config_map = Array::try_from(ebpf.map_mut("config_map").ok_or_else(|| {
            BadgerError::Network("Map 'config_map' not found".to_string())
        })?)
        .map_err(|e| BadgerError::Network(format!("Failed to open config_map: {}", e)))?;

        let cfg = net_config_t {
            default_action: if policy.default_action == NetworkAction::Allow {
                ACTION_ALLOW as u32
            } else {
                ACTION_DENY as u32
            },
            rule_count4: r4_count,
            rule_count6: r6_count,
            block_cloud_metadata: if policy.block_cloud_metadata { 1 } else { 0 },
            log_all_decisions: 1, // Full audit logging
            policy_version: policy.version,
        };

        config_map.set(0, cfg, 0).map_err(|e| {
            BadgerError::Network(format!("Failed to set config_map: {}", e))
        })?;

        Ok(())
    }

    /// Retrieves kernel-enforced connection statistics
    #[cfg(target_os = "linux")]
    pub fn get_stats(&self) -> NetworkStats {
        let mut holder = self.ebpf_holder.lock().unwrap();
        if let Some(ref mut ebpf) = *holder {
            use aya::maps::Array;
            if let Ok(stats_map) = Array::<_, u64>::try_from(ebpf.map_mut("stats_map").unwrap()) {
                let total = stats_map.get(&0, 0).unwrap_or(0);
                let allowed = stats_map.get(&1, 0).unwrap_or(0);
                let denied = stats_map.get(&2, 0).unwrap_or(0);
                return NetworkStats {
                    total_connections: total,
                    allowed_connections: allowed,
                    denied_connections: denied,
                    violations_count: denied,
                };
            }
        }
        NetworkStats::default()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn attach(&self, _policy: &NetworkPolicy) -> BadgerResult<()> {
        self.is_running.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn update_policy(&self, _policy: &NetworkPolicy) -> BadgerResult<()> {
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn get_stats(&self) -> NetworkStats {
        NetworkStats::default()
    }

    /// Stops the network enforcer and detaches BPF programs
    pub fn detach(&self) -> BadgerResult<()> {
        self.is_running.store(false, Ordering::SeqCst);
        #[cfg(target_os = "linux")]
        {
            let mut links = self.cgroup_links.lock().unwrap();
            links.clear();
            let mut holder = self.ebpf_holder.lock().unwrap();
            *holder = None;
        }
        info!("Network enforcer detached for workload '{}'", self.workload_id);
        Ok(())
    }
}

impl Drop for NetworkEnforcer {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}
