# BADGER Phase 2: Granular Network Security & Egress Engine Architecture

**Status:** Operational / Linux Kernel Verified  
**Subsystem Crate:** `badger-network`  
**Kernel Mechanism:** eBPF `cgroup_sock_addr` (`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`)  
**Attach Points:** `cgroup/connect4`, `cgroup/connect6`, `cgroup/sendmsg4`, `cgroup/sendmsg6`  
**Target Kernel:** Linux >= 5.8 (Verified on Linux 6.6.87.2-microsoft-standard-WSL2)

---

## 1. Architectural Mission & Invariants

Autonomous agents interacting with external APIs, database drivers, and MCP tool servers require strict, destination-specific network boundaries. Traditional host firewalls (e.g. host-wide iptables) lack process-level container granularity without heavyweight routing and virtual ethernet pairs (`veth`).

BADGER Phase 2 implements in-kernel socket address filtering directly attached to workload cgroup v2 directories (`/sys/fs/cgroup/badger/<workload_id>`).

### Non-Negotiable Enforcement Principles
1. **Kernel Boundary Failure:** Denied connections must actively fail at the operating system socket layer with `EPERM` (`Operation not permitted`). Connections are never permitted and merely flagged later.
2. **Zero-Packet Transmission:** Filtering executes during `connect()` or `sendto()`, before any TCP SYN packet or UDP datagram is constructed or routed.
3. **Per-Workload Granularity:** BPF programs attach to specific cgroups, ensuring policies apply strictly to the target workload without impacting host daemons or sibling workloads.
4. **Atomic In-Memory Updates:** Policy changes update in-kernel BPF maps in-place without process interruption, socket drops, or workload restarts.
5. **Mandatory Cloud Metadata Shield:** `169.254.169.254` (IPv4) and `fd00:ec2::254` (IPv6) are blocked by default to prevent token and credential theft from cloud instance metadata services (AWS IMDS, GCP metadata, Azure IMDS).

```
+----------------------------------------------------------------------------------------------------+
|                                    WORKLOAD EXECUTION (cgroup v2)                                  |
|                                                                                                    |
|   Autonomous Agent / Subprocess / MCP Server                                                       |
|        |                                                                                           |
|        | 1. socket.connect("10.20.1.5:443") / sendto("1.1.1.1:53")                                |
|        v                                                                                           |
+--------|-------------------------------------------------------------------------------------------+
         |                                                                                           
+--------v-------------------------------------------------------------------------------------------+
|                                    LINUX KERNEL eBPF HOOKS                                         |
|                                                                                                    |
|   +--------------------------------------------------------------------------------------------+   |
|   |  cgroup/connect4  |  cgroup/connect6  |  cgroup/sendmsg4  |  cgroup/sendmsg6               |   |
|   +--------------------------------------------------------------------------------------------+   |
|        |                                                                                           |
|        | Inspect struct bpf_sock_addr (dip, dport, protocol)                                      |
|        v                                                                                           |
|   +--------------------+     +--------------------+     +-----------------------------------+      |
|   |    config_map      |     |     rules4_map     |     |            rules6_map             |      |
|   | (default_action,   |     | (64 CIDR rules,    |     | (64 IPv6 CIDR rules,              |      |
|   |  block_metadata)   |     |  min/max port)     |     |  min/max port)                    |      |
|   +--------------------+     +--------------------+     +-----------------------------------+      |
|        |                                                                                           |
|        +---- Match: ALLOW ---> return 1;  (TCP SYN emitted / Socket proceeds)                      |
|        |                                                                                           |
|        +---- Match: DENY  ---> return 0;  (Kernel returns EPERM immediately)                       |
|        |                                                                                           |
|        v Emit decision to ring buffer                                                              |
|   +-----------------------+     +-----------------------+                                          |
|   |   net_events_ringbuf  |     |       stats_map       | (total, allowed, denied counters)        |
|   +-----------------------+     +-----------------------+                                          |
+------------|---------------------------------------------------------------------------------------+
             |                                                                                       
+------------v---------------------------------------------------------------------------------------+
|                               BADGER USERSPACE AGENT & CONTROL PLANE                               |
|                                                                                                    |
|   +-----------------------+     +-----------------------+     +--------------------------------+   |
|   |  NetworkEnforcer      | <-> |  NetworkPolicyEngine  | <-> |  Control Plane & Operator UI   |   |
|   | (Ring buffer reader,  |     | (HMAC-SHA256, version |     | (Real-time telemetry table,    |   |
|   |  map synchronizer)    |     |  stack, offline cache)|     |  policy deploy & rollback)     |   |
|   +-----------------------+     +-----------------------+     +--------------------------------+   |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Kernel Enforcement Subsystem Evaluation

We evaluated multiple operating system network isolation primitives:

| Enforcement Mechanism | Boundary Layer | Granularity | Performance | Verdict |
|---|---|---|---|---|
| **`cgroup/connect4` + `cgroup/connect6` (Chosen)** | Socket syscall entry (`connect`, `sendmsg`) | Per-workload cgroup, IP CIDR, Port range, Protocol | Ultra-fast (< 70µs decision latency) | **Selected Primary Mechanism** |
| `nftables` / `iptables` | Netfilter packet routing | Host-wide or network namespace | Fast, but requires veth pair routing & NAT overhead | Suboptimal for single-host agent sandboxes |
| Network Namespaces (`CLONE_NEWNET`) | Interface layer | Coarse (all-or-nothing without veth) | Zero latency (sockets fail with `ENETUNREACH`) | **Retained for full network isolation mode** |
| Userspace SOCKS5 / HTTP Proxy | Application layer | Hostname & URL path | Slow (context switches, TLS termination, bypassable) | Inadequate for adversarial security |

---

## 3. Subsystem Components in `badger-network`

The `badger-network` crate is organized into clean, single-responsibility modules:

- [`bpf/badger_network.bpf.c`](file:///d:/Mac/project/badger/agent/crates/badger-network/bpf/badger_network.bpf.c): In-kernel C source containing `cgroup/connect4`, `cgroup/connect6`, `cgroup/sendmsg4`, `cgroup/sendmsg6` and map definitions.
- [`bpf_types.rs`](file:///d:/Mac/project/badger/agent/crates/badger-network/src/bpf_types.rs): Exact memory representations (`#[repr(C)]`) of BPF structs, `Pod` trait implementations, and CIDR parsing logic.
- [`policy.rs`](file:///d:/Mac/project/badger/agent/crates/badger-network/src/policy.rs): `NetworkPolicyEngine` managing HMAC-SHA256 policy validation, monotonic version enforcement, safe rollback stacks, and offline disk caching.
- [`enforcer.rs`](file:///d:/Mac/project/badger/agent/crates/badger-network/src/enforcer.rs): `NetworkEnforcer` attaching eBPF programs via Aya to target cgroup directories, managing atomic map synchronization, and polling the ring buffer.
- [`dns.rs`](file:///d:/Mac/project/badger/agent/crates/badger-network/src/dns.rs): `DnsSecurityManager` performing hostname-to-IP resolution with protection against DNS rebinding and cloud metadata exfiltration.
- [`telemetry.rs`](file:///d:/Mac/project/badger/agent/crates/badger-network/src/telemetry.rs): Thread-safe circular buffer and statistics registry.
