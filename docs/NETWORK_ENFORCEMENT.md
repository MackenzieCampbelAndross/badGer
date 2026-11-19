# BADGER Kernel Network Enforcement & DNS Security Guide

## 1. Operating System Socket Enforcement Mechanics

Enforcement is implemented via the Linux kernel's `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program type:

1. **Attachment Point:**
   The programs attach to the workload's dedicated cgroup v2 directory:
   - `cgroup/connect4`: Intercepts `AF_INET` `connect()` calls.
   - `cgroup/connect6`: Intercepts `AF_INET6` `connect()` calls.
   - `cgroup/sendmsg4`: Intercepts unconnected `AF_INET` UDP datagram emissions.
   - `cgroup/sendmsg6`: Intercepts unconnected `AF_INET6` UDP datagram emissions.

2. **In-Kernel Evaluation Flow:**
   When an application inside the cgroup initiates a connection:
   - Kernel loads destination IP (`ctx->user_ip4` or `ctx->user_ip6`), destination port (`ctx->user_port`), and protocol (`ctx->protocol`).
   - Cloud metadata check: If `dip == 169.254.169.254` (or `fd00:ec2::254`), connection is immediately blocked with `return 0;`.
   - Sequential rule evaluation: Iterates through `rules4_map` or `rules6_map` in ascending priority order. If a rule matches on subnet mask, port range, and protocol:
     - If rule action is `ALLOW`: increments allowed counter in `stats_map` and returns `1`.
     - If rule action is `DENY`: increments denied counter, emits a telemetry event into `net_events_ringbuf`, and returns `0`.
   - Fallback: If no rule matches, evaluates `default_action` from `config_map`.

3. **Userspace Outcome:**
   - Returning `1` from BPF allows the kernel network stack to proceed with TCP handshake.
   - Returning `0` from BPF causes the `connect()` or `sendto()` syscall to immediately fail with `EPERM` (`Operation not permitted`). The socket is aborted before transmitting packets.

## 2. DNS Resolution vs. In-Kernel IP Enforcement

A critical security principle in BADGER is distinguishing between **hostname intent** and **kernel enforcement**:

- The Linux kernel BPF socket hook operates on numerical IP addresses (layer 3) and port numbers (layer 4). It has no visibility into application-level DNS hostnames.
- Trusting application-supplied hostnames at runtime introduces severe vulnerabilities:
  - **DNS Rebinding:** An attacker's domain (e.g. `evil.com`) initially resolves to a public IP to pass allowlist checks, then resolves to `127.0.0.1` or `169.254.169.254` to access internal services.
  - **Dynamic Multi-IP:** Large cloud services (e.g. `api.anthropic.com`) return different IPs across geographic clusters and rotation cycles.

### BADGER's DNS Security Architecture (`DnsSecurityManager`)
1. **Pre-Resolution Filtering:** Translates approved hostnames to verified IP sets using secure system resolvers.
2. **Rebinding Protection:** Rejects any hostname resolution that returns loopback (`127.0.0.0/8`, `::1`), RFC 1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or link-local ranges.
3. **Discrete Rule Generation:** Generates discrete `/32` (IPv4) or `/128` (IPv6) rules for each resolved address.
4. **TTL Expiration Management:** Caches resolutions based on DNS TTL. When a TTL expires, re-resolves and synchronizes updated IP entries with the kernel BPF maps.
