# BADGER Known Limitations & Threat Model Boundaries

**Release Target:** BADGER V1.0.1 Hardened Security Release  
**Last Updated:** 2026-11-18  
**Classification:** Definitive Operational & Architectural Boundaries  

---

## 1. Operating System & Kernel Dependencies

1. **Linux-Exclusive Kernel Primitives:**
   Core isolation primitives (Namespaces, cgroups v2, Seccomp-BPF, Landlock LSM) require a Linux kernel >= 5.13. On non-Linux hosts (such as native Windows or macOS), the agent operates in degraded user-space execution mode and emits explicit degradation warnings.
2. **Namespace Creation Privileges:**
   Creating independent namespaces (`CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWNET`) requires `CAP_SYS_ADMIN` or user namespace support (`CLONE_NEWUSER`). In environments where user namespaces are disabled by kernel sysctl (`kernel.unprivileged_userns_clone = 0`), execution must run as root or setuid.
3. **cgroups v2 Hierarchy Delegation:**
   Creating and managing workload groups in `/sys/fs/cgroup/badger` requires initial administrative delegation or root permission to initialize controllers (`cgroup.subtree_control`).

---

## 2. Filesystem & Landlock LSM Invariants

1. **Subtree Permission Hierarchy (SEC-001):**
   Landlock LSM is inherently hierarchical. Granting read access to a parent directory (e.g. `/` or `/etc`) grants read access to all child files. Denied subpaths must be masked using mount namespaces (bind-mounting `/dev/null` or mode 0000 tmpfs over the path) before `landlock_restrict_self()`.
2. **Pre-Existing Host Symlinks:**
   Mount masking relies on path canonicalization at sandbox configuration time. If a malicious process creates dynamic symlinks to unmasked external files inside an allowed writable directory, access is governed strictly by the Landlock rules applied to the parent directory.
3. **Privileged Host Attacker Boundary:**
   Landlock and Seccomp cannot protect against a privileged host attacker (`CAP_SYS_ADMIN` on host). BADGER enforces containment *from the outside in*, preventing the unprivileged workload from escaping.

---

## 3. Network Isolation Invariants (SEC-007)

1. **All-or-Nothing Network Namespace Isolation:**
   When `isolate_network: true` is configured, BADGER unshares the network namespace (`CLONE_NEWNET`) without configuring loopback or veth pairs. All external and local network communication fails at the kernel socket boundary with `ENETUNREACH` (`Network is unreachable`).
2. **Granular Per-Destination/Port Egress Filtering (Phase 2 Implemented):**
   BADGER now enforces granular network egress boundaries at the operating system socket layer using eBPF `cgroup_sock_addr` hooks (`connect4`, `connect6`, `sendmsg4`, `sendmsg6`). Denied connections fail immediately with `EPERM` at the kernel boundary before any packet is transmitted.
3. **Rule Capacity & Dynamic Sizing:**
   In-kernel rule arrays currently accommodate up to 64 active CIDR/port rules per workload cgroup. Workloads requiring complex multi-thousand endpoint policies must summarize targets using broader CIDR ranges or await future LPM trie expansion.
4. **Hostname Resolution Dependency:**
   In-kernel eBPF socket filters inspect numerical IP addresses (layer 3) and ports (layer 4). Domain name intents are translated into verified IP CIDRs by `DnsSecurityManager` with TTL tracking and DNS rebinding protections. Hostname rules cannot be loaded into the kernel without DNS resolution.

---

## 4. Telemetry Visibility & eBPF Boundaries

1. **Native eBPF Status (Phase 1 Implemented):**
   BADGER now features an operational native eBPF runtime intelligence engine using Aya on Linux kernels >= 5.8 with BTF support. The sensor attaches to six kernel tracepoints (`sched_process_exec`, `sched_process_exit`, `sched_process_fork`, `sys_enter_connect`, `sys_enter_openat`, `sys_enter_setuid`) and streams events through a 256 KB bounded BPF ring buffer.
2. **Fallback to Procfs on Older Kernels:**
   When running on systems lacking BPF ring buffer support (Linux < 5.8) or without BTF (`/sys/kernel/btf/vmlinux`), the sensor falls back gracefully to `/proc/{pid}` monitoring and reports `Degraded` status instead of `Protected`.
3. **Passive Observation vs. In-Kernel Blocking:**
   The Phase 1 eBPF engine observes and reports kernel telemetry. Network connect filtering and syscall logging are passive observation probes; actual runtime containment is actively enforced by Landlock LSM, Seccomp-BPF filters, and network namespaces. Future phases will introduce LSM-BPF and `cgroup/sock_addr` programs for active kernel-level blocking.
4. **Ring Buffer Overflow Under Heavy Burst:**
   Under extreme event generation bursts exceeding userspace consumption rates, the kernel ring buffer will drop events. The sensor tracks these dropped events and transitions health to `Degraded` if the loss count exceeds tolerance thresholds.

---

## 5. Control Plane Security Boundaries (SEC-002, SEC-008)

1. **Token Lifetime and Revocation:**
   Tokens are validated in-memory by `TokenManager`. In a multi-node distributed control plane deployment, token revocation requires an external shared store (e.g., Redis or database) to invalidate tokens across nodes.
2. **Body Size Limits:**
   Control plane endpoints enforce a 1MB limit (`http.MaxBytesReader`) to prevent memory exhaustion attacks. Workloads submitting bulk telemetry batches must batch events within this boundary.
3. **Workload Ownership Binding:**
   Event ingestion strictly validates that the target `WorkloadID` belongs to the authenticated tenant. Telemetry for unknown or cross-tenant workloads is rejected with `403 Forbidden`.

---

## 6. Performance Benchmarks Reality

1. **In-Memory Microbenchmarks vs. Distributed Pipeline:**
   The reported throughput metric of 862,958 events/second measures in-memory Rust rule evaluation against an already allocated struct in CPU L1/L2 cache. It does not measure end-to-end pipeline throughput, operating system event capture, network transport, or database commits.
2. **Expected Distributed Throughput:**
   When ingesting telemetry over HTTP/JSON with Bearer token authentication and HMAC verification, single-thread control plane throughput is approximately 25,000 – 45,000 requests/second.

---

## 7. Capability Governance & Containment Boundaries (Phase 4 & Phase 5)

1. **Unsupported In-Sandbox Capabilities:**
   Certain capabilities (such as `ContainerManage` or direct `PrivilegeChange`) cannot be enforced by the unprivileged in-sandbox Landlock/Seccomp layer. The capability resolver explicitly marks these as `Unsupported` rather than fabricating success.
2. **Human-in-the-Loop Operator Recovery:**
   Controlled recovery intentionally cannot be performed autonomously by an agent. An authenticated human operator with `containment:recover` RBAC permissions must review the incident and sign off on recovery.
3. **Cgroup V2 Migration Delays:**
   Under extreme CPU contention, cgroup freezer transitions (`cgroup.freeze = 1`) may take up to a few milliseconds while kernel threads exit interruptible states before reaching `frozen`.
4. **Keyed HMAC-SHA256 Fingerprinting:**
   HMAC-SHA256 fingerprints ensure raw secrets are never persisted or exposed. However, rotated credentials generate new fingerprints; downstream identity graph correlation depends on connector re-discovery.
