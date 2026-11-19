# BADGER Engine Design Specification

This document details the engineering specifications and implementation decisions for BADGER's six core engines.

---

## Engine 01: Identity Intelligence Engine (`badger-identity`)
- **Responsibilities:**
  - Workload registration and SPIFFE-compliant ID generation (`spiffe://badger.local/ns/{tenant}/workload/{id}`).
  - Principal normalization across human operators, AI agents, MCP servers, and service accounts.
  - Credential fingerprinting (SHA-256) and relationship mapping.
  - Identity drift detection: `detect_drift(workload_id, observed_tenant, observed_policy_version)`.
- **Key Invariants:**
  - Workload IDs are immutable.
  - Raw credentials are never stored.

---

## Engine 02: Execution Isolation Engine (`badger-sandbox`)
- **Linux Security Primitives:**
  - **Namespaces:** Unshares `CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWIPC`, `CLONE_NEWUTS`.
  - **cgroups v2:** Allocates subtrees in `/sys/fs/cgroup/badger/{id}` configuring `memory.max`, `pids.max`, `cpu.max`.
  - **Landlock LSM:** Syscalls `SYS_landlock_create_ruleset` (444), `SYS_landlock_add_rule` (445), and `SYS_landlock_restrict_self` (446).
  - **Seccomp-BPF:** Installs classic BPF filters enforcing `EPERM` or kill on high-risk system calls (`SYS_ptrace`, `SYS_bpf`, `SYS_mount`).
  - **Capabilities:** Drops dangerous capabilities including `CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`.

---

## Engine 03: Runtime Intelligence Engine (`badger-sensor`)
- **Dual Telemetry Architecture:**
  - Primary path: eBPF CO-RE tracepoints (`/sys/kernel/debug/tracing` and `/sys/kernel/btf/vmlinux`).
  - Fallback path: `/proc` procfs scanning and audit notifications.
- **Health State Machine:**
  - Transitions between `Protected`, `Degraded`, `Unprotected`, and `Unknown`. Emits `EventType::SensorStatusChange` on state shifts.

---

## Engine 04: Threat Detection Engine (`badger-threat`)
- **Detection Rules:**
  - `DET-FS-001`: Unauthorized Filesystem Access (blocked `openat`/`write`).
  - `DET-NET-002`: Unauthorized Network Connection (blocked socket egress).
  - `DET-PROC-003`: Prohibited Binary Execution (blocked tool invocation).
  - `DET-SYSCALL-005`: Forbidden System Call Blocked (blocked `SYS_bpf`/`SYS_ptrace`).
  - `DET-INTEG-006`: Sensor Telemetry Loss (sensor stopped or detached).
- **Finding Format:**
  - Every finding includes rule ID, 1.0 confidence, severity, evidence attributes, and recommended response.

---

## Engine 05: Capability Governance Engine (`badger-policy`)
- **Policy Invariants:**
  - Default deny for executables, filesystem paths, and network destinations.
  - Path specificity resolution (longest prefix match for nested rules).
  - Cryptographic signature validation with signing key.
  - Lifetime bounds checking (`valid_from_unix` and `valid_until_unix`).

---

## Engine 06: Autonomous Containment Engine (`badger-containment`)
- **Response Actions:**
  - `SuspendWorkload`: Sets `/sys/fs/cgroup/badger/{id}/cgroup.freeze = 1`.
  - `KillProcess`: Sends `SIGTERM` followed by `SIGKILL` and verifies termination via `kill(pid, 0) == ESRCH`.
  - `RevokeCredential`: Revokes workload credentials across identity store.
  - Every containment action produces a verifiable, tamper-evident `AuditRecord`.
