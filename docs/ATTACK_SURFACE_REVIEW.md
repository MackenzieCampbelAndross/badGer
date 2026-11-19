# BADGER V1.0 — Attack Surface Review

**Auditor:** Principal Security Architect & Systems Engineer  
**Date:** 2026-11-18  
**Scope:** Host Boundary, Kernel Primitives, Control Plane API, and Telemetry Channels

---

## 1. Architectural Attack Surface Map

```text
               [ UNTRUSTED NETWORK / EXTERNAL OPERATORS ]
                                   │
                                   ▼ (Port 8080: HTTP/REST) - [UNAUTHENTICATED]
                        ┌──────────────────────┐
                        │ BADGER Control Plane │
                        └──────────┬───────────┘
                                   │ (Telemetry / Policy Distribution)
                                   ▼
                        ┌──────────────────────┐
                        │   BADGER Rust Host   │
                        │     Data Plane       │
                        └──────────┬───────────┘
               ════════════════════╪══════════════════════ [HOST PRIVILEGE BOUNDARY]
                                   ▼
             ┌───────────────────────────────────────────┐
             │       CONTAINED WORKLOAD SANDBOX          │
             │  ┌──────────────┐       ┌──────────────┐  │
             │  │ Landlock LSM │       │ Seccomp-BPF  │  │
             │  └──────┬───────┘       └──────┬───────┘  │
             │         │                      │          │
             │  ┌──────▼───────┐       ┌──────▼───────┐  │
             │  │  Namespaces  │       │  cgroups v2  │  │
             │  └──────────────┘       └──────────────┘  │
             │                                           │
             │       UNTRUSTED AUTONOMOUS AGENT /        │
             │            MCP TOOL PROCESS               │
             └───────────────────────────────────────────┘
```

---

## 2. Trust Boundaries & Privilege Levels

| Boundary | High Trust Side | Low Trust Side | Enforcement Mechanism | Assessment |
|---|---|---|---|---|
| **TB-01: Agent to Host Kernel** | Linux Host Kernel (ring 0) | Untrusted Agent Process (ring 3) | Landlock LSM, Seccomp-BPF, Namespaces, cgroups v2 | **BROKEN:** Subpath Landlock bypass allows reading sensitive host files; PID namespace leaks host `/proc`. |
| **TB-02: Agent to Control Plane** | Control Plane (Go) | Host Agent (Rust) | HTTP REST (`/api/v1/events`) | **BROKEN:** Completely unauthenticated; any network client can inject events. |
| **TB-03: Operator to Control Plane** | Control Plane (Go) | Web Frontend (`:3000`) | HTTP REST (`/api/v1/workloads`) | **BROKEN:** No authentication, wildcard CORS (`*`), zero tenant isolation. |
| **TB-04: Process Privilege Boundary** | Root / Host User | Sandboxed Workload | `PR_SET_NO_NEW_PRIVS`, Dropped Capabilities | **PASS:** Privilege escalation prevented by kernel prctl. |
| **TB-05: Audit Record Storage** | Tamper-Evident Chain | Local Logs / Process | SHA-256 Hash Chaining ($H_n$) | **PASS (Internal):** Cryptographically sound, though susceptible to API forgery. |

---

## 3. Boundary-by-Boundary Adversarial Breakdown

### Boundary 1: Linux Filesystem & VFS
- **Threat Vector:** Traversal outside allowlisted paths, symlink following, reading host secrets (`/etc/shadow`, `~/.ssh/id_rsa`, `/proc/kcore`).
- **Actual Enforcement:**
  - Landlock LSM is initialized with `handled_access_fs = 0x1fff`.
  - When a parent directory (e.g. `/etc`) is allowed with read access, Landlock's hierarchical model grants read access to all child paths.
  - Denied subpaths (`access: "none"`) are omitted from the ruleset, which fails to revoke inherited parent permissions.
- **Exposure:** Any sandboxed process that is granted read access to `/etc` can read `/etc/shadow`.

### Boundary 2: Process & Namespace Isolation
- **Threat Vector:** Inspecting neighboring host processes, sending signals (`kill -9`), exploiting ptrace on host binaries.
- **Actual Enforcement:**
  - `unshare(CLONE_NEWPID)` is called in the child pre-exec hook. Because the calling process is not forked again, it remains in the host PID namespace.
  - `/proc` is not unmounted or remounted.
- **Exposure:** The sandboxed workload can view all processes running on the machine (`/proc/[pid]/cmdline`, `/proc/[pid]/environ`).

### Boundary 3: Network Egress
- **Threat Vector:** C2 exfiltration, port scanning, lateral network exploitation.
- **Actual Enforcement:**
  - When `isolate_network` is true, `CLONE_NEWNET` is unshared. The process has no network interfaces except an unconfigured loopback (`lo`).
  - When `isolate_network` is false, the process shares the host network.
- **Exposure:** Granular policy rules (e.g., allow `127.0.0.1:8080`, deny `*`) are evaluated only in user-space policy structs; the kernel sandbox does not install iptables/nftables or eBPF socket filters.

### Boundary 4: Control Plane & Event Ingestion API
- **Threat Vector:** Attacker on local network or adjacent pod forging security events or stealing workload metadata.
- **Actual Enforcement:**
  - None. HTTP server binds to `0.0.0.0:8080` with no authentication middleware.
- **Exposure:** Complete compromise of detection and audit integrity.
