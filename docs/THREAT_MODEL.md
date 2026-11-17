# BADGER Threat Model

**Standard:** STRIDE & Mitre ATT&CK for Autonomous Systems  
**Scope:** Autonomous Agents, LLM Tool Integrations, Host Infrastructure

---

## 1. Threat Actors & Scenarios

| Threat Actor | Capabilities | Vector | Objective |
|---|---|---|---|
| **Compromised Agent** | Arbitrary code execution within workload context | Prompt injection, malicious tools | Host takeover, file exfiltration, lateral movement |
| **Rogue / Hallucinating Agent** | High API permissions, autonomous tooling loop | Model drift, logic bugs | Data destruction, infinite process spawning, resource exhaustion |
| **Malicious MCP Server** | Local socket/pipe communication, file inspection | Tool poisoning, deceptive schemas | Host privilege escalation, credential theft |
| **Insider / Untrusted Operator** | Unauthorized policy modification | Unauthenticated API updates | Weakening agent containment boundaries |

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing (Identity)
- **Threat:** An unauthenticated workload attempts to impersonate a privileged agent to inherit its permissions or access credentials.
- **Mitigation:** BADGER assigns cryptographically random, verifiable SPIFFE workload IDs. Principal-to-workload relationships are validated against tenant manifests. Any drift in tenant ID or policy version is flagged by `detect_drift()`.

### 2.2 Tampering (Integrity)
- **Threat:** An agent alters its local configuration, modifies system libraries, or tampers with the policy file.
- **Mitigation:**
  - Filesystem is restricted by Landlock LSM to read-only for system paths.
  - Policy files require cryptographic SHA-256 signatures; unsigned or tampered updates are rejected (verified in Scenario H).
  - Audit records use SHA-256 forward hash chaining, making log tampering immediately detectable.

### 2.3 Repudiation
- **Threat:** A compromised agent denies making an unauthorized outbound connection or executing a forbidden command.
- **Mitigation:** Every telemetry event and enforcement outcome is immutably logged with sensor provenance (`landlock-lsm`, `seccomp-bpf`, `exec-monitor`) and chained into the audit log.

### 2.4 Information Disclosure
- **Threat:** An agent reads sensitive host files (`/etc/shadow`, AWS/cloud credentials in `~/.aws`, SSH keys in `~/.ssh`).
- **Mitigation:** Landlock LSM enforces an allowlist model. All paths not explicitly permitted in `filesystem_rules` are denied with `EACCES` or `EPERM` at the kernel VFS layer (verified in Scenario A). Raw credentials are never stored in telemetry or databases.

### 2.5 Denial of Service (Resource Exhaustion)
- **Threat:** Fork bomb, memory leakage, or CPU pegging by an agent loop.
- **Mitigation:** cgroups v2 strictly caps `memory.max`, `pids.max` (preventing fork bombs), and `cpu.max` (quota and period enforcement).

### 2.6 Elevation of Privilege
- **Threat:** An agent executes `setuid`, calls `ptrace` on neighboring processes, mounts filesystems, or loads malicious eBPF programs.
- **Mitigation:**
  - `PR_SET_NO_NEW_PRIVS` prevents any suid/guid escalation.
  - Seccomp-BPF blocks `SYS_ptrace` (101), `SYS_bpf` (321), `SYS_mount` (165), `SYS_kexec_load` (246).
  - Dangerous capabilities (`CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`) are stripped.
