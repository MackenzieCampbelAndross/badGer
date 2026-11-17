# BADGER Security Model

---

## 1. Zero Trust Architecture for Autonomous Identities

BADGER assumes that **all workloads, regardless of their origin, have the potential to behave adversarially**. Security enforcement is never delegated to the agent runtime, prompt system prompt, or language model.

### Key Pillars
1. **Host-Enforced Immutability:** The agent cannot alter its own cgroup, cannot unblock seccomp syscalls, and cannot override Landlock VFS rules once `landlock_restrict_self()` is invoked.
2. **Deterministic Kernel Enforcement:** All blocking happens at the Linux kernel boundary before the syscall completes.
3. **Defense in Depth:** Even if one layer fails (e.g., if an agent finds a loophole in a filesystem path), secondary layers (seccomp, network namespace, cgroup limits) prevent lateral movement.

---

## 2. Sensor Health & Fail-Safe Semantics

A critical failure mode of security software is silent degradation. BADGER formalizes four distinct sensor states:

| State | Definition | System Behavior |
|---|---|---|
| **`Protected`** | Primary eBPF / tracepoint telemetry and all Linux kernel primitives are operational and verified. | Normal workload execution permitted. |
| **`Degraded`** | Kernel telemetry fallback active (e.g. procfs / audit socket). Full kernel visibility cannot be guaranteed. | Workloads execute with clear operational warnings visible in control plane. |
| **`Unprotected`** | Sensor is stopped, crashed, or detached. | Triggers critical finding `DET-INTEG-006`. Workload may be suspended. |
| **`Unknown`** | Workload registered but telemetry handshake not yet confirmed. | Staged execution only. |

The system **never claims `Protected` when primary guarantees cannot be verified**.

---

## 3. Cryptographic Verification & Audit Integrity

- **Policy Signatures:** Each policy contains a SHA-256 digest over its rules and valid timeframe using a control-plane signing key. Tampered or expired policies are rejected at load time.
- **Audit Hash Chaining:**
  $$H_0 = 0x00...00$$
  $$H_n = \text{SHA256}(ID_n \parallel Timestamp_n \parallel Actor_n \parallel Action_n \parallel Entity_n \parallel Details_n \parallel H_{n-1})$$
  Modifying any record $i < n$ breaks the signature chain for all records $k \ge i$.
- **No Raw Credentials:** Credential associations are indexed strictly by metadata and SHA-256 fingerprints. Raw API keys, JWTs, and passwords never enter memory stores or telemetry events.
