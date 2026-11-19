# BADGER Incident Response & Containment Playbook

## 1. Response Playbook Overview

When an autonomous agent workload attempts unauthorized operations (such as sensitive file exfiltration, unauthorized network egress, or credential harvesting), the **Autonomous Containment Subsystem** coordinates an immediate, verifiable response.

---

## 2. Containment Actions Matrix

| Action | Kernel Mechanism | Expected Operating System Verification |
|---|---|---|
| `SuspendWorkload` | `cgroup.freeze = 1` | `cgroup.freeze` reads `1`, state reads `frozen` |
| `FreezeCgroup` | Direct freezer controller write | Processes frozen in D-state; 0 CPU cycles |
| `KillProcess` | `SIGTERM` followed by `SIGKILL` | `kill(pid, 0)` returns `ESRCH` (No such process) |
| `IsolateNetwork` | BPF cgroup socket connect override | All outbound connect attempts return `EPERM` |
| `RevokeCredentials`| SPIFFE / SPIRE CRL publication | SVID invalidated across all gateways |
| `RestrictPolicy` | Atomic downgrade to `DROP-ALL` | Policy version clamped |
| `QuarantineWorkload`| Combined freeze, net isolate & revoke | Total sandbox isolation |

---

## 3. Controlled Operator Recovery Protocol

Recovery from containment is intentionally non-autonomous and requires explicit human operator sign-off:

1. **Root Cause Analysis**: Inspect threat findings (`/api/v1/findings`) and runtime telemetry events (`/api/v1/events`).
2. **Finding Acknowledgment**: The operator must explicitly toggle `findings_acknowledged = true`.
3. **Baseline Policy Selection**: Specify the known-good policy version.
4. **Execute Recovery**: Call `POST /api/v1/containment/recover` with operator authorization token.
5. **OS Verification**: The subsystem resets network drop rules, unfreezes the cgroup (`cgroup.freeze = 0`), and records a digitally signed recovery audit entry.
