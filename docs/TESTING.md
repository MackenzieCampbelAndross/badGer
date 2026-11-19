# BADGER Testing & Verification Guide

---

## 1. Test Architecture

BADGER employs three tiers of automated verification:
1. **Unit Testing:** In-memory validation of individual engines (hash chaining, signature verification, policy specificity, drift detection, finding generation).
2. **Adversarial Security Scenarios (A through H):** End-to-end attacks executed against real Linux kernel primitives to confirm that detection, enforcement, audit logging, and containment succeed.
3. **Performance Benchmarks:** Empirical latency and throughput measurement under synthetic load.

---

## 2. Adversarial Scenarios Matrix

| Scenario | Objective | Enforcement Layer | Expected Outcome |
|---|---|---|---|
| **Scenario A** | Read protected `/etc/shadow` | Landlock LSM / VFS | Access denied (`EACCES`/`EPERM`), finding `DET-FS-001` generated |
| **Scenario B** | Outbound connection to prohibited external IP | Network Namespace isolation | Network unreachable, finding `DET-NET-002` generated |
| **Scenario C** | Execute prohibited `/bin/nc` | Policy Engine / Exec hook | Execution denied, finding `DET-PROC-003` generated |
| **Scenario D** | Launch permitted `/usr/bin/python3` child | Telemetry Sensor | Process monitored, event attributed to SPIFFE workload identity |
| **Scenario E** | Forbidden `SYS_bpf` system call | Seccomp-BPF filter | Syscall blocked, workload suspended via `cgroup.freeze` |
| **Scenario F** | Workload isolation initialization | Namespaces + cgroups v2 | Isolated mount, pid, net, ipc, uts trees verified |
| **Scenario G** | Sensor failure simulation | Telemetry State Machine | Reports `Unprotected`/`Degraded` state, never claims `Protected` |
| **Scenario H** | Malformed policy update | Cryptographic verifier | Tampered signature rejected, active policy preserved |

---

## 3. Running the Verification Suite

```bash
# Execute complete adversarial suite
cargo run -p badger-agent -- adversarial

# Execute individual scenario (e.g. Scenario A)
cargo run -p badger-agent -- adversarial --scenario A
```
