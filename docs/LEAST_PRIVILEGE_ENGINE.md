# Evidence-Based Least Privilege Intelligence Engine

## 1. Overview

Rather than requiring human operators to guess minimal permissions for complex autonomous workloads, BADGER provides an **Evidence-Based Least Privilege Engine** (`badger-policy::least_privilege`).

The engine continuously analyzes native eBPF tracepoint telemetry and LSM access events, correlates them with granted policy capabilities, and generates provably tighter policy definitions.

---

## 2. Policy Mining Workflow

1. **Telemetry Collection**: Capture all filesystem accesses (`sys_enter_openat`), process spawns (`sched_process_exec`), and outbound socket connects (`sys_enter_connect`).
2. **Access Clustering**: Consolidate individual file accesses into minimal directory trees (e.g. 50 reads in `/workspace/data/` become `FsRead(/workspace/data, recursive=true)`).
3. **Difference Calculation**:
   - `Overprivileged Capabilities`: Capabilities defined in the active policy that were never exercised during observation.
   - `Used Capabilities`: Capabilities actively exercised and validated.
   - `Denied / Blocked Operations`: Anomalous attempts outside policy bounds.
4. **Simulation & Diff Engine**:
   Before deploying a tightened policy, the engine simulates it against historical workload events, producing a clear diff:
   - `Newly Denied`: What will stop working.
   - `Newly Allowed`: What will be newly permitted.
   - `Unchanged`: What remains identical.
