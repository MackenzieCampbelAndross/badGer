# BADGER Runtime Event Schema

---

## 1. Schema Definition

All runtime events emitted by data plane sensors conform to the following contract:

```json
{
  "event_id": "evt_d98031e",
  "timestamp_unix_nanos": 1731862500000000,
  "workload_id": "wkl_69b6f01e",
  "principal_id": "prn:tenant-1:agent-a",
  "process_id": 4321,
  "parent_process_id": 1,
  "event_type": "file_open",
  "resource": "/etc/shadow",
  "outcome": "blocked",
  "severity": "high",
  "sensor_provenance": "landlock-lsm",
  "attributes": {
    "operation": "read",
    "pid": "4321",
    "ppid": "1"
  }
}
```

## 2. Event Types & Provenance Sources

| Event Type | Provenance Sensor | Outcome Types | Typical Severity |
|---|---|---|---|
| `process_exec` | `exec-monitor` / `ebpf-tracepoint` | `allowed`, `blocked`, `audited` | `informational`, `critical` |
| `process_exit` | `exec-monitor` | `audited` | `informational` |
| `file_open` | `landlock-lsm` / `fs-monitor` | `allowed`, `blocked` | `informational`, `high` |
| `file_write` | `landlock-lsm` / `fs-monitor` | `allowed`, `blocked` | `informational`, `high` |
| `net_connect` | `net-monitor` / `seccomp-bpf` | `allowed`, `blocked` | `informational`, `high` |
| `syscall_blocked` | `seccomp-bpf` | `blocked` | `critical` |
| `sensor_status_change` | `sensor-monitor` | `audited` | `informational`, `critical` |
