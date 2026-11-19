# BADGER In-Kernel Telemetry Specification

## 1. Tracepoint Event Specifications

The `badger-sensor` module attaches to standard Linux kernel tracepoints to observe workload operations:

- `sched:sched_process_exec`: Intercepts binary execution transitions. Captures process name, PID, TGID, parent PID, and cgroup ID.
- `sched:sched_process_exit`: Intercepts process termination. Captures exit code and cleans up tracking entries.
- `sched:sched_process_fork`: Intercepts `clone()` and `fork()` calls to record child PIDs in `WorkloadAttributor`.
- `syscalls:sys_enter_connect`: Intercepts socket outbound connection attempts, recording destination address families and sockaddr metadata.
- `syscalls:sys_enter_openat`: Intercepts filesystem open and create requests, capturing target paths up to 128 bytes.
- `syscalls:sys_enter_setuid`: Intercepts user privilege changes, capturing targeted UID changes.

## 2. Event Binary Layout

The in-kernel structure serialized into the BPF ring buffer is defined in `agent/crates/badger-sensor/bpf/badger_telemetry.bpf.c`:

| Field | Type | Description |
|---|---|---|
| `event_id` | `u64` | Monotonically incremented sequence identifier |
| `timestamp_ns` | `u64` | Nanosecond timestamp from `bpf_ktime_get_ns()` |
| `cpu_id` | `u32` | SMP processor core executing the hook |
| `pid` | `u32` | Thread ID from `bpf_get_current_pid_tgid()` |
| `tgid` | `u32` | Process ID from `bpf_get_current_pid_tgid()` |
| `ppid` | `u32` | Parent process ID |
| `uid` | `u32` | User ID from `bpf_get_current_uid_gid()` |
| `gid` | `u32` | Group ID from `bpf_get_current_uid_gid()` |
| `cgroup_id` | `u64` | Cgroup v2 inode from `bpf_get_current_cgroup_id()` |
| `event_type` | `u32` | Numerical event tag (1: exec, 2: exit, 3: fork, 4: connect, 5: open, 6: setuid) |
| `payload_len` | `u32` | Valid length of `resource` field |
| `comm[16]` | `char[16]` | Process command name from `bpf_get_current_comm()` |
| `resource[128]` | `char[128]` | Null-terminated resource string (path or socket info) |

## 3. Userspace Translation

`EventNormalizer` translates raw binary packets into BADGER's unified `TelemetryEvent` struct:
- Calculates system wall-clock time by correlating kernel monotonic timestamps with agent boot time.
- Strips null-byte padding from strings.
- Maps event codes to `badger_common::models::EventType`.
- Passes the normalized event to `WorkloadAttributor` for sandbox ownership assignment.
