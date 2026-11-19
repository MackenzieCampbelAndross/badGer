# BADGER Phase 1 — Native eBPF Runtime Intelligence Engine Architecture

**Status:** Operational / Production-Grade Implementation  
**Crate:** `badger-sensor`  
**Kernel Subsystem:** Linux eBPF (`tracepoints`, `BPF_MAP_TYPE_RINGBUF`, BTF)  
**Userspace Subsystem:** Rust Async Engine (`aya 0.13`, `tokio 1.54`)  
**Target Environment:** Linux Kernel >= 5.8 (Tested on Linux 6.6.87.2-WSL2 x86_64)

---

## 1. Executive Architectural Overview

BADGER Phase 1 introduces a native kernel-space telemetry engine replacing the legacy procfs polling mechanism. The architecture operates outside the target autonomous agent's execution context, intercepting operating system events at the Linux tracepoint layer and streaming structured events into userspace via a bounded BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`).

### Core Engineering Invariants
1. **Zero Workload Modification:** Sandboxed autonomous agents require no bytecode injection, LD_PRELOAD shims, or userspace wrappers.
2. **In-Kernel Tracepoint Interception:** Events are intercepted by verified eBPF programs executing in kernel space before or during syscall dispatch.
3. **True Asynchronous Streaming:** Memory-efficient, lock-free ring buffer communication between kernel and userspace eliminates kernel-to-userspace context switches per event.
4. **Primary Cgroup v2 Attribution:** Workload boundary attribution relies on `bpf_get_current_cgroup_id()`, ensuring immutable workload isolation that is invariant across nested PID namespaces.
5. **Fail-Safe Health State Machine:** The engine detects kernel capabilities at startup and reports accurate health (`Protected`, `Degraded`, `Unprotected`, `Unknown`), falling back safely when required kernel primitives are absent.

```
+-----------------------------------------------------------------------------------+
|                                  LINUX KERNEL                                     |
|                                                                                   |
|  [sys_enter_execve]  [sys_enter_openat]  [sys_enter_connect]  [sys_enter_setuid]   |
|         |                   |                    |                    |           |
|         v                   v                    v                    v           |
|   sched_process_exec   sys_enter_openat   sys_enter_connect   sys_enter_setuid    |
|   sched_process_exit                                                              |
|   sched_process_fork                                                              |
|         +-------------------+--------------------+--------------------+           |
|                             |                                                     |
|                             v                                                     |
|                 +-----------------------+                                         |
|                 | badger_telemetry.bpf  |                                         |
|                 | (Clang -target bpf)   |                                         |
|                 +-----------------------+                                         |
|                             |                                                     |
|                             v bpf_ringbuf_reserve() / bpf_ringbuf_submit()        |
|                 +-----------------------+                                         |
|                 |    events_ringbuf     | (256 KB Bounded Ring Buffer)            |
|                 +-----------------------+                                         |
+-----------------------------|-----------------------------------------------------+
                              | mmap() / epoll / RingBuf::poll
+-----------------------------v-----------------------------------------------------+
|                     BADGER USERSPACE AGENT (Rust)                                 |
|                                                                                   |
|                 +-----------------------+                                         |
|                 | EventRingBufferReader | (aya::maps::RingBuf polling thread)     |
|                 +-----------------------+                                         |
|                             | raw bytes (badger_event_t struct)                   |
|                             v                                                     |
|                 +-----------------------+                                         |
|                 |    EventNormalizer    | (Converts C struct to TelemetryEvent)   |
|                 +-----------------------+                                         |
|                             |                                                     |
|                             v                                                     |
|                 +-----------------------+                                         |
|                 |   WorkloadAttributor  | (Matches cgroup_id & dynamic PIDs)      |
|                 +-----------------------+                                         |
|                             |                                                     |
|                             v broadcast channel                                   |
|                 +-----------------------+                                         |
|                 | TelemetryHealthMonitor| (Monitors event loss, latency, state)   |
|                 +-----------------------+                                         |
+-----------------------------------------------------------------------------------+
```

---

## 2. In-Kernel eBPF Program Architecture

The eBPF probe program is implemented in C (`bpf/badger_telemetry.bpf.c`), compiled with Clang 14+ (`-target bpf -g -O2`) to generate an ELF binary containing full `.BTF` and `.BTF.ext` type sections.

### 2.1 Monitored Kernel Tracepoints
The sensor attaches to six deterministic kernel tracepoints:

| Tracepoint Subsystem | Tracepoint Name | Kernel Event Intercepted | Event Code |
|---|---|---|---|
| `sched` | `sched_process_exec` | Workload process image execution | `EVENT_TYPE_EXEC = 1` |
| `sched` | `sched_process_exit` | Process termination & exit code | `EVENT_TYPE_EXIT = 2` |
| `sched` | `sched_process_fork` | Child process cloning / spawning | `EVENT_TYPE_FORK = 3` |
| `syscalls` | `sys_enter_connect` | Network socket connection attempt | `EVENT_TYPE_CONNECT = 4` |
| `syscalls` | `sys_enter_openat` | Filesystem file open/create attempt | `EVENT_TYPE_OPEN = 5` |
| `syscalls` | `sys_enter_setuid` | Process privilege elevation attempt | `EVENT_TYPE_PRIVILEGE = 6` |

### 2.2 Memory Layout & BPF Ring Buffer Map
Events are formatted into an aligned C structure (`badger_event_t`) and pushed into a 256 KB bounded ring buffer map:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} events_ringbuf SEC(".maps");

struct badger_event_t {
    __u64 event_id;
    __u64 timestamp_ns;
    __u32 cpu_id;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u32 event_type;
    __u32 payload_len;
    char comm[16];
    char resource[128];
};
```

### 2.3 Kernel Helper Mechanics
- **Process Context:** `bpf_get_current_pid_tgid()` captures the thread ID and thread group ID (PID in userspace terms).
- **Credentials:** `bpf_get_current_uid_gid()` captures real UID and GID.
- **Process Comm:** `bpf_get_current_comm()` extracts the 16-byte null-terminated task name.
- **Timestamping:** `bpf_ktime_get_ns()` provides nanosecond monotonic system time.
- **CPU Attribution:** `bpf_get_smp_processor_id()` captures the active executing CPU core.
- **Cgroup Boundary:** `bpf_get_current_cgroup_id()` extracts the 64-bit cgroup v2 inode ID.

---

## 3. Userspace Subsystem Design (`badger-sensor`)

The userspace sensor engine is organized into modular components adhering to single-responsibility engineering:

```
agent/crates/badger-sensor/src/
├── lib.rs              # Public sensor interface & RuntimeSensor orchestrator
├── types.rs            # Core TelemetryEvent, SensorHealth, Capability structs
├── capabilities.rs     # KernelCapabilityDetector (BTF, tracepoints, cgroups v2)
├── loader.rs           # ProbeLoader (Bytecode alignment, Aya Ebpf loading)
├── probes.rs           # ProbeManager & ProbeAttachmentRegistry (lifecycle & links)
├── ring_buffer.rs      # EventRingBufferReader (Asynchronous ring buffer poller)
├── normalizer.rs       # EventNormalizer (Binary deserialization & schema mapping)
├── attributor.rs       # WorkloadAttributor (Cgroup v2 & dynamic PID binding)
└── health.rs           # TelemetryHealthMonitor (Health transitions & event loss)
```

### 3.1 Kernel Capability Detection (`capabilities.rs`)
Before attempting to load eBPF bytecode, `KernelCapabilityDetector` performs non-destructive environment discovery:
1. Inspects kernel version via `uname()` (requires >= 5.8 for `BPF_MAP_TYPE_RINGBUF`).
2. Checks `/sys/kernel/btf/vmlinux` for in-kernel BTF support.
3. Verifies `/sys/kernel/tracing/events` or `/sys/kernel/debug/tracing/events` for tracepoint accessibility.
4. Checks `/sys/fs/cgroup/cgroup.controllers` for cgroups v2 unified hierarchy.
5. If any requirement fails, the sensor reports capability state and falls back honestly to `Degraded` procfs monitoring.

### 3.2 Bytecode Loading & Lifecycle Management (`loader.rs`, `probes.rs`)
- **Memory Header Alignment:** Aya's underlying ELF parser requires memory alignment matching host pointer width. Raw `include_bytes!` slices can be 1-byte aligned in Rust binaries. `ProbeLoader` automatically re-aligns the embedded bytecode into a pointer-aligned `Vec<u8>`.
- **Tracepoint Link Retention:** Aya's tracepoint links (`TracePointLink`) and kernel file descriptors are bound to the parent `aya::Ebpf` instance. `RuntimeSensor` maintains `ebpf_holder: Arc<Mutex<Option<aya::Ebpf>>>`, ensuring kernel hooks remain attached until `sensor.stop()` is explicitly called.

### 3.3 Event Normalization & Protocol Translation (`normalizer.rs`)
Raw binary records from the ring buffer are validated for minimum size (176 bytes) and unpacked into strongly-typed `TelemetryEvent` structures:
- Binary timestamps are correlated with wall-clock epoch time.
- Null-terminated strings (`comm`, `resource`) are sanitized.
- Event types are validated against the system contract.

### 3.4 Workload Attribution (`attributor.rs`)
Attributing events from system-wide kernel tracepoints to isolated workloads requires dual-layer matching:
1. **Cgroup v2 Inode ID (Primary):** Workloads running inside a dedicated BADGER sandbox cgroup (`/sys/fs/cgroup/badger/<workload_id>`) possess an invariant 64-bit cgroup ID. Events from the root host cgroup (`cgroup_id <= 1`) are never attributed as workload containers, preventing host noise.
2. **Dynamic Child PID Tracking:** When a monitored workload invokes `fork()` or `clone()`, the `EVENT_TYPE_FORK` handler dynamically registers the new child PID with the attributor, ensuring multi-process workloads remain fully observed across their entire process tree.

### 3.5 Backpressure & Loss Accounting (`health.rs`, `ring_buffer.rs`)
The ring buffer reader monitors event delivery rates. If userspace cannot consume events at the kernel generation rate:
- The kernel drops events and increments its internal lost counter.
- `TelemetryHealthMonitor` increments `event_loss_count`.
- If event loss exceeds configured thresholds, sensor health transitions from `Protected` to `Degraded`, alerting security operators that telemetry loss has occurred.

---

## 4. Security & Safety Guarantees

1. **Kernel Verifier Safety:** The eBPF program conforms strictly to the Linux kernel BPF verifier constraints: bounded loops, validated buffer boundaries, and read-only probe arguments.
2. **No Data Leakage:** Event structures omit sensitive environment variables, full shell arguments, process memory dumps, or file contents. Telemetry is limited to metadata descriptors (paths, addresses, UIDs, PIDs).
3. **Clean Teardown:** Upon `sensor.stop()`, all kernel tracepoint links are detached and file descriptors closed. No orphaned probes or lingering maps remain in the kernel.
