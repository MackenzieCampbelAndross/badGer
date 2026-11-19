# BADGER Kernel and eBPF Compatibility Guide

## 1. System Requirements

The native eBPF telemetry engine in BADGER requires specific kernel features:

- **Linux Kernel Version:** >= 5.8 (required for `BPF_MAP_TYPE_RINGBUF`).
- **Kernel Config Options:**
  - `CONFIG_BPF=y`
  - `CONFIG_BPF_SYSCALL=y`
  - `CONFIG_DEBUG_INFO_BTF=y` (provides `/sys/kernel/btf/vmlinux`)
  - `CONFIG_TRACEPOINTS=y`
  - `CONFIG_CGROUPS=y` and `CONFIG_CGROUP_BPF=y`
- **Capabilities:** Running the agent requires `CAP_BPF` and `CAP_PERFMON` (or root `CAP_SYS_ADMIN`).
- **Filesystem Mounts:** Tracefs must be mounted at `/sys/kernel/tracing` or `/sys/kernel/debug/tracing`.

## 2. Environment Verification

| Environment | Supported | Telemetry Status | Notes |
|---|---|---|---|
| Linux 5.15+ (Debian, Ubuntu, Fedora) | Yes | Full `Protected` | All tracepoints and cgroup attribution functional |
| WSL2 (Kernel 5.15 - 6.6+) | Yes | Full `Protected` | Fully verified on 6.6.87.2-microsoft-standard-WSL2 |
| Linux 5.4 - 5.7 | Partial | `Degraded` | Kernel lacks BPF ring buffer; falls back to procfs polling |
| Linux < 5.4 | Partial | `Degraded` | Falls back to procfs polling |
| macOS / Windows Native | No | `Unprotected` | eBPF and namespaces unavailable outside Linux |

## 3. Graceful Fallback Strategy

When `badger-sensor` initializes:
1. `KernelCapabilityDetector` inspects kernel release, BTF presence, and tracepoint directories.
2. If any prerequisite is missing, the sensor does not crash; it logs specific warnings and activates `AttachedFallbackProcfs`.
3. Sensor health status accurately reflects this state as `Degraded` rather than `Protected`.
