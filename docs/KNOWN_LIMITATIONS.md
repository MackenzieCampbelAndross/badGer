# BADGER Known Limitations

---

## 1. Operating System Dependencies

1. **Linux-Exclusive Kernel Primitives:**
   Enforcement primitives (Namespaces, cgroups v2, Seccomp-BPF, Landlock LSM) require a Linux kernel >= 5.13. On non-Linux hosts (such as native Windows or macOS), the agent operates in degraded user-space execution mode and emits explicit degradation warnings.

2. **Unprivileged vs. Privileged Setup:**
   - Namespaces (`CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWNET`) require `CAP_SYS_ADMIN` or user namespace support (`CLONE_NEWUSER`).
   - cgroups v2 hierarchy creation in `/sys/fs/cgroup/badger` requires initial administrative delegation or root permission.
   - Landlock LSM and Seccomp-BPF operate completely unprivileged via `PR_SET_NO_NEW_PRIVS`.

---

## 2. Telemetry Visibility Limits

1. **eBPF Kernel Probes:**
   Full eBPF CO-RE telemetry requires kernel BTF type information (`/sys/kernel/btf/vmlinux`) and tracing access (`/sys/kernel/debug/tracing`). In restricted containerized environments where debugfs is not mounted, BADGER automatically downgrades to `/proc` scanning and reports `SensorHealthStatus::Degraded`.

2. **Short-Lived Ephemeral Processes:**
   In procfs fallback mode, processes terminating in less than 5 milliseconds may evade point-in-time directory polling. High-assurance production deployments must use eBPF tracepoint probes.
