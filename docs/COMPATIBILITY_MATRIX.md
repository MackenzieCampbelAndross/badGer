# BADGER Compatibility Matrix

## 1. Operating System & Kernel Support

| Platform | Kernel Version | Landlock Support | eBPF Tracepoints | cgroups v2 Freezer | Support Level |
|---|---|---|---|---|---|
| **Ubuntu 22.04 LTS** | 5.15+ / 6.5+ | ABI v1 / v2 | Full | Unified | Production |
| **Ubuntu 24.04 LTS** | 6.8+ | ABI v3 / v4 | Full | Unified | Production |
| **RHEL / Rocky Linux 9** | 5.14+ | ABI v1 / v2 | Full | Unified | Production |
| **Debian 12 (Bookworm)** | 6.1+ | ABI v2 / v3 | Full | Unified | Production |
| **WSL2 (Windows 11)** | 6.6.87+ | ABI v3 | Full | Unified | Verified Development & CI |
| **Fedora 39 / 40** | 6.5+ / 6.8+ | ABI v3 / v4 | Full | Unified | Production |

---

## 2. Hardware Architecture Support

- **x86_64**: Fully supported across all subsystems (Landlock, Seccomp-BPF, Aya eBPF, RingBuffer).
- **aarch64 (ARM64)**: Fully supported with dedicated Seccomp syscall definitions (omitting x86-specific syscall numbers).
- **Other architectures**: Evaluated as `Degraded` mode; policy evaluation operational, kernel LSM fallback to namespaces.
