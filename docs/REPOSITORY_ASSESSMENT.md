# Repository Assessment & Environment Evaluation

**Date:** 2026-11-17  
**Host Platform:** Windows 11 AMD64 (with WSL2 Ubuntu 22.04 LTS)  
**Assessor:** Principal Security & Systems Architect (BADGER Team)  
**Git Author:** `MackenzieCampbelAndross` (`mackenzieandross@gmail.com`)

---

## 1. Executive Summary

This assessment establishes the technical and environmental baseline for building **BADGER V1.0** (Autonomous Agent Security and Runtime Containment Infrastructure). Prior to this assessment, the workspace directory (`D:\Mac\project\badger`) was uninitialized. A Git repository has now been initialized on branch `main` with strict compliance to the designated user identity and email.

The execution environment is a hybrid Windows 11 host with an active, operational WSL2 Linux subsystem running Linux Kernel 6.6 and a freshly initialized Docker Desktop runtime. Native Linux kernel security primitives (Namespaces, cgroups v2, Seccomp-BPF, Landlock LSM, and BTF) are fully supported on the WSL2 kernel.

---

## 2. Environment & Toolchain Inventory

| Component | Host Environment (Windows) | Subsystem / Target (WSL2 Ubuntu 22.04) | Status / Version |
|---|---|---|---|
| **OS / Kernel** | Windows 11 (build 10.0.26100) | `Linux 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC` | Operational (Linux 6.6) |
| **Rust Toolchain** | `rustc 1.92.0`, `cargo 1.92.0` | `rustc 1.100.0`, `cargo 1.100.0` (`x86_64-unknown-linux-gnu`) | Operational |
| **Go Toolchain** | Not installed in Windows PATH | `go version go1.18.1 linux/amd64` | Operational |
| **Node.js / npm** | Node.js `v22.21.1`, npm `11.4.2` | Available via host / path | Operational |
| **Docker Engine** | Docker CLI `29.7.2` | Engine `29.7.2`, API `1.55`, containerd `v2.2.5`, runc `1.3.6` | Operational |
| **C / C++ Compiler** | MSVC Build Tools | `gcc 11.4.0`, `build-essential` | Operational |
| **Security Libs** | N/A | `libseccomp-dev 2.5.3`, `pkg-config 0.29.2` | Installed & Verified |

---

## 3. Linux Kernel Security Primitives Assessment

We probed the active Linux kernel directly via `/proc` and `/sys` interfaces:

1. **cgroups v2:**
   - Mount: `/sys/fs/cgroup`
   - Unified hierarchy confirmed with controllers: `cpu`, `memory`, `io`, `pids`, `cpuset`.
   - Supports subtree delegation and strict per-workload resource limits (`memory.max`, `pids.max`, `cpu.max`).
2. **Linux Namespaces (`unshare`):**
   - Verified available: Mount (`CLONE_NEWNS`), PID (`CLONE_NEWPID`), Network (`CLONE_NEWNET`), IPC (`CLONE_NEWIPC`), UTS (`CLONE_NEWUTS`), User (`CLONE_NEWUSER`).
   - Enables independent file hierarchies, network stacks, and PID trees.
3. **Seccomp (Secure Computing Mode):**
   - Kernel config verification: `CONFIG_SECCOMP=y`, `CONFIG_SECCOMP_FILTER=y`.
   - `libseccomp-dev` is installed. Allows granular syscall filtering (denying raw socket creation, unauthorized `execve`, `ptrace`, etc.).
4. **Landlock LSM (Linux Security Module):**
   - LSM status: `cat /sys/kernel/security/lsm` returns `capability,landlock,yama,safesetid,selinux`.
   - Landlock is active and supported natively on Linux 6.6. Enables unprivileged filesystem sandboxing (restricting read, write, directory traversal to strictly allowlisted paths).
5. **eBPF & Tracing Subsystem:**
   - BTF Type Information: `/sys/kernel/btf/vmlinux` is present (5.8 MB).
   - `/sys/kernel/debug/tracing` and `/sys/fs/bpf` are mounted and available.
   - Kernel supports CO-RE (Compile Once - Run Everywhere) and tracepoints (`sys_enter_execve`, `sys_enter_connect`, `sched_process_exit`).

---

## 4. Architectural & Implementation Strategy

### Hybrid Execution Model
- **Cross-Platform Compatibility:** The codebase is designed as a unified workspace. Code authoring, CLI interactions, and test orchestration run cleanly from both Windows PowerShell and WSL2/Linux.
- **Linux Enforcement Harness:** Because true OS security enforcement (namespaces, seccomp, landlock, cgroups v2) is Linux-specific, all sandbox execution and adversarial enforcement tests execute on the Linux engine (via WSL2 or containerized Linux runners). The agent compiles natively to `x86_64-unknown-linux-gnu`.
- **Telemetry Dual-Path:**
  - **Primary/High-Assurance Path:** eBPF tracepoint / kprobe telemetry (using `aya` or `libbpf` bindings when compiled with Linux BPF support).
  - **Documented Alternative Path:** `/proc` monitoring + `ptrace`/seccomp user notification or audit socket fallback. BADGER explicitly marks telemetry degraded if eBPF cannot attach, preventing false "Protected" claims.
- **Control Plane & Data Plane Separation:**
  - **Data Plane (Agent):** Written in Rust (`agent/crates/badger-agent`, `badger-sandbox`, `badger-sensor`, `badger-identity`). Handles process isolation, seccomp filters, cgroup management, Landlock rules, and telemetry capture.
  - **Control Plane:** Go service (`control-plane/cmd/badger-server`) managing workload identity issuance, policy distribution, finding correlation, and audit persistence.
  - **Contracts:** Versioned Protobuf / JSON schemas (`contracts/proto/` and `contracts/schemas/`) defining strict types for Workload, Principal, Policy, Event, Finding, and AuditRecord.
  - **Operator Interface:** React/TypeScript web interface (`frontend/`) connecting via REST/gRPC API.

---

## 5. Next Steps

1. Create repository layout: `.gitignore`, `contracts/`, `agent/`, `control-plane/`, `policies/`, `tests/`, `docs/`.
2. Define versioned contracts (Protobuf and JSON schemas for Identity, RuntimeEvent, Policy, Finding, AuditRecord).
3. Implement Engine 01 (Identity Intelligence Engine) and Engine 02 (Execution Isolation Engine) in Rust.
4. Implement Engine 03 (Runtime Intelligence Engine) and Engine 04 (Threat Detection Engine).
5. Implement Engine 05 (Capability Governance) and Engine 06 (Autonomous Containment).
6. Build and execute reproducible adversarial verification scenarios A through H.
7. Implement Control Plane & Operator Dashboard.
