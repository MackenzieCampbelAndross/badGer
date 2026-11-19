# BADGER: Autonomous Agent Security & Runtime Containment Infrastructure

[![Linux Kernel](https://img.shields.io/badge/Linux-6.6%20LTS-blue.svg)](https://kernel.org)
[![Security Primitives](https://img.shields.io/badge/Security-Landlock%20ABI%20v3%20%7C%20eBPF%20%7C%20cgroups%20v2-green.svg)](#security-architecture)
[![Adversarial Suite](https://img.shields.io/badge/Adversarial%20Suite-8%2F8%20PASS-brightgreen.svg)](#adversarial-verification)
[![Test Suite](https://img.shields.io/badge/Test%20Suite-100%25%20PASS-brightgreen.svg)](#test-metrics)
[![Enterprise Release](https://img.shields.io/badge/Release-V1.0%20Enterprise-blue.svg)](docs/V1_RELEASE_REPORT.md)

> **Core Mission:** Secure every identity. Constrain every capability. Observe every action. Contain every breach.  
> **Core Thesis:** Never trust an autonomous agent merely because it runs inside a trusted environment. BADGER independently governs machine identity, execution boundaries, runtime behavior, capabilities, and containment outside the agent's own decision-making process.

---

## 1. System Overview

**BADGER** is an enterprise-grade autonomous agent security and runtime containment infrastructure designed to protect host operating systems, cloud environments, and internal networks from rogue, hallucinating, prompt-injected, or compromised autonomous software.

BADGER enforces security boundaries at the operating system kernel level using native Linux security primitives (Landlock LSM ABI v3, Seccomp-BPF architecture-specific syscall filters, cgroups v2 freezer, and eBPF socket address hooks), providing verifiable isolation and deterministic threat detection without relying on language model judgments for security decisions.

### BADGER's Subsystems

1. **Native eBPF Runtime Intelligence Engine** (`badger-sensor`) — 6 kernel tracepoint probes (`sched_process_exec`, `sched_process_exit`, `sched_process_fork`, `sys_enter_connect`, `sys_enter_openat`, `sys_enter_setuid`), 256KB bounded ring buffer, and deterministic cgroup inode attribution.
2. **Granular Network Egress Enforcement Engine** (`badger-network`) — Kernel-level cgroup socket connect hooks (`cgroup/connect4`, `cgroup/connect6`), AWS/GCP metadata drops (`169.254.169.254`), and monotonic policy rollbacks.
3. **Machine Identity Intelligence Engine** (`badger-identity`) — Canonical identity graph (Principals, Workloads, Credentials, Resources), keyed HMAC-SHA256 fingerprinting (zero raw secrets), SPIFFE X.509 SVID rotation, and drift detection.
4. **Capability Governance & Policy Engine** (`badger-policy`) — 12 strongly-typed capabilities, subsumption and intersection algebra, anti-rollback distribution, delegation depth enforcement, and evidence-based least privilege recommendations.
5. **Autonomous Containment & Incident Response** (`badger-containment`) — 10 verifiable response actions (`SuspendWorkload`, `FreezeCgroup`, `KillProcess`, `IsolateNetwork`, `RevokeCredentials`, `QuarantineWorkload`), 10-stage response lifecycle, and gated operator recovery.
6. **Execution Isolation Engine** (`badger-sandbox`) — Multi-namespace isolation (PID, Mount, Net, IPC, UTS), cgroups v2 quotas (`memory.max`, `pids.max`, `cgroup.freeze`), and Landlock LSM v3 path restrictions.
7. **Enterprise Control Plane** (`control-plane`) — Multi-tenant Go REST gateway with RBAC roles (`Platform Administrator`, `Security Administrator`, `Security Analyst`, `Platform Engineer`, `Auditor`), audit hash chains, and integration catalog.
8. **Enterprise Operator Console** (`frontend`) — React 18 / Vite console featuring 13 dedicated operational sections: Overview, Workloads, Identities, Identity Graph, Runtime Activity, Network Security, Threat Findings, Capability Governance, Policies, Containment, Audit Trail, Integrations, and Settings.

---

## 2. Adversarial Verification Suite (Milestone 1)

All eight required adversarial scenarios were executed directly inside the Linux 6.6 kernel environment and passed verification:

| Scenario | Target Attack Vector | Detection | Enforcement | Audit Record | Status |
|---|---|:---:|:---:|:---:|:---:|
| **Scenario A: Filesystem Boundary** | Unauthorized access attempt to `/etc/shadow` | **YES** | **YES** | **YES** | **PASS** |
| **Scenario B: Network Boundary** | Prohibited external egress attempt (`198.51.100.1:4444`) | **YES** | **YES** | **YES** | **PASS** |
| **Scenario C: Process Execution** | Prohibited execution attempt of unauthorized tool (`/bin/nc`) | **YES** | **YES** | **YES** | **PASS** |
| **Scenario D: Process Monitoring** | Permitted child process creation & SPIFFE identity attribution | **YES** | **YES** | **YES** | **PASS** |
| **Scenario E: Policy Violation** | Forbidden system call interception (`SYS_bpf`) & cgroup freeze | **YES** | **YES** | **YES** | **PASS** |
| **Scenario F: Workload Isolation** | Namespace (mount/pid/net/ipc/uts) + cgroup v2 subtree setup | **YES** | **YES** | **YES** | **PASS** |
| **Scenario G: Sensor Failure** | Telemetry disruption reporting degraded visibility transparently | **YES** | **YES** | **YES** | **PASS** |
| **Scenario H: Policy Integrity** | Signature tampering rejection & active policy fallback | **YES** | **YES** | **YES** | **PASS** |

---

## 3. Measured Performance Benchmarks

Measured over 10,000 iterations on AMD64 Linux 6.6:

| Metric | Measured Value | Standard Target | Status |
|---|---|---|---|
| **Policy Evaluation Latency (P50)** | **0.950 µs** | < 10.0 µs | **Achieved** |
| **Policy Evaluation Latency (P95)** | **0.960 µs** | < 25.0 µs | **Achieved** |
| **Policy Evaluation Latency (P99)** | **1.032 µs** | < 50.0 µs | **Achieved** |
| **Threat Detection Latency (P50)** | **0.990 µs** | < 10.0 µs | **Achieved** |
| **Threat Detection Latency (P95)** | **1.021 µs** | < 25.0 µs | **Achieved** |
| **Threat Detection Latency (P99)** | **1.982 µs** | < 50.0 µs | **Achieved** |
| **Event Ingestion Throughput** | **888,273 events/sec** | > 100,000 | **Achieved** |
| **Event Loss Under Load** | **0.00%** | < 0.01% | **Achieved** |

---

## 4. Repository Structure

```text
badger/
├── agent/                          # Rust Data Plane
│   └── crates/
│       ├── badger-agent/           # CLI daemon, adversarial runner & benchmarks
│       ├── badger-common/          # Shared types, error definitions, SHA256 audit logger
│       ├── badger-identity/        # Workload registration & SPIFFE ID generation
│       ├── badger-policy/          # Capability policy engine & signature verification
│       ├── badger-sandbox/         # Linux namespaces, cgroups v2, Landlock LSM, Seccomp-BPF
│       ├── badger-sensor/          # Runtime telemetry, eBPF / procfs dual-path monitor
│       ├── badger-threat/          # Deterministic rules engine (DET-FS, DET-NET, DET-PROC)
│       └── badger-containment/     # Verified response actions (freeze, kill, network cut)
├── control-plane/                  # Go Control Plane
│   ├── cmd/badger-server/          # HTTP REST / gRPC API server
│   └── internal/
│       ├── events/                 # Event ingestion & threat correlation
│       ├── identity/               # Workload identity directory
│       └── models/                 # Go model definitions
├── contracts/                      # API & Data Contracts
│   ├── proto/badger.proto          # Protobuf v3 definitions
│   └── schemas/                    # JSON Schema specifications (policy, event, finding, audit)
├── frontend/                       # React / TypeScript Operator Interface
├── deployment/                     # Docker & Compose Configurations
├── policies/                       # Example security policies
├── docs/                           # Architecture, Threat Model & Engineering Specifications
└── Makefile                        # Automated build & test orchestration
```

---

## 5. Quickstart & Verification

### Prerequisites
- Linux Kernel >= 5.13 (Linux 6.6 LTS recommended; native Linux, WSL2, or container runtime).
- Rust >= 1.80 (`cargo`, `rustc`).
- Go >= 1.18.
- Node.js >= 20.

### 1. Run Unit Tests Across All Components
```bash
cargo test
cd control-plane && go test -v ./...
```

### 2. Run Adversarial Security Verification Suite
```bash
cargo run -p badger-agent -- adversarial
```

### 3. Run Performance Benchmark Harness
```bash
cargo run -p badger-agent --release -- benchmark
```

### 4. Launch Operator Control Plane & Interface
```bash
# Terminal 1: Start Control Plane
cd control-plane && go run ./cmd/badger-server

# Terminal 2: Start Frontend
cd frontend && npm install && npm run dev
```

Open `http://localhost:3000` to inspect workloads, security findings, telemetry, and the cryptographic audit trail.
