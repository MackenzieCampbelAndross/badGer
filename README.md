# BADGER: Autonomous Agent Security & Runtime Containment Infrastructure

[![Linux Kernel](https://img.shields.io/badge/Linux-6.6%20LTS-blue.svg)](https://kernel.org)
[![Security Primitives](https://img.shields.io/badge/Security-Landlock%20%7C%20Seccomp--BPF%20%7C%20cgroups%20v2-green.svg)](#security-architecture)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Adversarial Verification](https://img.shields.io/badge/Adversarial%20Suite-8%2F8%20PASS-brightgreen.svg)](#adversarial-verification)

> **Core Mission:** Secure every identity. Constrain every capability. Observe every action. Contain every breach.  
> **Core Thesis:** Never trust an autonomous agent merely because it runs inside a trusted environment. BADGER independently governs machine identity, execution boundaries, runtime behavior, capabilities, and containment outside the agent's own decision-making process.

---

## 1. System Overview

**BADGER** is an enterprise-grade autonomous agent security and runtime containment infrastructure designed to protect host operating systems, cloud environments, and internal networks from rogue, hallucinating, prompt-injected, or compromised autonomous software.

BADGER enforces security boundaries at the operating system kernel level using native Linux security primitives, providing verifiable isolation and deterministic threat detection without relying on language model judgments for security decisions.

### BADGER's Six Core Engines

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BADGER CONTROL PLANE                              │
│  ┌─────────────────────────┐                 ┌───────────────────────────┐  │
│  │   ENGINE 01: IDENTITY   │◄───────────────►│   ENGINE 05: CAPABILITY   │  │
│  │   INTELLIGENCE ENGINE   │                 │     GOVERNANCE ENGINE     │  │
│  └────────────┬────────────┘                 └─────────────┬─────────────┘  │
│               │                                            │                │
│               ▼                                            ▼                │
│  ┌─────────────────────────┐                 ┌───────────────────────────┐  │
│  │   ENGINE 04: THREAT     │                 │   ENGINE 06: AUTONOMOUS   │  │
│  │    DETECTION ENGINE     │────────────────►│    CONTAINMENT ENGINE     │  │
│  └────────────▲────────────┘                 └─────────────┬─────────────┘  │
└───────────────┼────────────────────────────────────────────┼────────────────┘
                │ Telemetry Stream                           │ Containment
┌───────────────┼────────────────────────────────────────────┼────────────────┐
│               │             BADGER DATA PLANE              │                │
│  ┌────────────┴────────────┐                 ┌─────────────▼─────────────┐  │
│  │   ENGINE 03: RUNTIME    │                 │   ENGINE 02: EXECUTION    │  │
│  │   INTELLIGENCE SENSOR   │                 │     ISOLATION ENGINE      │  │
│  │ (eBPF / Tracepoints /   │                 │ (Namespaces / cgroups v2 /│  │
│  │   procfs fallback)      │                 │  Landlock / Seccomp-BPF)  │  │
│  └─────────────────────────┘                 └───────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Engine 01: Identity Intelligence Engine** (`badger-identity`) — Assigns cryptographically verifiable, stable workload identities (SPIFFE ID), tracks credential relationships without storing raw secrets, maps principal ownership, and detects identity drift.
2. **Engine 02: Execution Isolation Engine** (`badger-sandbox`) — Enforces multi-namespace isolation (PID, Mount, Net, IPC, UTS), cgroups v2 resource quotas (`memory.max`, `pids.max`, `cpu.max`), Seccomp-BPF system call filtering, and Landlock LSM filesystem restriction.
3. **Engine 03: Runtime Intelligence Engine** (`badger-sensor`) — Observes process creation, file operations, socket connections, and privilege alterations via eBPF/tracepoints with transparent degradation tracking (`Protected`, `Degraded`, `Unprotected`).
4. **Engine 04: Threat Detection Engine** (`badger-threat`) — Deterministic, explainable detection rules (`DET-FS-001`, `DET-NET-002`, `DET-PROC-003`, `DET-SYSCALL-005`, `DET-INTEG-006`) generating auditable findings.
5. **Engine 05: Capability Governance Engine** (`badger-policy`) — Cryptographically signed, versioned capability policy manifests with explicit path, network, and system call allowlists.
6. **Engine 06: Autonomous Containment Engine** (`badger-containment`) — Idempotent, bounded containment actions (`cgroup.freeze`, process termination with `ESRCH` verification, network namespace isolation) with tamper-evident SHA-256 hash chaining.

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
