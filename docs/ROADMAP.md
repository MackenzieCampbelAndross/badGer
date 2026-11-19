# BADGER Engineering Roadmap

---

## Milestone 1: Linux Agent Sandbox Foundation (Completed)
- [x] Repository & Environment Assessment (`docs/REPOSITORY_ASSESSMENT.md`).
- [x] Engine 01: Identity Intelligence Engine (SPIFFE identity, drift detection, credential fingerprinting).
- [x] Engine 02: Execution Isolation Engine (Namespaces, cgroups v2, Seccomp-BPF, Landlock LSM).
- [x] Engine 03: Runtime Intelligence Engine (eBPF & procfs dual-path, sensor health state machine).
- [x] Engine 04: Threat Detection Engine (deterministic rules: DET-FS-001, DET-NET-002, DET-PROC-003, DET-SYSCALL-005, DET-INTEG-006).
- [x] Engine 05: Capability Governance Engine (signed policies, allowlist specificity, lifetime bounds).
- [x] Engine 06: Autonomous Containment Engine (cgroup freeze, verified kill, tamper-evident hash chaining).
- [x] Adversarial verification suite (Scenarios A through H: 8/8 PASS).
- [x] Microsecond-grade benchmark harness (>800k events/sec).
- [x] Go Control Plane REST API server.
- [x] React & TypeScript operator dashboard.

---

## Milestone 2: MicroVM & gVisor Containment Layer
- [ ] Evaluate Firecracker microVM backend for hypervisor-isolated multi-tenant agent workloads.
- [ ] Integrate gVisor runsc sandbox runtime as an alternate isolation tier.
- [ ] Implement Open Policy Agent (OPA) / Rego dynamic policy compilation.

---

## Milestone 3: Distributed Agent Federation & Cloud IAM
- [ ] AWS IAM / GCP Workload Identity federation using BADGER SPIFFE tokens.
- [ ] Real-time eBPF socket connection interception and TLS SNI filtering.
- [ ] Distributed streaming ingestion via Apache Kafka / Redpanda when cluster volumes exceed 1M events/sec.
- [ ] Integration with major LLM agent frameworks (LangChain, CrewAI, AutoGen, Claude Desktop MCP).
