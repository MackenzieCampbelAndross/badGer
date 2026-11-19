# BADGER Enterprise Deployment Guide

## 1. Supported Deployment Topologies

BADGER supports three production deployment patterns:

### Topology A: Kubernetes Cluster (Recommended for Cloud Native)
- **Control Plane**: Runs as a non-root Deployment (`runAsUser: 65534`) across multiple availability zones behind an internal LoadBalancer.
- **Node Security Daemon**: Runs as a privileged DaemonSet (`hostPID: true`, `hostNetwork: true`) on every worker node to manage cgroups, load eBPF bytecode into tracepoints, and isolate local workloads.
- **Operator Console**: Deployed as an NGINX container serving the compiled React/Vite dashboard.
- Manifest: [`deployment/kubernetes/badger-k8s.yaml`](file:///deployment/kubernetes/badger-k8s.yaml)

### Topology B: Docker Compose (Recommended for Small Teams & Testing)
- Microservices topology with isolated bridge networking.
- Services: `control-plane`, `frontend`, and `agent-sandbox`.
- Manifest: [`deployment/compose/docker-compose.yml`](file:///deployment/compose/docker-compose.yml)

### Topology C: Linux Single-Host / Bare Metal (systemd)
- Direct host installation using systemd service units for environments requiring bare-metal performance and strict physical host confinement.

---

## 2. Environment Prerequisites

- **OS**: Linux 5.15+ (6.6+ recommended for Landlock ABI v3 and eBPF ring buffer features).
- **Kernel Features**:
  - `CONFIG_SECURITY_LANDLOCK=y`
  - `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`
  - `CONFIG_CGROUPS=y`, `CONFIG_CGROUP_FREEZER=y`
- **WSL2 Compatibility**: Fully tested and verified on Windows Subsystem for Linux (Kernel 6.6.87.2-WSL2).
