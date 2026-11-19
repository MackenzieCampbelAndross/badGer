# BADGER Identity Discovery Connectors Architecture

## 1. Overview

BADGER discovers machine identities and runtime execution contexts by interfacing with host and container environments through modular **Identity Connectors**.

Connectors adhere to the following core design principles:
1. **Zero Simulation**: Observations are derived solely from real operating system interfaces (`/proc`, cgroups v2, unix sockets).
2. **Graceful Degradation**: If an optional runtime (such as Docker or Kubernetes) is not installed or accessible, the connector reports `Unavailable` with clear diagnostic details and does NOT crash, block, or degrade other subsystem operations.
3. **Source Attribution & Confidence**: Every observation records its originating connector and an empirical confidence rating reflecting data completeness.

---

## 2. Connector Interface

All discovery connectors implement the `IdentityConnector` trait:

```rust
pub trait IdentityConnector: Send + Sync {
    fn name(&self) -> &str;
    fn connector_type(&self) -> IdentitySource;
    fn status(&self) -> ConnectorStatus;
    fn discover(&self, tenant_id: &str) -> BadgerResult<Vec<IdentityObservation>>;
}
```

### Connector Health States
- `ConnectorStatus::Healthy`: Operating system boundary is accessible and actively yielding valid observations.
- `ConnectorStatus::Degraded { reason }`: Partial observability (e.g. procfs readable but cgroup attributes restricted).
- `ConnectorStatus::Unavailable { reason }`: The underlying runtime boundary (e.g. `/var/run/docker.sock`) is not present or permissions are withheld. Discovery gracefully returns an empty observation list.

---

## 3. Implemented Connectors

### 3.1 Linux Process Discovery Connector (`LinuxProcessConnector`)
- **Telemetry Source**: Host `/proc` filesystem.
- **Attributes Collected**:
  - PID and PPID (`/proc/[pid]/status`)
  - Real UID, Effective UID, Real GID (`/proc/[pid]/status`)
  - Command line execution vector (`/proc/[pid]/cmdline`)
  - Cgroup v2 path (`/proc/[pid]/cgroup`)
- **Badger Workload Attribution**:
  - Analyzes the cgroup string for the `/badger/` hierarchy. If present, the entity is categorized as `BadgerProcess` with confidence `0.99`; host daemon processes are categorized as `HostProcess` with confidence `0.85`.

### 3.2 BADGER Sandbox Workload Connector (`BadgerWorkloadConnector`)
- **Telemetry Source**: Internal active sandbox registry and cgroups v2 hierarchy (`/sys/fs/cgroup/badger/`).
- **Attributes Collected**:
  - Workload ID and Principal ID
  - Cryptographic SPIFFE ID (`spiffe://badger.local/...`)
  - Associated Landlock policy ID and version
  - Sensor protection status (`Protected`, `Degraded`, `Unprotected`)
- **Confidence**: `1.0` (Direct control-plane authority).

### 3.3 Docker Container Connector (`DockerConnector`)
- **Telemetry Source**: Local UNIX domain socket at `/var/run/docker.sock`.
- **Fault-Tolerant Behavior**:
  - Checks if `/var/run/docker.sock` exists and is readable.
  - If absent or permission denied: sets status to `ConnectorStatus::Unavailable { reason: "Docker socket /var/run/docker.sock not accessible or daemon not running" }`.
  - Ingestion continues smoothly without throwing unhandled exceptions.

### 3.4 Kubernetes In-Cluster Connector (`KubernetesConnector`)
- **Telemetry Source**: In-cluster ServiceAccount token (`/var/run/secrets/kubernetes.io/serviceaccount/token`) or `KUBECONFIG` environment variable.
- **Fault-Tolerant Behavior**:
  - Verifies presence of token path or configuration file.
  - If neither is detected: returns `ConnectorStatus::Unavailable { reason: "Kubernetes in-cluster service account or KUBECONFIG absent" }`.
  - Non-Kubernetes host machines (e.g. bare metal or local development WSL2 instances) operate with full stability.

---

## 4. Connector Registry & Execution Lifecycle

The `ConnectorRegistry` manages all active connectors:
```rust
let mut registry = ConnectorRegistry::new();
registry.register(Box::new(LinuxProcessConnector::default()));
registry.register(Box::new(DockerConnector::default()));
registry.register(Box::new(KubernetesConnector::default()));

// Batched non-blocking discovery execution
let observations = registry.run_discovery("tenant-corp");
```

Observations are forwarded to the Normalizer, which updates the `IdentityGraph` and correlates newly observed processes with existing principals and policy bindings.
