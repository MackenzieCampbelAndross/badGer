# Capability Governance & Policy Intelligence

## 1. Overview

BADGER Capability Governance is a centralized, mathematically grounded authorization framework designed to govern autonomous machine identities, AI agent workflows, and sandboxed workloads.

Rather than relying on coarse binary process permissions, BADGER models security as fine-grained, strongly-typed capabilities evaluated within dynamic execution contexts.

---

## 2. Capability Taxonomy

BADGER defines 12 core capability types covering all standard autonomous agent operations:

| Capability Type | Parameters | Primary OS Enforcement Mechanism |
|---|---|---|
| `FsRead` | `path: String`, `recursive: bool` | Landlock LSM VFS Read |
| `FsWrite` | `path: String`, `allow_create: bool`, `allow_truncate: bool` | Landlock LSM VFS Write |
| `ProcessExec` | `binary: String`, `args: Vec<String>` | Seccomp-BPF & Landlock Exec |
| `NetConnect` | `destination: String`, `port: u16`, `protocol: String` | eBPF `cgroup/connect4`, `cgroup/connect6` |
| `ContainerManage` | `action: String`, `container_id: String` | Docker Socket / OCI Proxy (`Unsupported` in sandbox) |
| `DbAccess` | `database: String`, `query_type: String` | DB Protocol Inspection Proxy |
| `ApiAccess` | `endpoint: String`, `method: String` | MCP Gatekeeper & HTTP Reverse Proxy |
| `CredentialUse` | `credential_id: String`, `scope: String` | SPIRE / SPIFFE Workload Attestation |
| `DeploymentOp` | `cluster: String`, `target: String` | Kubernetes RBAC ServiceAccount |
| `PrivilegeChange` | `privilege: String` | Linux User Namespaces (Deny-by-default) |
| `ResourceLimit` | `resource: String`, `max_value: u64` | cgroups v2 Controller Bounds |
| `Delegation` | `target_principal: String`, `max_depth: u32` | Recursive Capability Intersection |

---

## 3. Subsumption & Intersection Algebra

To prevent privilege escalation and ensure formal verification of grants, capabilities support formal subsumption (`is_subsumed_by`) and intersection (`intersect`):

### 3.1 Subsumption Rules
A requested capability $C_{req}$ is subsumed by a granted capability $C_{grant}$ ($C_{req} \subseteq C_{grant}$) if and only if:
1. `Type(C_{req}) == Type(C_{grant})`
2. **Filesystem Bounds**: `C_{req}.path` is a subpath or identical to `C_{grant}.path`. If `C_{grant}.recursive` is false, `C_{req}.path` must be identical.
3. **Network Bounds**: `C_{req}.destination` is an IP or hostname matching the CIDR or wildcard of `C_{grant}.destination`, ports match, and protocols match.
4. **Execution Bounds**: `C_{req}.binary` matches `C_{grant}.binary` and requested arguments are allowed.

### 3.2 Intersection Algebra
When delegating capabilities to child agents or issuing temporary grants, the resultant grant is the mathematical intersection:
$$C_{effective} = C_{parent} \cap C_{child}$$

If the intersection is empty (e.g., disjoint path trees or non-overlapping network destinations), the delegation is rejected.

---

## 4. Evaluation Engine & Context Conditions

Decisions are explainable, deterministic, and enforce Deny-precedence:

1. **Deny Precedence**: If any matching policy denies the capability, the decision is immediately `Deny`.
2. **Approval Gate**: If allowed by policy but flagged as requiring multi-party approval, the decision is `PendingApproval`.
3. **Context Conditions**:
   - `ClientIp`: Verifies caller socket IP falls within approved subnet.
   - `TimeWindow`: Enforces valid operating hours (e.g. UTC maintenance windows).
   - `MaxRiskScore`: Denies high-risk operations if workload risk score exceeds threshold.
   - `Environment`: Differentiates production, staging, and development workloads.
   - `MfaVerified`: Requires human operator approval confirmation.

4. **Explainability**: Every decision returns structured diagnostic metadata:
   - Evaluated policy IDs.
   - Matched rule IDs.
   - Exact failure reason (if denied).
   - Required approver identities.

---

## 5. Ephemeral Temporary Grants

For break-glass operations and short-lived tasks, temporary capability grants can be attached to workloads:
- Bound by explicit `valid_from` and `valid_until` UNIX timestamps.
- Maximum TTL enforced (default 3600 seconds).
- Automatically purged upon expiration.
- Audited with cryptographic hash-chain signatures.
