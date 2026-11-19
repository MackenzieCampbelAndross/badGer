# BADGER Machine Identity Graph Specification

## 1. Overview

The BADGER Machine Identity Graph (`IdentityGraph`) provides a strongly typed, directed, property-graph representation of all machine identities, runtime workloads, credentials, and accessible resources within a tenant.

The graph powers:
- Real-time lineage and blast-radius tracing.
- Transitive effective access calculation.
- Delegation cycle and anomaly detection.
- Interactive visualization in the BADGER Operator Interface.

---

## 2. Typed Relationships

Every relationship edge in BADGER has a defined semantics, directionality, confidence score, and validity window:

| Relationship Type | Source Entity | Target Entity | Semantics |
|---|---|---|---|
| `OWNS` | Principal / Tenant | Workload / Resource | Declares governance and administrative authority. |
| `RUNS_AS` | Workload | Principal | Identifies the execution persona assumed by the workload. |
| `USES_CREDENTIAL` | Workload | Credential | Records that a workload is configured with or actively utilizing a credential. |
| `CAN_ACCESS` | Workload / Credential | Resource | Grants permission to execute actions against a target resource. |
| `DELEGATES_TO` | Workload / Principal | Workload / Principal | Transitive delegation of capabilities from delegator to delegatee. |
| `CONNECTS_TO` | Workload | Resource (Network) | Kernel-observed or policy-permitted egress connection. |
| `EXECUTES` | Workload | Resource (Binary) | Sandbox-confined process execution. |
| `MANAGED_BY` | Workload | Principal | Orchestrator control relationship. |
| `DISCOVERED_FROM`| Node | Connector | Provenance link connecting an entity to its discovery source. |
| `AUTHENTICATED_BY`| Workload | Credential | Identity attestation relationship. |

---

## 3. Direct vs Inferred Relationships

BADGER strictly categorizes every edge as either:
1. **Direct (`RelationshipKind::Direct`)**: Declared by an explicit security policy, registered via control-plane API, or signed by an authorized principal. Confidence is generally `1.0`.
2. **Inferred (`RelationshipKind::Inferred`)**: Discovered dynamically by eBPF socket events, `/proc` process hierarchy scans, or runtime network egress telemetry. Carries a confidence score (`0.0 <= confidence <= 1.0`).

When calculating critical access decisions, inferred relationships are flagged and subject to strict verification thresholds.

---

## 4. Graph Algorithms & Traversal Engine

### 4.1 Path Traversal & Blast Radius
The graph engine implements depth-limited Depth-First Search (`find_paths`) to compute all connection routes between any pair of nodes up to a configurable depth limit:
```rust
let paths = graph.find_paths("principal-1", "res-db-prod", 5);
```
This enables security teams to determine the exact sequence of delegations and credential bindings that grant an agent access to sensitive infrastructure.

### 4.2 Cycle Detection
Delegation loops (e.g. Agent A delegates to Agent B, which delegates to Agent C, which delegates back to Agent A) can cause confused-deputy vulnerabilities and infinite access amplification.

BADGER implements depth-first cycle detection maintaining recursion call stacks:
```rust
let cycles = graph.detect_cycles();
// Flags any cyclic component and emits an alert
```

### 4.3 Tenant Isolation
Every node and edge carries a `tenant_id`. Graph queries and exports are scoped using `filter_by_tenant(tenant_id)`. If an edge is discovered connecting entities in different tenants without an explicit bilateral federation trust, the Identity Drift Detector raises an immediate `Critical` alert.

---

## 5. Visualization Export Schema

The graph engine exports a normalized JSON schema consumed directly by frontend visualizers:

```json
{
  "nodes": [
    {
      "id": "wkl_146be722",
      "tenant_id": "tenant-corp",
      "entity_type": "Workload",
      "label": "code-synthesis-worker",
      "properties": {
        "spiffe_id": "spiffe://badger.local/ns/tenant-corp/sa/code-agent/workload/wkl_146be722",
        "policy_id": "pol-restricted"
      }
    }
  ],
  "edges": [
    {
      "id": "rel_uses_wkl_cred",
      "tenant_id": "tenant-corp",
      "source_id": "wkl_146be722",
      "target_id": "cred_88a1b2",
      "relationship_type": "USES_CREDENTIAL",
      "kind": "Direct",
      "confidence": 1.0,
      "source_attribution": "control_plane",
      "valid_from_unix": 1731945600
    }
  ],
  "summary": {
    "node_count": 1,
    "edge_count": 1
  }
}
```
