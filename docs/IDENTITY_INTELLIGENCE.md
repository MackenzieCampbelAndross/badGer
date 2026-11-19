# BADGER Phase 3: Machine Identity Intelligence Architecture

## 1. Executive Summary

Autonomous AI agents, background tool-runners, and Model Context Protocol (MCP) servers operate as nonhuman machine identities with dynamic privilege lifecycles. Traditional IAM systems assume human-in-the-loop workflows, static OAuth client definitions, and long-lived API tokens. 

BADGER Phase 3 implements an operating-system-anchored Machine Identity Intelligence and Graph Subsystem that:
1. Discovers, normalizes, and continuously monitors machine identities across Linux processes, cgroups, container boundaries, and active sandboxes.
2. Formulates a strongly typed directed relationship graph correlating ownership, delegation, execution, and credential bindings.
3. Issues and rotates cryptographically verified SPIFFE-compatible workload identities (X.509 SVIDs) with kernel attestation.
4. Governs credential intelligence using keyed HMAC-SHA256 fingerprinting without ever storing or logging raw secrets.
5. Computes transitive effective access across multi-hop delegation chains, inherited tenant scopes, and credential bindings.
6. Detects identity drift, unapproved credential sharing, cross-tenant boundary crossings, and orphaned service accounts in real time.

---

## 2. Canonical Identity Model

The identity model defines the core entities governed by BADGER:

```
+-----------------------------------------------------------------------------------+
|                                  TENANT                                           |
|                           (Cryptographic Boundary)                                |
+-----------------------------------------------------------------------------------+
       |                                                                    |
       v (OWNS)                                                             v (OWNS)
+-------------------+                                               +-------------------+
|     PRINCIPAL     |                                               |     RESOURCE      |
| (Agent / Service) |                                               | (API / DB / Disk) |
+-------------------+                                               +-------------------+
       |                                                                    ^
       v (OWNS)                                                             |
+-------------------+ (USES_CREDENTIAL) +--------------------+              |
|     WORKLOAD      | ----------------> |     CREDENTIAL     | (CAN_ACCESS) |
| (Process/Sandbox) |                   | (HMAC Fingerprint) | -------------+
+-------------------+                   +--------------------+              |
       |                                                                    |
       +---------------------------- (CAN_ACCESS) --------------------------+
       |
       +---------------------------- (DELEGATES_TO) ------------------------> [Workload B]
```

### Entity Specifications

1. **Tenant**: Absolute multi-tenant security boundary. All identities, workloads, credentials, and graph relationships are owned by a tenant. Cross-tenant relationships are strictly prohibited unless explicit bilateral federation is configured.
2. **Principal**: The nonhuman identity representing an agent persona, service account, or orchestrator. Principals own workloads and define baseline policy boundaries.
3. **Workload**: The execution instance running inside an isolated Linux sandbox, associated with a cgroup v2 path, a dedicated PID namespace, and Landlock filesystem rules.
4. **Credential**: Cryptographic credential metadata identified exclusively by a keyed HMAC-SHA256 fingerprint (`HMAC(tenant_salt, raw_secret)`). Raw credentials are never stored in memory or persisted to disk.
5. **Resource**: Governed target systems including internal databases, external LLM APIs, host filesystem paths, and network CIDR destinations.
6. **Capability**: Granular permissions (e.g. `read`, `write`, `execute`, `connect`, `admin`) bound to target resources.
7. **IdentityObservation**: Raw telemetry ingested from discovery connectors with source attribution and confidence ratings.
8. **IdentityFinding**: Actionable security drift and anomaly alerts with evidence and remediation playbooks.

---

## 3. Subsystem Architecture

The identity intelligence pipeline runs asynchronously alongside the eBPF runtime sensor and egress network engine:

```
[ Linux /proc ]  [ BADGER Sandbox ]  [ Docker Socket ]  [ K8s ServiceAccount ]
       |                  |                  |                    |
       +------------------+------------------+--------------------+
                                  |
                                  v
                     [ Discovery Connectors Engine ]
                                  |
                                  v
                     [ Observation Normalizer ]
                                  |
       +--------------------------+--------------------------+
       |                                                     |
       v                                                     v
[ Identity Graph Engine ]                            [ SPIFFE Authority ]
 - Adjacency lists (In/Out)                           - X.509 SVID generation
 - Cycle detection (Tarjan)                           - Automated rotation
 - BFS/DFS path traversal                             - CRL revocation list
       |                                                     |
       +--------------------------+--------------------------+
                                  |
                                  v
                     [ Credential Intelligence ]
                      - Keyed HMAC-SHA256 fingerprinting
                      - Usage frequency & exposure tracking
                                  |
                                  v
                     [ Effective Access Analyzer ]
                      - Transitive closure over DELEGATES_TO
                      - Over-privileged identity detector
                                  |
                                  v
                     [ Identity Drift Detector ]
                      - Unowned workload detection
                      - Credential sharing across workloads
                      - Expired credential tracking
                      - Cross-tenant breach alerts
```

---

## 4. Verification and Security Properties

| Property | Guarantee | Implementation Mechanism |
|---|---|---|
| **Zero Raw Secrets** | No plaintext API keys or tokens are stored or logged. | Keyed HMAC-SHA256 fingerprinting using tenant-isolated salt keys. |
| **Kernel Attestation** | SVIDs are issued only to verified sandboxed processes. | Validation of cgroup v2 membership and active PID existence prior to SVID signing. |
| **Delegation Containment** | Delegation cannot cause runaway privilege or cycles. | Cycle detection and configurable max-depth enforcement (`max_delegation_depth = 2`). |
| **Strict Multi-Tenancy** | Identities cannot span or access cross-tenant entities. | Tenant boundary checks on all graph edges and API query layers. |
| **Graceful Degradation** | Missing container runtimes do not impede host operation. | Dynamic connector status checking (`Healthy` vs `Unavailable`) without crashing. |
