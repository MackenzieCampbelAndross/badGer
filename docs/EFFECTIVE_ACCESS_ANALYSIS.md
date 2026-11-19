# BADGER Effective Access Analysis & Over-Privilege Detection

## 1. The Challenge of Agentic Access

Autonomous agents rarely operate with static, single-hop permissions. In enterprise workflows:
- Orchestrator agents delegate tasks to worker subagents (`DELEGATES_TO`).
- Workloads inherit permissions from their parent principals (`OWNS` / `RUNS_AS`).
- Capabilities are expanded through dynamic credential attachments (`USES_CREDENTIAL` $\to$ `CAN_ACCESS`).
- Network policies determine which physical egress CIDRs and APIs can be reached.

Looking solely at direct workload policies produces a distorted view of actual permissions. BADGER resolves this with the **Effective Access Analyzer**, computing the full transitive closure over all identity graph edges.

---

## 2. Transitive Access Computation Model

The effective access of any entity $E$ across target resources $R$ is computed by evaluating the union of four provenance vectors:

$$\text{EffectiveAccess}(E) = \mathcal{A}_{\text{Direct}} \cup \mathcal{A}_{\text{Inherited}} \cup \mathcal{A}_{\text{Delegated}} \cup \mathcal{A}_{\text{Credential}}$$

```
[ Workload ]
     |
     +--- (Direct) -------------> CAN_ACCESS --------> [ Resource ]
     |
     +--- (Inherited) ----------> OWNS (Principal) --> CAN_ACCESS --------> [ Resource ]
     |
     +--- (Delegated) ----------> DELEGATES_TO ------> [ Workload B ] ----> CAN_ACCESS --> [ Resource ]
     |
     +--- (Credential-Linked) --> USES_CREDENTIAL ---> [ Credential ] ----> CAN_ACCESS --> [ Resource ]
```

### Provenance Tracking
Every computed permission carries an explicit `AccessProvenance` explaining how the capability was acquired:
1. `Direct`: Directly bound to the entity via policy.
2. `Inherited { from_id }`: Inherited from the owning Principal or Tenant.
3. `Delegated { via_chain }`: Acquired through a transitive chain of `DELEGATES_TO` edges.
4. `CredentialAssociated { credential_id }`: Unlocked via a credential bound to the workload.

---

## 3. Delegation Depth & Attenuation

Unbounded delegation creates severe security risks (e.g. Confused Deputy attacks). BADGER enforces:
1. **Configurable Maximum Delegation Depth** (Default: $D_{\max} = 2$ hops). Any delegation path exceeding $D_{\max}$ triggers an `UnexpectedDelegation` drift alert.
2. **Strict Scope Attenuation**: A delegatee can never possess a broader set of capabilities than the delegator.
3. **Cross-Tenant Prevention**: Delegation paths that cross tenant boundaries are blocked and flagged with `FindingSeverity::Critical`.

---

## 4. Over-Privileged Identity Detection

BADGER continuously compares the **Effective Access Matrix** against **Observed Runtime Telemetry** collected via eBPF tracepoints (`sched_process_exec`, `sys_enter_connect`, `sys_enter_openat`):

```
+-----------------------------------------------------------------------------------+
| Granted Effective Actions:   [ read, write, admin, execute ]                      |
| Observed Telemetry Actions:  [ read ]                                             |
|                                                                                   |
| RESULT: Over-Privileged Finding (High Severity)                                   |
| Unused Actions: [ write, admin, execute ]                                         |
| Recommendation: Revoke unused 'admin' and 'write' actions from agent policy.      |
+-----------------------------------------------------------------------------------+
```

### Actionable Remediation
When an agent is flagged as over-privileged, BADGER generates an `OverPrivilegedFinding` specifying:
- Entity ID and Resource Identifier.
- Exact set of unused high-privilege actions (`admin`, `write`, `delete`).
- Concrete policy modification recommendations to enforce the Principle of Least Privilege.
