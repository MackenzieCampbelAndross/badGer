# Agent-to-Agent Delegation Security

## 1. The Autonomous Delegation Problem

Modern agentic architectures frequently employ multi-agent workflows where a primary coordinator agent delegates subtasks to specialized subagents.

Without strict containment boundaries, malicious or hallucinating subagents could acquire privileges exceeding the parent agent, resulting in privilege escalation.

---

## 2. Delegation Invariants in BADGER

BADGER enforces three mathematical guarantees for all autonomous delegations:

### Invariant 1: Monotonic Non-Expansion (Intersection Rule)
A parent agent $A_{parent}$ with capability set $C_{parent}$ delegating task capabilities $C_{child}$ to subagent $A_{child}$ can NEVER grant privileges beyond $C_{parent}$:
$$C_{granted} = C_{parent} \cap C_{child}$$

If $C_{child} \setminus C_{parent} \neq \emptyset$, the excess capabilities are stripped, and a security warning is audited.

### Invariant 2: Maximum Delegation Depth
To prevent unbounded recursion or delegation chain obfuscation, every delegation record specifies `delegation_depth` and enforces a hard system ceiling `MAX_DELEGATION_DEPTH` (default 5).

### Invariant 3: Provenance & Revocation Propagation
Every child capability carries a cryptographic provenance chain linking back to the root principal. If the parent's credentials or policy are restricted or revoked, all descendant delegated capabilities are immediately invalidated.
