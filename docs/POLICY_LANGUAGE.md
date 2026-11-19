# BADGER Policy Language Specification (v1.0)

## 1. Overview

The BADGER Policy Language defines the declarative syntax for specifying autonomous agent security policies. Policies are versioned, digitally signed, and compile directly to Landlock LSM access vectors, Seccomp BPF filters, and eBPF socket address rules.

---

## 2. Policy Schema Definition

```json
{
  "policy_id": "pol-strict-agent-01",
  "tenant_id": "finance-corp",
  "name": "Strict Financial Agent Confinement",
  "description": "Production confinement policy for ledger reconciliation AI worker",
  "version": 1,
  "priority": 100,
  "target_principals": ["prn:finance:ledger-agent"],
  "target_workloads": ["wkl_finance_*"],
  "target_resources": ["res_ledger_*"],
  "allowed_capabilities": [
    {
      "type": "FsRead",
      "path": "/workspace",
      "recursive": true
    },
    {
      "type": "FsWrite",
      "path": "/workspace/output",
      "allow_create": true,
      "allow_truncate": false
    },
    {
      "type": "NetConnect",
      "destination": "10.0.4.0/24",
      "port": 443,
      "protocol": "TCP"
    }
  ],
  "denied_capabilities": [
    {
      "type": "FsRead",
      "path": "/etc/shadow",
      "recursive": false
    },
    {
      "type": "ProcessExec",
      "binary": "/bin/bash",
      "args": ["-c", "*"]
    },
    {
      "type": "NetConnect",
      "destination": "169.254.169.254",
      "port": 80,
      "protocol": "TCP"
    }
  ],
  "context_conditions": [
    {
      "condition_type": "MaxRiskScore",
      "operator": "LessThan",
      "value": "60"
    },
    {
      "condition_type": "Environment",
      "operator": "Equals",
      "value": "production"
    }
  ],
  "approval_requirements": {
    "required_approvers": ["prn:sec:security-admin"],
    "minimum_approvals": 1,
    "timeout_seconds": 1800
  },
  "valid_from_unix": 1773900000,
  "valid_until_unix": 1805436000,
  "signature": "hmac-sha256:d489b1c7a8...",
  "issuer": "badger-control-plane-authority"
}
```

---

## 3. Selector Matching & Compiler Optimization

- **Regex Cache**: Selectors are compiled into regex matchers cached in an indexed LRU table.
- **Conflict Detection**: The compiler checks for semantic contradictions between `allowed_capabilities` and `denied_capabilities`.
- **Enforcement Mapping**: The compiler queries the OS kernel capabilities and marks capabilities as enforced by Landlock, Seccomp, eBPF, or returns `Unsupported` when an action cannot be kernel-enforced in a sandbox (e.g. `ContainerManage`).
