# BADGER Operations Guide

## 1. Day-2 Operator Procedures

### 1.1 Managing Workloads & Monitoring Health
- Access the Operator Console at `http://<host>:3000` or invoke the REST API `/api/v1/workloads`.
- Sensor Status Indicators:
  - `Protected`: Landlock LSM active, Seccomp active, eBPF tracepoints attached.
  - `Degraded`: Kernel probe dropped or high ring buffer backpressure; fallback procfs polling engaged.
  - `Unprotected`: Workload PID not found or sandbox initialization failed. Immediate containment recommended.

### 1.2 Authentication & RBAC Governance
BADGER enforces role-based access control. All requests must supply a Bearer token:
```bash
curl -H "Authorization: Bearer token-security-admin" http://127.0.0.1:8080/api/v1/containment/actions
```

| Role | Permitted Actions |
|---|---|
| `Platform Administrator` | Wildcard full system configuration, all tenants |
| `Security Administrator` | Containment execution, policy updates, credential revocation |
| `Security Analyst` | Threat finding triage, risk evaluation, simulation |
| `Platform Engineer` | Workload registration, connector maintenance |
| `Auditor` | Read-only access to cryptographic hash-chained audit logs |

### 1.3 Backing Up Audit Trails
The audit trail is cryptographically chained via SHA-256. Dump and verify the trail periodically:
```bash
curl -H "Authorization: Bearer token-auditor" http://127.0.0.1:8080/api/v1/audit > audit_backup.json
```
