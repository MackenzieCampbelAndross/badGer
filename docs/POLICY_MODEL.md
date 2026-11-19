# BADGER Policy Model & Governance

---

## 1. Specification

BADGER Capability Policies are declarative, versioned specifications that govern the exact operational bounds of an agent or workload.

```json
{
  "id": "pol-strict-v1",
  "tenant_id": "tenant-corp",
  "name": "Strict Autonomous Agent Policy",
  "version": 1,
  "allowed_executables": [
    "/bin/bash",
    "/usr/bin/python3"
  ],
  "denied_executables": [
    "/bin/nc",
    "/usr/bin/ncat"
  ],
  "filesystem_rules": [
    { "path": "/workspace", "access": "rw", "recursive": true },
    { "path": "/etc", "access": "ro", "recursive": true },
    { "path": "/etc/shadow", "access": "none", "recursive": false }
  ],
  "network_rules": [
    { "destination": "127.0.0.1", "port": 8080, "protocol": "tcp", "allow": true },
    { "destination": "*", "port": 0, "protocol": "all", "allow": false }
  ],
  "limits": {
    "max_memory_bytes": 268435456,
    "cpu_quota_us": 100000,
    "cpu_period_us": 100000,
    "max_pids": 32
  },
  "drop_capabilities": [
    "CAP_SYS_ADMIN",
    "CAP_NET_RAW"
  ],
  "disallow_privilege_escalation": true,
  "valid_from_unix": 0,
  "valid_until_unix": 1893456000,
  "signature": "SHA256_HMAC_DIGEST"
}
```

## 2. Evaluation Rules

1. **Explicit Deny Precedence:** Denied executables take absolute precedence over allowlists.
2. **Path Specificity:** When evaluating a filesystem path, the longest matching rule path takes effect. For example, `/etc/shadow` (`access: none`) overrides the parent `/etc` (`access: ro`).
3. **Default Deny:** Any binary, path, or network egress not matching an explicit allow rule is denied.
4. **Signature Verification:** Rejects any policy whose signature does not match the computed digest using the authorized key.
