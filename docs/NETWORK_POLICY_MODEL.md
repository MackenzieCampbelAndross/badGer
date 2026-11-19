# BADGER Network Policy Model Specification

## 1. Policy Structure

Network policies in BADGER are strongly-typed, cryptographically signed data models governing egress and ingress network capabilities:

```json
{
  "id": "pol-net-agent-prod-01",
  "tenant_id": "finance-corp",
  "workload_id": "wkl-ledger-9823",
  "version": 2,
  "default_action": "deny",
  "block_cloud_metadata": true,
  "rules": [
    {
      "rule_id": 101,
      "direction": "egress",
      "destination_cidr": "10.20.0.0/16",
      "min_port": 443,
      "max_port": 443,
      "protocol": "tcp",
      "action": "allow",
      "priority": 100,
      "description": "Internal Core Banking Gateway"
    },
    {
      "rule_id": 102,
      "direction": "egress",
      "destination_cidr": "1.1.1.1/32",
      "min_port": 53,
      "max_port": 53,
      "protocol": "udp",
      "action": "allow",
      "priority": 100,
      "description": "DNS Resolver"
    },
    {
      "rule_id": 103,
      "direction": "egress",
      "destination_cidr": "0.0.0.0/0",
      "min_port": 0,
      "max_port": 65535,
      "protocol": "any",
      "action": "deny",
      "priority": 1000,
      "description": "Catch-all Deny"
    }
  ],
  "valid_from_unix": 1773820800,
  "valid_until_unix": 1773907200,
  "signature": "d38a7b14c6e9f2a0...",
  "issuer": "sec-ops-admin"
}
```

## 2. Field Specifications

| Field | Type | Description |
|---|---|---|
| `id` | String | Globally unique policy identifier |
| `tenant_id` | String | Multi-tenant namespace owner |
| `workload_id` | String | Target autonomous workload boundary |
| `version` | uint32 | Monotonically increasing version counter |
| `default_action` | Enum (`allow`, `deny`) | Action taken when no rule matches (Zero Trust default: `deny`) |
| `block_cloud_metadata` | Boolean | When `true`, automatically rejects `169.254.169.254` and `fd00:ec2::254` |
| `rules` | Array | Ordered collection of `NetworkRule` specifications |
| `valid_from_unix` | int64 | Epoch timestamp before which the policy cannot be used |
| `valid_until_unix` | int64 | Epoch timestamp after which the policy expires |
| `signature` | String | HMAC-SHA256 signature calculated over all policy attributes |
| `issuer` | String | Principal identity that authorized the policy |

## 3. Cryptographic Verification & Anti-Tampering

The policy engine computes an HMAC-SHA256 signature across all canonical attributes:
```rust
let mut hasher = Sha256::new();
hasher.update(policy.id.as_bytes());
hasher.update(policy.tenant_id.as_bytes());
hasher.update(policy.workload_id.as_bytes());
hasher.update(policy.version.to_string().as_bytes());
hasher.update(format!("{:?}", policy.default_action).as_bytes());
hasher.update(policy.block_cloud_metadata.to_string().as_bytes());
for r in &policy.rules {
    hasher.update(r.rule_id.to_string().as_bytes());
    hasher.update(r.destination_cidr.as_bytes());
    hasher.update(r.min_port.to_string().as_bytes());
    hasher.update(r.max_port.to_string().as_bytes());
    hasher.update(format!("{:?}", r.protocol).as_bytes());
    hasher.update(format!("{:?}", r.action).as_bytes());
    hasher.update(r.priority.to_string().as_bytes());
}
hasher.update(policy.valid_from_unix.to_string().as_bytes());
hasher.update(policy.valid_until_unix.to_string().as_bytes());
hasher.update(signing_key.as_bytes());
```

If any field is tampered with, signature verification fails and `load_policy()` rejects the update.

## 4. Rollback and Version Monotonicity

- **Anti-Rollback Protection:** Deploying an older or equal version (e.g. attempting to deploy v1 when v2 is active) is rejected with `BadgerError::PolicyInvalid`.
- **Safe Rollback Stack:** The previous active policy is archived in-memory. Operators can invoke `rollback_policy(workload_id)` to explicitly revert to the previous verified configuration.
- **Offline Disk Cache:** When enabled, verified policies are persisted to `/tmp/badger_network_cache/` or a configured directory. If the control plane is disconnected during agent restart, the engine loads active policies directly from disk.
