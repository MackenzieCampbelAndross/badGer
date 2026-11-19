# BADGER Machine Credential Lifecycle & Cryptographic Intelligence

## 1. Zero Raw Secrets Policy

In modern agentic architectures, workloads frequently require access to sensitive credentials: API keys, OAuth tokens, STS assume-role credentials, and mutual TLS certificates.

**BADGER enforces a strict Zero Raw Secrets invariant:**
- Raw tokens, secret keys, and passwords MUST NEVER be stored in the control-plane database, logged in telemetry streams, or mirrored in memory stores.
- Credential tracking operates exclusively through **Keyed HMAC-SHA256 Fingerprints**.

---

## 2. Keyed HMAC-SHA256 Fingerprinting

To prevent rainbow-table inversion or correlation attacks across tenants while enabling deterministic credential tracking, BADGER computes a keyed HMAC-SHA256 fingerprint:

$$\text{Fingerprint} = \text{SHA-256}(\text{HMAC-SHA256}(K_{\text{tenant}}, \text{RawSecret}))$$

Where:
- $K_{\text{tenant}}$ is a 256-bit secret key uniquely bound to the owning tenant.
- $\text{RawSecret}$ is passed ephemerally during registration solely for fingerprint computation and immediately dropped from memory.

### Fingerprint Guarantees
1. **Irreversibility**: It is computationally infeasible to recover the raw credential from the fingerprint.
2. **Deterministic Matching**: Workloads attempting to use the same credential produce the identical fingerprint within the tenant, allowing instant detection of credential reuse or sharing.
3. **Cross-Tenant Isolation**: The identical raw token presented in Tenant A and Tenant B yields completely distinct fingerprints due to tenant-specific salts $K_{\text{tenant}}$.

---

## 3. SPIFFE Workload Identity Issuance & Lifecycle

BADGER provides a native SPIFFE authority (`SpiffeAuthority`) generating short-lived X.509 SVIDs:

### 3.1 SPIFFE ID Format
Workload identities follow the standard SPIFFE URI scheme:
```
spiffe://<trust-domain>/ns/<tenant>/sa/<principal>/workload/<workload-id>
```
*Example:* `spiffe://badger.local/ns/finance-corp/sa/ledger-agent/workload/wkl_357d4e92`

### 3.2 Kernel Pre-Issuance Attestation
Before generating and signing an X.509 SVID, the authority performs operating-system attestation:
1. Validates that the requesting workload's process ID exists on the host (`kill(pid, 0) == 0`).
2. Validates that the process is confined within the assigned cgroups v2 path (`/sys/fs/cgroup/badger/<workload_id>`).
3. Verifies that the tenant and principal IDs match registered control-plane policies.

### 3.3 Automated Rotation
To eliminate the risk of long-lived key compromise:
- SVIDs are issued with short validity lifetimes (default: 24 hours).
- When an active SVID reaches 50% of its lifetime, `maybe_rotate_svid()` automatically revokes the old serial number and issues a freshly signed certificate.
- Private keys remain secured within the execution boundary and are never exposed across APIs.

### 3.4 Revocation List (CRL)
When a workload terminates, is contained, or triggers an alert:
1. The SVID serial number is published to the `SpiffeCrl`.
2. Any subsequent authorization request presenting the revoked serial number fails immediately with `BadgerError::Identity("Certificate revoked")`.

---

## 4. Credential Intelligence & Drift Detection

The `CredentialIntelligenceStore` continuously tracks:
- **Usage Frequency**: Monotonically increments use counts whenever an agent exercises credential-scoped capabilities.
- **Last Used Timestamp**: Observes inactivity to identify stale or abandoned credentials.
- **Unapproved Credential Sharing**: Detects when multiple distinct workloads utilize the same credential fingerprint without an explicit `DELEGATES_TO` edge connecting them in the identity graph.
- **Expired Token Usage**: Flags active workloads still attempting to authenticate using credentials whose expiration date has passed.
