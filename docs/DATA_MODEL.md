# BADGER Data Model Specification

---

## 1. Core Entity Types

1. **Tenant:**
   - `id: string` (e.g. `tenant-enterprise-prod`)
   - `name: string`
   - `created_at: DateTime<Utc>`

2. **Principal:**
   - `id: string` (e.g. `prn:tenant-1:uuid`)
   - `tenant_id: string`
   - `name: string`
   - `principal_type: PrincipalType` (`Agent`, `McpServer`, `ServiceAccount`, `HumanOperator`, `CiWorkflow`)
   - `labels: map<string, string>`

3. **Workload:**
   - `id: string` (e.g. `wkl_69b6f01e`)
   - `tenant_id: string`
   - `principal_id: string`
   - `name: string`
   - `state: WorkloadState` (`Registered`, `Staging`, `Running`, `Suspended`, `Contained`, `Terminated`, `Failed`)
   - `policy_id: string`
   - `policy_version: u32`
   - `metadata: map<string, string>` (includes `spiffe_id`)
   - `sensor_status: SensorHealthStatus` (`Protected`, `Degraded`, `Unprotected`, `Unknown`)

4. **Credential Metadata:**
   - `id: string`
   - `tenant_id: string`
   - `workload_id: string`
   - `credential_type: string`
   - `issuer: string`
   - `audience: string`
   - `fingerprint_sha256: string` (64-character hex digest)
   - `is_revoked: bool`

5. **Security Finding:**
   - `finding_id: string`
   - `workload_id: string`
   - `detection_rule: string`
   - `severity: Severity` (`Informational`, `Low`, `Medium`, `High`, `Critical`)
   - `confidence: float32` (0.0 - 1.0)
   - `summary: string`
   - `recommended_response: string`
   - `evidence: map<string, string>`

6. **Audit Record:**
   - `record_id: string`
   - `timestamp_unix: i64`
   - `actor: string`
   - `action: string`
   - `entity_id: string`
   - `entity_type: string`
   - `details_json: string`
   - `sha256_prev_record: string`
   - `signature: string`
