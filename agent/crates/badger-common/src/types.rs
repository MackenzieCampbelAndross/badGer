use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    Agent,
    McpServer,
    ServiceAccount,
    HumanOperator,
    CiWorkflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadState {
    Registered,
    Staging,
    Running,
    Suspended,
    Contained,
    Terminated,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorHealthStatus {
    Unknown,
    Protected,
    Degraded,
    Unprotected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub principal_type: PrincipalType,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workload {
    pub id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub name: String,
    pub state: WorkloadState,
    pub policy_id: String,
    pub policy_version: u32,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sensor_status: SensorHealthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub id: String,
    pub tenant_id: String,
    pub workload_id: String,
    pub credential_type: String,
    pub issuer: String,
    pub audience: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_revoked: bool,
    pub fingerprint_sha256: String,
}

// -----------------------------------------------------------------------------
// Capability & Policy Types
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FsAccess {
    Ro,
    Rw,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesystemRule {
    pub path: String,
    pub access: FsAccess,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkRule {
    pub destination: String,
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub allow: bool,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_memory_bytes: u64,
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub max_pids: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024, // 256MB default
            cpu_quota_us: 100_000,
            cpu_period_us: 100_000,
            max_pids: 32,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityPolicy {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub version: u32,
    #[serde(default)]
    pub allowed_executables: Vec<String>,
    #[serde(default)]
    pub denied_executables: Vec<String>,
    #[serde(default)]
    pub filesystem_rules: Vec<FilesystemRule>,
    #[serde(default)]
    pub network_rules: Vec<NetworkRule>,
    #[serde(default)]
    pub limits: ResourceLimits,
    #[serde(default)]
    pub drop_capabilities: Vec<String>,
    #[serde(default = "default_true")]
    pub disallow_privilege_escalation: bool,
    pub valid_from_unix: i64,
    pub valid_until_unix: i64,
    #[serde(default)]
    pub signature: String,
}

fn default_true() -> bool {
    true
}

// -----------------------------------------------------------------------------
// Runtime Events & Telemetry Types
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ProcessExec,
    ProcessExit,
    FileOpen,
    FileWrite,
    NetConnect,
    PrivilegeChange,
    SyscallBlocked,
    PolicyViolation,
    SensorStatusChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementOutcome {
    Allowed,
    Blocked,
    Audited,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub timestamp_unix_nanos: i64,
    pub workload_id: String,
    pub principal_id: String,
    pub process_id: u32,
    pub parent_process_id: u32,
    pub event_type: EventType,
    pub resource: String,
    pub outcome: EnforcementOutcome,
    pub severity: Severity,
    pub sensor_provenance: String,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

// -----------------------------------------------------------------------------
// Threat Detection Types
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub finding_id: String,
    pub workload_id: String,
    pub detection_rule: String,
    pub severity: Severity,
    pub confidence: f32,
    pub timestamp_unix: i64,
    pub summary: String,
    #[serde(default)]
    pub trigger_event_ids: Vec<String>,
    pub recommended_response: String,
    #[serde(default)]
    pub evidence: HashMap<String, String>,
}

// -----------------------------------------------------------------------------
// Containment & Audit Types
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionType {
    SuspendWorkload,
    RestrictNetwork,
    KillProcess,
    TerminateWorkload,
    RevokeCredential,
    CollectEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub action_id: String,
    pub workload_id: String,
    pub finding_id: String,
    pub action_type: ResponseActionType,
    pub requested_at_unix: i64,
    pub completed_at_unix: Option<i64>,
    pub verified: bool,
    pub verification_evidence: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub record_id: String,
    pub timestamp_unix: i64,
    pub actor: String,
    pub action: String,
    pub entity_id: String,
    pub entity_type: String,
    pub details_json: String,
    pub sha256_prev_record: String,
    pub signature: String,
}
