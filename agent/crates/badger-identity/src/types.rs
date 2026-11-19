use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identifies the tenant owning identities, workloads, and resources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Type of principal identity in the system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PrincipalType {
    Agent,
    Human,
    ServiceAccount,
    Workload,
    Infrastructure,
}

/// Security principal representing an autonomous agent, service account, or operator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub principal_type: PrincipalType,
    pub labels: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

/// Execution state of a machine workload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkloadState {
    Registered,
    Staging,
    Running,
    Active,
    Suspended,
    Contained,
    Terminated,
    Failed,
    Unknown,
}

/// Health and telemetry capture state of the workload sensor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SensorHealthStatus {
    Protected,
    Degraded,
    Unprotected,
    Unknown,
}

/// Autonomous agent or sandboxed machine workload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Workload {
    pub id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub name: String,
    pub state: WorkloadState,
    pub spiffe_id: String,
    pub cgroup_path: Option<String>,
    pub pid: Option<u32>,
    pub policy_id: String,
    pub policy_version: u32,
    pub metadata: HashMap<String, String>,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sensor_status: SensorHealthStatus,
}

/// Types of credentials used by machine identities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CredentialType {
    ApiKey,
    OAuthToken,
    SpiffeX509Svid,
    AwsStsToken,
    GcpServiceAccountToken,
    K8sServiceAccountToken,
    TlsCertificate,
}

/// Metadata and cryptographic fingerprint of a credential (never stores raw secrets).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    pub id: String,
    pub tenant_id: String,
    pub credential_type: CredentialType,
    pub issuer: String,
    pub audience: String,
    pub scope: Vec<String>,
    /// Keyed HMAC-SHA256 fingerprint of the secret using tenant key. Never stores the secret itself.
    pub fingerprint_hmac_sha256: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub use_count: u64,
    pub associated_principals: Vec<String>,
}

/// Type of target resource accessible in the environment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ResourceType {
    ApiEndpoint,
    Database,
    StorageBucket,
    HostFilesystem,
    NetworkDestination,
    InternalService,
}

/// Target resource accessible by workloads or principals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resource {
    pub id: String,
    pub tenant_id: String,
    pub resource_type: ResourceType,
    pub identifier: String,
    pub labels: HashMap<String, String>,
    pub attributes: HashMap<String, String>,
}

/// A specific capability or action permitted against a resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub id: String,
    pub action: String, // e.g. "read", "write", "execute", "connect", "admin"
    pub resource_id: String,
    pub conditions: HashMap<String, String>,
}

/// Strongly typed relationships in the identity graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum RelationshipType {
    OWNS,
    RUNS_AS,
    USES_CREDENTIAL,
    CAN_ACCESS,
    DELEGATES_TO,
    CONNECTS_TO,
    EXECUTES,
    MANAGED_BY,
    DISCOVERED_FROM,
    AUTHENTICATED_BY,
}

/// Relationship provenance distinguishing direct assertion vs behavioral inference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelationshipKind {
    Direct,
    Inferred,
}

/// An edge in the Identity Graph connecting two entities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Relationship {
    pub id: String,
    pub tenant_id: String,
    pub source_id: String,
    pub target_id: String,
    pub relationship_type: RelationshipType,
    pub kind: RelationshipKind,
    pub confidence: f32, // 0.0 to 1.0
    pub source_attribution: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

/// Source system providing identity telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentitySource {
    LinuxProcFs,
    BadgerSandbox,
    DockerDaemon,
    KubernetesApi,
    StaticConfig,
    SpiffeAuthority,
}

/// Raw identity observation collected by a discovery connector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityObservation {
    pub observation_id: String,
    pub connector_name: String,
    pub source: IdentitySource,
    pub tenant_id: String,
    pub timestamp: DateTime<Utc>,
    pub entity_id: String,
    pub entity_type: String,
    pub raw_attributes: HashMap<String, String>,
    pub confidence: f32,
}

/// Severity level for identity drift and security findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Type of identity drift or vulnerability identified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IdentityFindingType {
    UnownedWorkload,
    CredentialSharing,
    ExpiredCredentialInUse,
    OrphanedServiceAccount,
    UnexpectedDelegation,
    PrivilegeDrift,
    DuplicateIdentity,
    CrossTenantAccessAttempt,
}

/// Structured finding produced by Identity Drift detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityFinding {
    pub id: String,
    pub tenant_id: String,
    pub finding_type: IdentityFindingType,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub entity_id: String,
    pub evidence: HashMap<String, String>,
    pub remediation: String,
    pub detected_at: DateTime<Utc>,
    pub status: String, // "Open", "Remediated", "Suppressed"
}
