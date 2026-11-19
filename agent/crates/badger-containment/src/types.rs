use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The 10 verifiable containment and response action types supported by BADGER.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ResponseActionType {
    SuspendWorkload,
    FreezeCgroup,
    KillProcess,
    IsolateNetwork,
    RevokeCredentials,
    RestrictPolicy,
    CollectEvidence,
    QuarantineWorkload,
    ControlledRecovery,
    ManualApproval,
}

/// The explicit 10-stage lifecycle state of a response action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecycleState {
    FindingReceived,
    FindingValidated,
    RiskEvaluated,
    ResponseSelected,
    ApprovalEvaluated,
    ResponseExecuted,
    OutcomeVerified,
    EvidenceRecorded,
    AuditPersisted,
    RecoveryEvaluated,
    Failed { reason: String },
}

/// Execution mode of a response policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseMode {
    Automatic,
    HumanApprovalRequired,
    NotificationOnly,
    ManualOnly,
}

/// Policy rule defining how BADGER responds to a threat finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponsePolicyRule {
    pub rule_id: String,
    pub tenant_id: String,
    pub min_severity: String, // "Low", "Medium", "High", "Critical"
    pub min_confidence: f32,  // 0.0 to 1.0 (prevents low-confidence automated destruction)
    pub mode: ResponseMode,
    pub actions: Vec<ResponseActionType>,
    pub break_glass_enabled: bool,
}

/// Comprehensive, auditable record of an executed response action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseExecutionRecord {
    pub action_id: String,
    pub tenant_id: String,
    pub initiating_identity: String,
    pub target_workload: String,
    pub triggering_finding_id: String,
    pub action_type: ResponseActionType,
    pub lifecycle_state: LifecycleState,
    pub requested_at_unix: i64,
    pub completed_at_unix: Option<i64>,
    pub verified: bool,
    pub verification_evidence: String,
    pub rollback_status: Option<String>,
    pub failure_reason: Option<String>,
}

/// Non-invasive, bounded evidence package collected during an incident.
/// Strictly omits raw file contents and private credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidencePackage {
    pub evidence_id: String,
    pub workload_id: String,
    pub tenant_id: String,
    pub collected_at: DateTime<Utc>,
    pub process_metadata: HashMap<String, String>,
    pub network_summary: HashMap<String, String>,
    pub recent_events_count: usize,
    pub sensor_status: String,
    pub policy_version: u32,
    pub findings_count: usize,
}

/// Explainable, deterministic risk evaluation for a workload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskAssessment {
    pub workload_id: String,
    pub risk_score: u8, // 0 to 100
    pub severity: String,
    pub contributing_factors: Vec<String>,
    pub evidence: HashMap<String, String>,
    pub evaluated_at: DateTime<Utc>,
}
