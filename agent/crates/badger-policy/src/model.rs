use crate::capability::Capability;
use serde::{Deserialize, Serialize};

/// Contextual conditions that must hold for a policy rule to match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "condition_type", content = "spec")]
pub enum ContextCondition {
    ClientIp { cidr: String },
    TimeWindow { valid_from_unix: i64, valid_until_unix: i64 },
    MaxRiskScore { max_score: u8 }, // 0 to 100
    Environment { name: String },   // "production", "staging", "development"
    MfaVerified { required: bool },
}

/// Multi-party approval configuration for high-privilege policy activations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRequirements {
    pub required_approvers: Vec<String>,
    pub min_approvals: u32,
    pub approved_by: Vec<String>,
}

/// Canonical, versioned policy definition in BADGER.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Policy {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub version: u32,
    pub priority: i32, // Higher numbers take precedence
    pub principal_selectors: Vec<String>,
    pub workload_selectors: Vec<String>,
    pub resource_selectors: Vec<String>,
    pub allowed_capabilities: Vec<Capability>,
    pub denied_capabilities: Vec<Capability>,
    pub context_conditions: Vec<ContextCondition>,
    pub approval_requirements: Option<ApprovalRequirements>,
    pub valid_from_unix: i64,
    pub valid_until_unix: i64,
    pub is_staging: bool,
    pub signature: String,
    pub provenance: String,
}

/// Request context submitted for capability authorization evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationContext {
    pub principal: String,
    pub workload: String,
    pub resource: String,
    pub capability: Capability,
    pub client_ip: Option<String>,
    pub timestamp_unix: i64,
    pub environment: String,
    pub risk_score: u8,
    pub mfa_verified: bool,
}

/// Outcome of policy capability evaluation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecisionOutcome {
    Allow,
    Deny,
}

/// Real operating system mechanism backing capability enforcement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnforcementPath {
    Landlock,
    Seccomp,
    EbpfCgroupSocket,
    CgroupsV2,
    CredentialIntelligence,
    Unsupported { reason: String },
}

/// Structured, fully explainable policy authorization decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationDecision {
    pub decision: DecisionOutcome,
    pub policy_id: String,
    pub policy_version: u32,
    pub matched_rule: String,
    pub principal: String,
    pub workload: String,
    pub resource: String,
    pub capability: Capability,
    pub reason: String,
    pub evaluated_at: i64,
    pub enforcement_path: EnforcementPath,
}
