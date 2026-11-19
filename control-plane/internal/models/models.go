package models

type WorkloadState string

const (
	StateRegistered WorkloadState = "registered"
	StateStaging    WorkloadState = "staging"
	StateRunning    WorkloadState = "running"
	StateSuspended  WorkloadState = "suspended"
	StateContained  WorkloadState = "contained"
	StateTerminated WorkloadState = "terminated"
	StateFailed     WorkloadState = "failed"
)

type SensorHealthStatus string

const (
	SensorUnknown     SensorHealthStatus = "unknown"
	SensorProtected   SensorHealthStatus = "protected"
	SensorDegraded    SensorHealthStatus = "degraded"
	SensorUnprotected SensorHealthStatus = "unprotected"
)

type Workload struct {
	ID             string             `json:"id"`
	TenantID       string             `json:"tenant_id"`
	PrincipalID    string             `json:"principal_id"`
	Name           string             `json:"name"`
	State          WorkloadState      `json:"state"`
	PolicyID       string             `json:"policy_id"`
	PolicyVersion  int                `json:"policy_version"`
	Metadata       map[string]string  `json:"metadata"`
	RegisteredAt   int64              `json:"registered_at_unix"`
	UpdatedAt      int64              `json:"updated_at_unix"`
	SensorStatus   SensorHealthStatus `json:"sensor_status"`
}

type RuntimeEvent struct {
	EventID            string            `json:"event_id"`
	TimestampUnixNanos int64             `json:"timestamp_unix_nanos"`
	WorkloadID         string            `json:"workload_id"`
	PrincipalID        string            `json:"principal_id"`
	ProcessID          int               `json:"process_id"`
	ParentProcessID    int               `json:"parent_process_id"`
	EventType          string            `json:"event_type"`
	Resource           string            `json:"resource"`
	Outcome            string            `json:"outcome"`
	Severity           string            `json:"severity"`
	SensorProvenance   string            `json:"sensor_provenance"`
	Attributes         map[string]string `json:"attributes"`
}

type SecurityFinding struct {
	FindingID           string            `json:"finding_id"`
	WorkloadID          string            `json:"workload_id"`
	DetectionRule       string            `json:"detection_rule"`
	Severity            string            `json:"severity"`
	Confidence          float32           `json:"confidence"`
	TimestampUnix       int64             `json:"timestamp_unix"`
	Summary             string            `json:"summary"`
	TriggerEventIDs     []string          `json:"trigger_event_ids"`
	RecommendedResponse string            `json:"recommended_response"`
	Evidence            map[string]string `json:"evidence"`
}

type AuditRecord struct {
	RecordID         string `json:"record_id"`
	TimestampUnix    int64  `json:"timestamp_unix"`
	Actor            string `json:"actor"`
	Action           string `json:"action"`
	EntityID         string `json:"entity_id"`
	EntityType       string `json:"entity_type"`
	DetailsJSON      string `json:"details_json"`
	Sha256PrevRecord string `json:"sha256_prev_record"`
	Signature        string `json:"signature"`
}

// -----------------------------------------------------------------------------
// Phase 2: Granular Network Security Models
// -----------------------------------------------------------------------------

type NetworkRuleModel struct {
	RuleID          int    `json:"rule_id"`
	Direction       string `json:"direction"`
	DestinationCIDR string `json:"destination_cidr"`
	MinPort         int    `json:"min_port"`
	MaxPort         int    `json:"max_port"`
	Protocol        string `json:"protocol"`
	Action          string `json:"action"`
	Priority        int    `json:"priority"`
	Description     string `json:"description"`
}

type NetworkPolicyModel struct {
	ID                 string             `json:"id"`
	TenantID           string             `json:"tenant_id"`
	WorkloadID         string             `json:"workload_id"`
	Version            int                `json:"version"`
	DefaultAction      string             `json:"default_action"`
	BlockCloudMetadata bool               `json:"block_cloud_metadata"`
	Rules              []NetworkRuleModel `json:"rules"`
	ValidFromUnix      int64              `json:"valid_from_unix"`
	ValidUntilUnix     int64              `json:"valid_until_unix"`
	Signature          string             `json:"signature"`
	Issuer             string             `json:"issuer"`
}

type NetworkDecisionEventModel struct {
	EventID            string `json:"event_id"`
	TimestampUnixNanos int64  `json:"timestamp_unix_nanos"`
	WorkloadID         string `json:"workload_id"`
	ProcessComm        string `json:"process_comm"`
	Family             string `json:"family"`
	Protocol           string `json:"protocol"`
	DestinationIP      string `json:"destination_ip"`
	DestinationPort    int    `json:"destination_port"`
	Action             string `json:"action"`
	MatchedRuleID      int    `json:"matched_rule_id"`
	Reason             string `json:"reason"`
	Provenance         string `json:"provenance"`
}

type NetworkStatsModel struct {
	TotalConnections   int64 `json:"total_connections"`
	AllowedConnections int64 `json:"allowed_connections"`
	DeniedConnections  int64 `json:"denied_connections"`
	ViolationsCount    int64 `json:"violations_count"`
}

// -----------------------------------------------------------------------------
// Phase 3: Identity Intelligence & Machine Identity Graph Models
// -----------------------------------------------------------------------------

type IdentityNode struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	EntityType string            `json:"entity_type"`
	Label      string            `json:"label"`
	Properties map[string]string `json:"properties"`
}

type RelationshipModel struct {
	ID                 string            `json:"id"`
	TenantID           string            `json:"tenant_id"`
	SourceID           string            `json:"source_id"`
	TargetID           string            `json:"target_id"`
	RelationshipType   string            `json:"relationship_type"`
	Kind               string            `json:"kind"`
	Confidence         float32           `json:"confidence"`
	SourceAttribution  string            `json:"source_attribution"`
	ValidFromUnix      int64             `json:"valid_from_unix"`
	ValidToUnix        int64             `json:"valid_to_unix,omitempty"`
	Metadata           map[string]string `json:"metadata"`
}

type CredentialModel struct {
	ID                   string   `json:"id"`
	TenantID             string   `json:"tenant_id"`
	CredentialType       string   `json:"credential_type"`
	Issuer               string   `json:"issuer"`
	Audience             string   `json:"audience"`
	Scope                []string `json:"scope"`
	FingerprintHmacSha256 string  `json:"fingerprint_hmac_sha256"`
	IssuedAtUnix         int64    `json:"issued_at_unix"`
	ExpiresAtUnix        int64    `json:"expires_at_unix"`
	IsRevoked            bool     `json:"is_revoked"`
	LastUsedAtUnix       int64    `json:"last_used_at_unix"`
	UseCount             int64    `json:"use_count"`
	AssociatedPrincipals []string `json:"associated_principals"`
}

type ResourceModel struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	ResourceType string            `json:"resource_type"`
	Identifier   string            `json:"identifier"`
	Labels       map[string]string `json:"labels"`
}

type EffectivePermissionModel struct {
	EntityID           string `json:"entity_id"`
	ResourceID         string `json:"resource_id"`
	ResourceIdentifier string `json:"resource_identifier"`
	Action             string `json:"action"`
	Provenance         string `json:"provenance"`
	Confidence         int    `json:"confidence"`
}

type IdentityFindingModel struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	FindingType string            `json:"finding_type"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	EntityID    string            `json:"entity_id"`
	Evidence    map[string]string `json:"evidence"`
	Remediation string            `json:"remediation"`
	DetectedAt  int64             `json:"detected_at_unix"`
	Status      string            `json:"status"`
}

type ConnectorStatusModel struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Status      string `json:"status"`
	Details     string `json:"details,omitempty"`
	LastObserved int64 `json:"last_observed_unix"`
}

type IdentityGraphViewModel struct {
	Nodes   []IdentityNode      `json:"nodes"`
	Edges   []RelationshipModel `json:"edges"`
	Summary map[string]int      `json:"summary"`
}

// -----------------------------------------------------------------------------
// Phase 5: Autonomous Containment, Risk & Enterprise Integration Models
// -----------------------------------------------------------------------------

type ResponseActionModel struct {
	ActionID             string `json:"action_id"`
	TenantID             string `json:"tenant_id"`
	InitiatingIdentity   string `json:"initiating_identity"`
	TargetWorkload       string `json:"target_workload"`
	TriggeringFindingID  string `json:"triggering_finding_id"`
	ActionType           string `json:"action_type"`
	LifecycleState       string `json:"lifecycle_state"`
	RequestedAtUnix      int64  `json:"requested_at_unix"`
	CompletedAtUnix      int64  `json:"completed_at_unix,omitempty"`
	Verified             bool   `json:"verified"`
	VerificationEvidence string `json:"verification_evidence"`
	FailureReason        string `json:"failure_reason,omitempty"`
}

type RecoveryRequestModel struct {
	WorkloadID             string `json:"workload_id"`
	TenantID               string `json:"tenant_id"`
	ApprovedBy             string `json:"approved_by"`
	Reason                 string `json:"reason"`
	FindingsAcknowledged   bool   `json:"findings_acknowledged"`
	BaselinePolicyVersion  int    `json:"baseline_policy_version"`
}

type RiskAssessmentModel struct {
	WorkloadID          string            `json:"workload_id"`
	TenantID            string            `json:"tenant_id"`
	RiskScore           int               `json:"risk_score"` // 0 to 100
	Severity            string            `json:"severity"`   // "Low", "Medium", "High", "Critical"
	ContributingFactors []string          `json:"contributing_factors"`
	Evidence            map[string]string `json:"evidence"`
	EvaluatedAtUnix     int64             `json:"evaluated_at_unix"`
}

type IntegrationModel struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Category         string   `json:"category"` // "Runtime", "Orchestration", "Identity", "AgentFramework"
	ConnectionStatus string   `json:"connection_status"` // "Connected", "Available", "Degraded", "Planned"
	AuthMethod       string   `json:"auth_method"`
	PermissionScope  string   `json:"permission_scope"`
	LastSyncUnix     int64    `json:"last_sync_unix"`
	HealthCheck      string   `json:"health_check"`
	Features         []string `json:"features"`
	StatusLevel      string   `json:"status_level"` // "Implemented", "Experimental", "Planned"
}

type OverviewStatsModel struct {
	ActiveWorkloads          int    `json:"active_workloads"`
	ProtectedWorkloads       int    `json:"protected_workloads"`
	DegradedWorkloads        int    `json:"degraded_workloads"`
	UnprotectedWorkloads     int    `json:"unprotected_workloads"`
	ActiveIdentities         int    `json:"active_identities"`
	PolicyViolations         int    `json:"policy_violations"`
	OpenFindings             int    `json:"open_findings"`
	ContainmentActions       int    `json:"containment_actions"`
	SensorHealth             string `json:"sensor_health"`
	NetworkEnforcementStatus string `json:"network_enforcement_status"`
}
