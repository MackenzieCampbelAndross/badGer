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
