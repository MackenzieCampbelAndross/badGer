package events_test

import (
	"testing"
	"time"

	"github.com/badger-security/badger/control-plane/internal/events"
	"github.com/badger-security/badger/control-plane/internal/models"
)

func TestEventIngestionAndFindingGeneration(t *testing.T) {
	svc := events.NewService()

	blockedEvt := &models.RuntimeEvent{
		EventID:            "evt-test-1",
		TimestampUnixNanos: time.Now().UnixNano(),
		WorkloadID:         "wkl-101",
		PrincipalID:        "prn-1",
		ProcessID:          1234,
		ParentProcessID:    1,
		EventType:          "file_open",
		Resource:           "/etc/shadow",
		Outcome:            "blocked",
		Severity:           "high",
		SensorProvenance:   "landlock-lsm",
	}

	finding, err := svc.IngestEvent(blockedEvt)
	if err != nil {
		t.Fatalf("unexpected error ingesting event: %v", err)
	}

	if finding == nil {
		t.Fatalf("expected security finding for blocked event, got nil")
	}

	if finding.DetectionRule != "DET-FS-001" {
		t.Errorf("expected detection rule DET-FS-001, got %s", finding.DetectionRule)
	}

	auditLogs := svc.ListAuditRecords()
	if len(auditLogs) != 1 {
		t.Errorf("expected 1 audit record, got %d", len(auditLogs))
	}
}
