package events

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/badger-security/badger/control-plane/internal/models"
)

type Service struct {
	mu        sync.RWMutex
	events    []*models.RuntimeEvent
	findings  []*models.SecurityFinding
	auditLogs []*models.AuditRecord
	prevHash  string
}

func NewService() *Service {
	return &Service{
		events:    make([]*models.RuntimeEvent, 0),
		findings:  make([]*models.SecurityFinding, 0),
		auditLogs: make([]*models.AuditRecord, 0),
		prevHash:  "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

func (s *Service) IngestEvent(evt *models.RuntimeEvent) (*models.SecurityFinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, evt)

	// Threat Detection Evaluation
	var finding *models.SecurityFinding

	if evt.Outcome == "blocked" {
		b := make([]byte, 8)
		rand.Read(b)
		fndID := fmt.Sprintf("fnd_%s", hex.EncodeToString(b))

		rule := "DET-GEN-001"
		summary := fmt.Sprintf("Blocked %s on resource %s", evt.EventType, evt.Resource)

		if evt.EventType == "file_open" || evt.EventType == "file_write" {
			rule = "DET-FS-001"
			summary = fmt.Sprintf("Unauthorized filesystem access attempt to %s", evt.Resource)
		} else if evt.EventType == "net_connect" {
			rule = "DET-NET-002"
			summary = fmt.Sprintf("Unauthorized outbound network connection to %s", evt.Resource)
		} else if evt.EventType == "process_exec" {
			rule = "DET-PROC-003"
			summary = fmt.Sprintf("Prohibited binary execution attempt: %s", evt.Resource)
		}

		finding = &models.SecurityFinding{
			FindingID:           fndID,
			WorkloadID:          evt.WorkloadID,
			DetectionRule:       rule,
			Severity:            evt.Severity,
			Confidence:          1.0,
			TimestampUnix:       time.Now().Unix(),
			Summary:             summary,
			TriggerEventIDs:     []string{evt.EventID},
			RecommendedResponse: "Enforce containment boundary and inspect agent activity",
			Evidence: map[string]string{
				"resource":   evt.Resource,
				"outcome":    evt.Outcome,
				"provenance": evt.SensorProvenance,
			},
		}

		s.findings = append(s.findings, finding)
	}

	// Record to tamper-evident audit log
	b := make([]byte, 8)
	rand.Read(b)
	recID := fmt.Sprintf("rec_%s", hex.EncodeToString(b))
	now := time.Now().Unix()

	h := sha256.New()
	h.Write([]byte(recID))
	h.Write([]byte(fmt.Sprintf("%d", now)))
	h.Write([]byte(evt.WorkloadID))
	h.Write([]byte(evt.EventType))
	h.Write([]byte(s.prevHash))
	sig := hex.EncodeToString(h.Sum(nil))

	audit := &models.AuditRecord{
		RecordID:         recID,
		TimestampUnix:    now,
		Actor:            "badger-sensor",
		Action:           fmt.Sprintf("ingest_%s", evt.EventType),
		EntityID:         evt.WorkloadID,
		EntityType:       "event",
		DetailsJSON:      fmt.Sprintf(`{"resource":"%s","outcome":"%s"}`, evt.Resource, evt.Outcome),
		Sha256PrevRecord: s.prevHash,
		Signature:        sig,
	}

	s.auditLogs = append(s.auditLogs, audit)
	s.prevHash = sig

	return finding, nil
}

func (s *Service) ListEvents(limit int) []*models.RuntimeEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.events) {
		limit = len(s.events)
	}
	start := len(s.events) - limit
	return s.events[start:]
}

func (s *Service) ListEventsForWorkloads(limit int, workloadIDs map[string]bool) []*models.RuntimeEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]*models.RuntimeEvent, 0)
	for _, e := range s.events {
		if workloadIDs[e.WorkloadID] {
			res = append(res, e)
		}
	}
	if limit > 0 && len(res) > limit {
		res = res[len(res)-limit:]
	}
	return res
}

func (s *Service) ListFindings() []*models.SecurityFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findings
}

func (s *Service) ListFindingsForWorkloads(workloadIDs map[string]bool) []*models.SecurityFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]*models.SecurityFinding, 0)
	for _, f := range s.findings {
		if workloadIDs[f.WorkloadID] {
			res = append(res, f)
		}
	}
	return res
}

func (s *Service) ListAuditRecords() []*models.AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auditLogs
}

func (s *Service) ListAuditRecordsForWorkloads(workloadIDs map[string]bool) []*models.AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]*models.AuditRecord, 0)
	for _, a := range s.auditLogs {
		if workloadIDs[a.EntityID] {
			res = append(res, a)
		}
	}
	return res
}
