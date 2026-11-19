package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/badger-security/badger/control-plane/internal/auth"
	"github.com/badger-security/badger/control-plane/internal/containment"
	"github.com/badger-security/badger/control-plane/internal/events"
	"github.com/badger-security/badger/control-plane/internal/identity"
	"github.com/badger-security/badger/control-plane/internal/models"
	"github.com/badger-security/badger/control-plane/internal/network"
)

func setupTestServer() *Server {
	identitySvc := identity.NewService()
	eventsSvc := events.NewService()
	networkSvc := network.NewService()
	containmentSvc := containment.NewService()
	tokenMgr := auth.NewTokenManager("test-secret-2026")

	// Pre-register workloads for finance and dev tenants
	identitySvc.RegisterWorkload("finance-corp", "prn:finance:agent", "finance-workload", "pol-fin", 1)
	identitySvc.RegisterWorkload("dev-team", "prn:dev:agent", "dev-workload", "pol-dev", 1)

	return &Server{
		identitySvc:    identitySvc,
		eventsSvc:      eventsSvc,
		networkSvc:     networkSvc,
		containmentSvc: containmentSvc,
		tokenMgr:       tokenMgr,
	}
}

func TestUnauthenticatedRequestRejected(t *testing.T) {
	server := setupTestServer()
	handler := server.authMiddleware(server.handleWorkloads)

	req := httptest.NewRequest("GET", "/api/v1/workloads", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized, got %d", w.Code)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	server := setupTestServer()
	// Issue an expired token (-1 hour)
	server.tokenMgr.IssueToken("token-expired", "finance-corp", "prn:finance:agent", auth.RoleAgent, -1*time.Hour)

	handler := server.authMiddleware(server.handleWorkloads)

	req := httptest.NewRequest("GET", "/api/v1/workloads", nil)
	req.Header.Set("Authorization", "Bearer token-expired")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized for expired token, got %d", w.Code)
	}
}

func TestRevokedTokenRejected(t *testing.T) {
	server := setupTestServer()
	server.tokenMgr.IssueToken("token-to-revoke", "finance-corp", "prn:finance:agent", auth.RoleAgent, 1*time.Hour)
	if err := server.tokenMgr.RevokeToken("token-to-revoke"); err != nil {
		t.Fatalf("failed to revoke token: %v", err)
	}

	handler := server.authMiddleware(server.handleWorkloads)

	req := httptest.NewRequest("GET", "/api/v1/workloads", nil)
	req.Header.Set("Authorization", "Bearer token-to-revoke")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized for revoked token, got %d", w.Code)
	}
}

func TestInvalidOrGarbageTokenRejected(t *testing.T) {
	server := setupTestServer()
	handler := server.authMiddleware(server.handleWorkloads)

	testCases := []string{
		"Bearer invalid-garbage-token",
		"Bearer ",
		"Basic dXNlcjpwYXNz",
		"token-without-scheme",
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", "/api/v1/workloads", nil)
		req.Header.Set("Authorization", tc)
		w := httptest.NewRecorder()

		handler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("header %q: expected 401 Unauthorized, got %d", tc, w.Code)
		}
	}
}

func TestTenantScopedWorkloadListing(t *testing.T) {
	server := setupTestServer()
	handler := server.authMiddleware(server.handleWorkloads)

	// Call as finance-corp agent
	req := httptest.NewRequest("GET", "/api/v1/workloads", nil)
	req.Header.Set("Authorization", "Bearer token-finance-agent")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", w.Code)
	}

	var workloads []*models.Workload
	if err := json.NewDecoder(w.Body).Decode(&workloads); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload for finance-corp, got %d", len(workloads))
	}
	if workloads[0].TenantID != "finance-corp" {
		t.Errorf("expected tenant finance-corp, got %s", workloads[0].TenantID)
	}
}

func TestCrossTenantWorkloadDetailForbidden(t *testing.T) {
	server := setupTestServer()
	handler := server.authMiddleware(server.handleWorkloadByID)

	// Get dev-team workload ID
	devWorkloads := server.identitySvc.ListWorkloadsByTenant("dev-team")
	if len(devWorkloads) == 0 {
		t.Fatalf("expected dev-team workload")
	}
	devWorkloadID := devWorkloads[0].ID

	// Attempt to access dev-team workload using finance-corp token
	req := httptest.NewRequest("GET", "/api/v1/workloads/"+devWorkloadID, nil)
	req.Header.Set("Authorization", "Bearer token-finance-agent") // finance token!
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant workload GET, got %d", w.Code)
	}
}

func TestUnauthorizedCrossTenantEventIngestionBlocked(t *testing.T) {
	server := setupTestServer()
	handler := server.authMiddleware(server.handleEvents)

	// Find the dev-team workload ID
	devWorkloads := server.identitySvc.ListWorkloadsByTenant("dev-team")
	if len(devWorkloads) == 0 {
		t.Fatalf("expected dev-team workload")
	}
	devWorkloadID := devWorkloads[0].ID

	// Attempt to forge an event for dev-team using finance-corp token
	fakeEvent := models.RuntimeEvent{
		EventID:          "evt-forged",
		WorkloadID:       devWorkloadID, // Belongs to dev-team!
		EventType:        "file_open",
		Resource:         "/etc/shadow",
		Outcome:          "blocked",
		Severity:         "critical",
		SensorProvenance: "forged",
	}
	body, _ := json.Marshal(fakeEvent)

	req := httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer token-finance-agent") // finance-corp token!
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant event ingestion, got %d", w.Code)
	}
}

func TestCrossTenantFindingsAndAuditIsolation(t *testing.T) {
	server := setupTestServer()

	// 1. Ingest valid event for dev-team
	devWorkloads := server.identitySvc.ListWorkloadsByTenant("dev-team")
	devWorkloadID := devWorkloads[0].ID

	devEvent := &models.RuntimeEvent{
		EventID:          "evt-dev-100",
		WorkloadID:       devWorkloadID,
		EventType:        "file_open",
		Resource:         "/etc/shadow",
		Outcome:          "blocked",
		Severity:         "critical",
		SensorProvenance: "landlock-lsm",
	}
	_, err := server.eventsSvc.IngestEvent(devEvent)
	if err != nil {
		t.Fatalf("failed to ingest dev event: %v", err)
	}

	// 2. Query findings as finance-corp agent
	fHandler := server.authMiddleware(server.handleFindings)
	reqF := httptest.NewRequest("GET", "/api/v1/findings", nil)
	reqF.Header.Set("Authorization", "Bearer token-finance-agent")
	wF := httptest.NewRecorder()
	fHandler(wF, reqF)

	if wF.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", wF.Code)
	}
	var findings []*models.SecurityFinding
	json.NewDecoder(wF.Body).Decode(&findings)
	if len(findings) != 0 {
		t.Fatalf("finance-corp should see 0 findings from dev-team, got %d", len(findings))
	}

	// 3. Query audit trail as finance-corp agent
	aHandler := server.authMiddleware(server.handleAudit)
	reqA := httptest.NewRequest("GET", "/api/v1/audit", nil)
	reqA.Header.Set("Authorization", "Bearer token-finance-agent")
	wA := httptest.NewRecorder()
	aHandler(wA, reqA)

	if wA.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", wA.Code)
	}
	var audit []*models.AuditRecord
	json.NewDecoder(wA.Body).Decode(&audit)
	if len(audit) != 0 {
		t.Fatalf("finance-corp should see 0 audit records from dev-team, got %d", len(audit))
	}
}

func TestMaxRequestBodySizeExceeded(t *testing.T) {
	server := setupTestServer()
	handler := server.authMiddleware(server.handleEvents)

	// Create body > 1MB (1,048,576 bytes)
	hugeBody := strings.Repeat("A", 1048576+100)
	req := httptest.NewRequest("POST", "/api/v1/events", strings.NewReader(hugeBody))
	req.Header.Set("Authorization", "Bearer token-finance-agent")
	w := httptest.NewRecorder()

	handler(w, req)

	// MaxBytesReader causes json.Decode to fail with error
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on oversized body (>1MB), got %d", w.Code)
	}
}

func TestContainmentActionsAndRecovery(t *testing.T) {
	server := setupTestServer()
	workloads := server.identitySvc.ListWorkloadsByTenant("finance-corp")
	if len(workloads) == 0 {
		t.Fatal("expected pre-registered workload for finance-corp")
	}
	wklID := workloads[0].ID

	// 1. Issue SecAdmin token
	server.tokenMgr.IssueToken("token-secadmin", "finance-corp", "prn:sec:admin", auth.RoleSecurityAdmin, 1*time.Hour)

	// 2. Trigger containment action
	actHandler := server.authMiddleware(server.handleContainmentActions)
	reqBody, _ := json.Marshal(map[string]string{
		"workload_id": wklID,
		"finding_id":  "find-001",
		"action_type": "SuspendWorkload",
	})
	req := httptest.NewRequest("POST", "/api/v1/containment/actions", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer token-secadmin")
	w := httptest.NewRecorder()
	actHandler(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on containment execution, got %d: %s", w.Code, w.Body.String())
	}

	var act models.ResponseActionModel
	json.NewDecoder(w.Body).Decode(&act)
	if act.ActionType != "SuspendWorkload" || !act.Verified {
		t.Fatalf("unexpected action result: %+v", act)
	}

	// 3. Trigger recovery
	recHandler := server.authMiddleware(server.handleContainmentRecover)
	recBody, _ := json.Marshal(map[string]interface{}{
		"workload_id":             wklID,
		"reason":                  "False positive cleared by secops",
		"findings_acknowledged":   true,
		"baseline_policy_version": 1,
	})
	reqRec := httptest.NewRequest("POST", "/api/v1/containment/recover", bytes.NewReader(recBody))
	reqRec.Header.Set("Authorization", "Bearer token-secadmin")
	wRec := httptest.NewRecorder()
	recHandler(wRec, reqRec)

	if wRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on recovery, got %d: %s", wRec.Code, wRec.Body.String())
	}
}

func TestOverviewAndIntegrations(t *testing.T) {
	server := setupTestServer()

	// 1. Overview check
	overviewHandler := server.authMiddleware(server.handleOverview)
	req := httptest.NewRequest("GET", "/api/v1/overview", nil)
	req.Header.Set("Authorization", "Bearer token-platform-admin")
	w := httptest.NewRecorder()
	overviewHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on overview, got %d", w.Code)
	}

	var stats models.OverviewStatsModel
	json.NewDecoder(w.Body).Decode(&stats)
	if stats.ActiveWorkloads < 2 {
		t.Fatalf("expected at least 2 active workloads, got %d", stats.ActiveWorkloads)
	}

	// 2. Integrations check
	integHandler := server.authMiddleware(server.handleIntegrations)
	reqInteg := httptest.NewRequest("GET", "/api/v1/integrations", nil)
	reqInteg.Header.Set("Authorization", "Bearer token-platform-admin")
	wInteg := httptest.NewRecorder()
	integHandler(wInteg, reqInteg)

	if wInteg.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on integrations, got %d", wInteg.Code)
	}

	var integRes struct {
		Integrations []models.IntegrationModel `json:"integrations"`
		Total        int                       `json:"total"`
	}
	json.NewDecoder(wInteg.Body).Decode(&integRes)
	if integRes.Total < 7 {
		t.Fatalf("expected at least 7 enterprise integrations, got %d", integRes.Total)
	}
}
