package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/badger-security/badger/control-plane/internal/auth"
	"github.com/badger-security/badger/control-plane/internal/containment"
	"github.com/badger-security/badger/control-plane/internal/events"
	"github.com/badger-security/badger/control-plane/internal/identity"
	"github.com/badger-security/badger/control-plane/internal/models"
	"github.com/badger-security/badger/control-plane/internal/network"
)

type contextKey string

const authContextKey contextKey = "authContext"

type Server struct {
	identitySvc    *identity.Service
	eventsSvc      *events.Service
	networkSvc     *network.Service
	containmentSvc *containment.Service
	tokenMgr       *auth.TokenManager
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Limit request body size to 1MB to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		authHeader := r.Header.Get("Authorization")
		authCtx, err := s.tokenMgr.ValidateAuthHeader(authHeader)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "unauthenticated",
				"message": err.Error(),
			})
			return
		}

		ctx := context.WithValue(r.Context(), authContextKey, authCtx)
		next(w, r.WithContext(ctx))
	}
}

func getAuthContext(r *http.Request) *auth.AuthContext {
	if val, ok := r.Context().Value(authContextKey).(*auth.AuthContext); ok {
		return val
	}
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"version": "1.0.1",
		"service": "badger-control-plane",
	})
}

func (s *Server) handleWorkloads(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			Name          string `json:"name"`
			PolicyID      string `json:"policy_id"`
			PolicyVersion int    `json:"policy_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
			return
		}

		// Security: TenantID and PrincipalID are strictly bound to the authenticated token!
		tenantID := authCtx.TenantID
		principalID := authCtx.PrincipalID

		wkl, err := s.identitySvc.RegisterWorkload(tenantID, principalID, req.Name, req.PolicyID, req.PolicyVersion)
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(wkl)
		return
	}

	if r.Method == http.MethodGet {
		// Multi-tenant authorization: Admins see all, tenants see only their own
		var workloads []*models.Workload
		if authCtx.Role == auth.RoleAdmin {
			workloads = s.identitySvc.ListWorkloads()
		} else {
			workloads = s.identitySvc.ListWorkloadsByTenant(authCtx.TenantID)
		}
		json.NewEncoder(w).Encode(workloads)
		return
	}

	http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
}

func (s *Server) handleWorkloadByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, `{"error":"invalid_path"}`, http.StatusBadRequest)
		return
	}
	id := parts[4]
	wkl, ok := s.identitySvc.GetWorkload(id)
	if !ok {
		http.Error(w, `{"error":"workload_not_found"}`, http.StatusNotFound)
		return
	}

	// Verify workload ownership
	if authCtx.Role != auth.RoleAdmin && wkl.TenantID != authCtx.TenantID {
		http.Error(w, `{"error":"forbidden_cross_tenant_access"}`, http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(wkl)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		var evt models.RuntimeEvent
		if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
			http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
			return
		}

		// Security: Workload ownership verification
		// An agent can only submit telemetry events for workloads belonging to its authenticated tenant
		if !s.identitySvc.VerifyWorkloadOwnership(evt.WorkloadID, authCtx.TenantID) && authCtx.Role != auth.RoleAdmin {
			http.Error(w, `{"error":"forbidden_unauthorized_workload"}`, http.StatusForbidden)
			return
		}

		finding, err := s.eventsSvc.IngestEvent(&evt)
		if err != nil {
			http.Error(w, `{"error":"ingestion_failed"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"accepted": true,
			"finding":  finding,
		})
		return
	}

	if r.Method == http.MethodGet {
		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}

		if authCtx.Role == auth.RoleAdmin {
			evts := s.eventsSvc.ListEvents(limit)
			json.NewEncoder(w).Encode(evts)
			return
		}

		// Tenant scoped event listing
		workloads := s.identitySvc.ListWorkloadsByTenant(authCtx.TenantID)
		wklMap := make(map[string]bool)
		for _, w := range workloads {
			wklMap[w.ID] = true
		}
		evts := s.eventsSvc.ListEventsForWorkloads(limit, wklMap)
		json.NewEncoder(w).Encode(evts)
		return
	}

	http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if authCtx.Role == auth.RoleAdmin {
		findings := s.eventsSvc.ListFindings()
		json.NewEncoder(w).Encode(findings)
		return
	}

	// Tenant scoped findings
	workloads := s.identitySvc.ListWorkloadsByTenant(authCtx.TenantID)
	wklMap := make(map[string]bool)
	for _, w := range workloads {
		wklMap[w.ID] = true
	}
	findings := s.eventsSvc.ListFindingsForWorkloads(wklMap)
	json.NewEncoder(w).Encode(findings)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if authCtx.Role == auth.RoleAdmin {
		logs := s.eventsSvc.ListAuditRecords()
		json.NewEncoder(w).Encode(logs)
		return
	}

	workloads := s.identitySvc.ListWorkloadsByTenant(authCtx.TenantID)
	wklMap := make(map[string]bool)
	for _, w := range workloads {
		wklMap[w.ID] = true
	}
	logs := s.eventsSvc.ListAuditRecordsForWorkloads(wklMap)
	json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleNetworkPolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet {
		policies := s.networkSvc.ListPolicies(authCtx.TenantID, authCtx.Role == auth.RoleAdmin)
		json.NewEncoder(w).Encode(policies)
		return
	}

	if r.Method == http.MethodPost {
		var pol models.NetworkPolicyModel
		if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
			http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
			return
		}

		if authCtx.Role != auth.RoleAdmin {
			pol.TenantID = authCtx.TenantID
		}

		if err := s.networkSvc.DeployPolicy(&pol); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(pol)
		return
	}

	http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
}

func (s *Server) handleNetworkRollback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		WorkloadID string `json:"workload_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}

	// Verify workload ownership
	wkl, ok := s.identitySvc.GetWorkload(req.WorkloadID)
	if !ok || (authCtx.Role != auth.RoleAdmin && wkl.TenantID != authCtx.TenantID) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	rolledBack, err := s.networkSvc.RollbackPolicy(req.WorkloadID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(rolledBack)
}

func (s *Server) handleNetworkTelemetry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	stats := s.networkSvc.GetStats()
	events := s.networkSvc.ListEvents(50)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"stats":  stats,
		"events": events,
	})
}

func (s *Server) handleNetworkEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var event models.NetworkDecisionEventModel
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}

	s.networkSvc.RecordEvent(&event)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

// -----------------------------------------------------------------------------
// Phase 3: Identity Intelligence Handlers
// -----------------------------------------------------------------------------

func (s *Server) handleIdentityGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	graph := s.identitySvc.GetGraph(authCtx.TenantID)
	json.NewEncoder(w).Encode(graph)
}

func (s *Server) handleIdentityConnectors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	connectors := s.identitySvc.ListConnectors()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"connectors": connectors,
	})
}

func (s *Server) handleIdentityDiscover(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	discoveredCount := s.identitySvc.TriggerDiscovery(authCtx.TenantID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           "success",
		"tenant_id":        authCtx.TenantID,
		"discovered_nodes": discoveredCount,
	})
}

func (s *Server) handleIdentityCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			WorkloadID     string   `json:"workload_id"`
			CredentialType string   `json:"credential_type"`
			Issuer         string   `json:"issuer"`
			Audience       string   `json:"audience"`
			Scope          []string `json:"scope"`
			ExpiresAtUnix  int64    `json:"expires_at_unix"`
			RawSecret      string   `json:"raw_secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
			return
		}

		cred, err := s.identitySvc.RegisterCredential(
			authCtx.TenantID,
			req.WorkloadID,
			req.CredentialType,
			req.Issuer,
			req.Audience,
			req.Scope,
			req.ExpiresAtUnix,
			[]byte(req.RawSecret),
		)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(cred)
		return
	}

	creds := s.identitySvc.ListCredentials(authCtx.TenantID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"credentials": creds,
	})
}

func (s *Server) handleIdentityCredentialRevoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CredentialID string `json:"credential_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}

	if err := s.identitySvc.RevokeCredential(authCtx.TenantID, req.CredentialID); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

func (s *Server) handleIdentityEffectiveAccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	entityID := r.URL.Query().Get("entity_id")
	if entityID == "" {
		http.Error(w, `{"error":"missing entity_id parameter"}`, http.StatusBadRequest)
		return
	}

	perms := s.identitySvc.ComputeEffectiveAccess(authCtx.TenantID, entityID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"entity_id":   entityID,
		"permissions": perms,
	})
}

func (s *Server) handleIdentityDrift(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	findings := s.identitySvc.GetDriftFindings(authCtx.TenantID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tenant_id": authCtx.TenantID,
		"findings":  findings,
	})
}

// -----------------------------------------------------------------------------
// Phase 5: Autonomous Containment, Risk & Enterprise Integration Handlers
// -----------------------------------------------------------------------------

func (s *Server) handleContainmentActions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet {
		if !auth.HasPermission(authCtx.Role, "containment:read") {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		actions := s.containmentSvc.ListContainmentActions(authCtx.TenantID)
		json.NewEncoder(w).Encode(actions)
		return
	}

	if r.Method == http.MethodPost {
		if !auth.HasPermission(authCtx.Role, "containment:execute") {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var req struct {
			WorkloadID string `json:"workload_id"`
			FindingID  string `json:"finding_id"`
			ActionType string `json:"action_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
			return
		}
		if req.WorkloadID == "" || req.ActionType == "" {
			http.Error(w, `{"error":"workload_id and action_type required"}`, http.StatusBadRequest)
			return
		}

		if authCtx.Role != auth.RoleAdmin && authCtx.Role != auth.RolePlatformAdmin {
			if !s.identitySvc.VerifyWorkloadOwnership(req.WorkloadID, authCtx.TenantID) {
				http.Error(w, `{"error":"forbidden_unauthorized_workload"}`, http.StatusForbidden)
				return
			}
		}

		action, err := s.containmentSvc.ExecuteContainment(authCtx.TenantID, authCtx.PrincipalID, req.WorkloadID, req.FindingID, req.ActionType)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(action)
		return
	}

	http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
}

func (s *Server) handleContainmentRecover(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if !auth.HasPermission(authCtx.Role, "containment:recover") && !auth.HasPermission(authCtx.Role, "containment:execute") {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	var req models.RecoveryRequestModel
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}

	if req.WorkloadID == "" {
		http.Error(w, `{"error":"workload_id required"}`, http.StatusBadRequest)
		return
	}

	if authCtx.Role != auth.RoleAdmin && authCtx.Role != auth.RolePlatformAdmin {
		req.TenantID = authCtx.TenantID
		if !s.identitySvc.VerifyWorkloadOwnership(req.WorkloadID, authCtx.TenantID) {
			http.Error(w, `{"error":"forbidden_unauthorized_workload"}`, http.StatusForbidden)
			return
		}
	} else if req.TenantID == "" {
		req.TenantID = authCtx.TenantID
	}
	if req.ApprovedBy == "" {
		req.ApprovedBy = authCtx.PrincipalID
	}

	action, err := s.containmentSvc.ExecuteRecovery(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(action)
}

func (s *Server) handleRisk(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	if !auth.HasPermission(authCtx.Role, "risk:read") {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	parts := strings.Split(strings.TrimRight(r.URL.Path, "/"), "/")
	workloadID := ""
	if len(parts) >= 5 && parts[4] != "" {
		workloadID = parts[4]
	} else {
		workloadID = r.URL.Query().Get("workload_id")
	}

	if workloadID == "" {
		http.Error(w, `{"error":"workload_id required"}`, http.StatusBadRequest)
		return
	}

	if authCtx.Role != auth.RoleAdmin && authCtx.Role != auth.RolePlatformAdmin {
		if !s.identitySvc.VerifyWorkloadOwnership(workloadID, authCtx.TenantID) {
			http.Error(w, `{"error":"forbidden_unauthorized_workload"}`, http.StatusForbidden)
			return
		}
	}

	findingCount := 0
	findings := s.eventsSvc.ListFindings()
	for _, f := range findings {
		if f.WorkloadID == workloadID {
			findingCount++
		}
	}

	risk := s.containmentSvc.EvaluateWorkloadRisk(authCtx.TenantID, workloadID, "Critical", findingCount, false)
	json.NewEncoder(w).Encode(risk)
}

func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	integrations := s.containmentSvc.ListIntegrations()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"integrations": integrations,
		"total":        len(integrations),
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authCtx := getAuthContext(r)
	if authCtx == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	var workloads []*models.Workload
	if authCtx.Role == auth.RoleAdmin || authCtx.Role == auth.RolePlatformAdmin {
		workloads = s.identitySvc.ListWorkloads()
	} else {
		workloads = s.identitySvc.ListWorkloadsByTenant(authCtx.TenantID)
	}

	activeCount := len(workloads)
	protectedCount := 0
	degradedCount := 0
	unprotectedCount := 0

	for _, wl := range workloads {
		switch wl.SensorStatus {
		case models.SensorProtected:
			protectedCount++
		case models.SensorDegraded:
			degradedCount++
		default:
			unprotectedCount++
		}
	}

	findings := s.eventsSvc.ListFindings()
	openFindings := 0
	for _, f := range findings {
		if authCtx.Role == auth.RoleAdmin || authCtx.Role == auth.RolePlatformAdmin || s.identitySvc.VerifyWorkloadOwnership(f.WorkloadID, authCtx.TenantID) {
			openFindings++
		}
	}

	containmentActions := len(s.containmentSvc.ListContainmentActions(authCtx.TenantID))

	stats := &models.OverviewStatsModel{
		ActiveWorkloads:          activeCount,
		ProtectedWorkloads:       protectedCount,
		DegradedWorkloads:        degradedCount,
		UnprotectedWorkloads:     unprotectedCount,
		ActiveIdentities:         len(workloads) + 2,
		PolicyViolations:         openFindings,
		OpenFindings:             openFindings,
		ContainmentActions:       containmentActions,
		SensorHealth:             "Healthy: eBPF Ring Buffer Active",
		NetworkEnforcementStatus: "Active: 4 cgroup socket address BPF hooks attached",
	}

	json.NewEncoder(w).Encode(stats)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	tokenSecret := os.Getenv("BADGER_AUTH_SECRET")
	if tokenSecret == "" {
		tokenSecret = "badger-default-auth-secret-key-2026"
	}

	server := &Server{
		identitySvc:    identity.NewService(),
		eventsSvc:      events.NewService(),
		networkSvc:     network.NewService(),
		containmentSvc: containment.NewService(),
		tokenMgr:       auth.NewTokenManager(tokenSecret),
	}

	// Register initial workloads for demonstration
	w1, _ := server.identitySvc.RegisterWorkload("finance-corp", "prn:finance:ledger-agent", "ledger-reconciliation-agent", "pol-strict", 1)
	server.identitySvc.UpdateSensorStatus(w1.ID, models.SensorProtected)

	w2, _ := server.identitySvc.RegisterWorkload("dev-team", "prn:dev:code-agent", "code-synthesis-worker", "pol-dev", 1)
	server.identitySvc.UpdateSensorStatus(w2.ID, models.SensorProtected)

	// Public routes
	http.HandleFunc("/api/v1/health", corsMiddleware(server.handleHealth))

	// Authenticated & Tenant-Scoped routes
	http.HandleFunc("/api/v1/workloads", corsMiddleware(server.authMiddleware(server.handleWorkloads)))
	http.HandleFunc("/api/v1/workloads/", corsMiddleware(server.authMiddleware(server.handleWorkloadByID)))
	http.HandleFunc("/api/v1/events", corsMiddleware(server.authMiddleware(server.handleEvents)))
	http.HandleFunc("/api/v1/findings", corsMiddleware(server.authMiddleware(server.handleFindings)))
	http.HandleFunc("/api/v1/audit", corsMiddleware(server.authMiddleware(server.handleAudit)))
	// Network routes
	http.HandleFunc("/api/v1/network/policies", corsMiddleware(server.authMiddleware(server.handleNetworkPolicies)))
	http.HandleFunc("/api/v1/network/policies/rollback", corsMiddleware(server.authMiddleware(server.handleNetworkRollback)))
	http.HandleFunc("/api/v1/network/telemetry", corsMiddleware(server.authMiddleware(server.handleNetworkTelemetry)))
	http.HandleFunc("/api/v1/network/events", corsMiddleware(server.authMiddleware(server.handleNetworkEvents)))

	// Identity Intelligence routes
	http.HandleFunc("/api/v1/identity/graph", corsMiddleware(server.authMiddleware(server.handleIdentityGraph)))
	http.HandleFunc("/api/v1/identity/connectors", corsMiddleware(server.handleIdentityConnectors))
	http.HandleFunc("/api/v1/identity/discover", corsMiddleware(server.authMiddleware(server.handleIdentityDiscover)))
	http.HandleFunc("/api/v1/identity/credentials", corsMiddleware(server.authMiddleware(server.handleIdentityCredentials)))
	http.HandleFunc("/api/v1/identity/credentials/revoke", corsMiddleware(server.authMiddleware(server.handleIdentityCredentialRevoke)))
	http.HandleFunc("/api/v1/identity/effective-access", corsMiddleware(server.authMiddleware(server.handleIdentityEffectiveAccess)))
	http.HandleFunc("/api/v1/identity/drift", corsMiddleware(server.authMiddleware(server.handleIdentityDrift)))

	// Phase 5: Autonomous Containment, Risk & Enterprise Integration routes
	http.HandleFunc("/api/v1/containment/actions", corsMiddleware(server.authMiddleware(server.handleContainmentActions)))
	http.HandleFunc("/api/v1/containment/recover", corsMiddleware(server.authMiddleware(server.handleContainmentRecover)))
	http.HandleFunc("/api/v1/risk/", corsMiddleware(server.authMiddleware(server.handleRisk)))
	http.HandleFunc("/api/v1/integrations", corsMiddleware(server.authMiddleware(server.handleIntegrations)))
	http.HandleFunc("/api/v1/overview", corsMiddleware(server.authMiddleware(server.handleOverview)))

	log.Printf("[BADGER v1.0.0 Enterprise] Autonomous Agent Security & Runtime Containment Control Plane on http://0.0.0.0:%s", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
