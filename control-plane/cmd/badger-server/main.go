package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/badger-security/badger/control-plane/internal/events"
	"github.com/badger-security/badger/control-plane/internal/identity"
	"github.com/badger-security/badger/control-plane/internal/models"
)

type Server struct {
	identitySvc *identity.Service
	eventsSvc   *events.Service
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

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"version": "1.0.0",
		"service": "badger-control-plane",
	})
}

func (s *Server) handleWorkloads(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodPost {
		var req struct {
			TenantID      string `json:"tenant_id"`
			PrincipalID   string `json:"principal_id"`
			Name          string `json:"name"`
			PolicyID      string `json:"policy_id"`
			PolicyVersion int    `json:"policy_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.TenantID == "" {
			req.TenantID = "default"
		}
		if req.PrincipalID == "" {
			req.PrincipalID = "prn:default:agent"
		}

		wkl, err := s.identitySvc.RegisterWorkload(req.TenantID, req.PrincipalID, req.Name, req.PolicyID, req.PolicyVersion)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(wkl)
		return
	}

	if r.Method == http.MethodGet {
		workloads := s.identitySvc.ListWorkloads()
		json.NewEncoder(w).Encode(workloads)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleWorkloadByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid workload path", http.StatusBadRequest)
		return
	}
	id := parts[4]
	wkl, ok := s.identitySvc.GetWorkload(id)
	if !ok {
		http.Error(w, "Workload not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(wkl)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodPost {
		var evt models.RuntimeEvent
		if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		finding, err := s.eventsSvc.IngestEvent(&evt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
		evts := s.eventsSvc.ListEvents(limit)
		json.NewEncoder(w).Encode(evts)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	findings := s.eventsSvc.ListFindings()
	json.NewEncoder(w).Encode(findings)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logs := s.eventsSvc.ListAuditRecords()
	json.NewEncoder(w).Encode(logs)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &Server{
		identitySvc: identity.NewService(),
		eventsSvc:   events.NewService(),
	}

	// Register some initial demonstration workloads for the dashboard
	w1, _ := server.identitySvc.RegisterWorkload("finance-corp", "prn:finance:ledger-agent", "ledger-reconciliation-agent", "pol-strict", 1)
	server.identitySvc.UpdateSensorStatus(w1.ID, models.SensorProtected)

	w2, _ := server.identitySvc.RegisterWorkload("dev-team", "prn:dev:code-agent", "code-synthesis-worker", "pol-dev", 1)
	server.identitySvc.UpdateSensorStatus(w2.ID, models.SensorDegraded)

	// Register routes
	http.HandleFunc("/api/v1/health", corsMiddleware(server.handleHealth))
	http.HandleFunc("/api/v1/workloads", corsMiddleware(server.handleWorkloads))
	http.HandleFunc("/api/v1/workloads/", corsMiddleware(server.handleWorkloadByID))
	http.HandleFunc("/api/v1/events", corsMiddleware(server.handleEvents))
	http.HandleFunc("/api/v1/findings", corsMiddleware(server.handleFindings))
	http.HandleFunc("/api/v1/audit", corsMiddleware(server.handleAudit))

	log.Printf("[BADGER] Control Plane running on http://0.0.0.0:%s", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
