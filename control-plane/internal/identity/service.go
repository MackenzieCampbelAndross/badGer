package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/badger-security/badger/control-plane/internal/models"
)

type Service struct {
	mu            sync.RWMutex
	workloads     map[string]*models.Workload
	nodes         map[string]map[string]*models.IdentityNode
	relationships map[string][]*models.RelationshipModel
	credentials   map[string]map[string]*models.CredentialModel
	resources     map[string]map[string]*models.ResourceModel
	findings      map[string][]*models.IdentityFindingModel
	connectors    []models.ConnectorStatusModel
}

func NewService() *Service {
	now := time.Now().Unix()
	s := &Service{
		workloads:     make(map[string]*models.Workload),
		nodes:         make(map[string]map[string]*models.IdentityNode),
		relationships: make(map[string][]*models.RelationshipModel),
		credentials:   make(map[string]map[string]*models.CredentialModel),
		resources:     make(map[string]map[string]*models.ResourceModel),
		findings:      make(map[string][]*models.IdentityFindingModel),
		connectors: []models.ConnectorStatusModel{
			{Name: "linux_process_connector", Type: "LinuxProcFs", Status: "Healthy", Details: "/proc discovery active", LastObserved: now},
			{Name: "badger_workload_connector", Type: "BadgerSandbox", Status: "Healthy", Details: "cgroups & sandbox tracking active", LastObserved: now},
			{Name: "docker_container_connector", Type: "DockerDaemon", Status: "Unavailable", Details: "Docker socket /var/run/docker.sock not present", LastObserved: now},
			{Name: "kubernetes_cluster_connector", Type: "KubernetesApi", Status: "Unavailable", Details: "In-cluster service account or KUBECONFIG absent", LastObserved: now},
		},
	}
	return s
}

func (s *Service) RegisterWorkload(tenantID, principalID, name, policyID string, policyVer int) (*models.Workload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("wkl_%s", hex.EncodeToString(b))
	spiffeID := fmt.Sprintf("spiffe://badger.local/ns/%s/sa/%s/workload/%s", tenantID, principalID, id)

	now := time.Now().Unix()
	w := &models.Workload{
		ID:            id,
		TenantID:      tenantID,
		PrincipalID:   principalID,
		Name:          name,
		State:         models.StateRegistered,
		PolicyID:      policyID,
		PolicyVersion: policyVer,
		Metadata: map[string]string{
			"spiffe_id": spiffeID,
		},
		RegisteredAt: now,
		UpdatedAt:    now,
		SensorStatus: models.SensorUnknown,
	}

	s.workloads[id] = w

	// Initialize maps for tenant if not exists
	if s.nodes[tenantID] == nil {
		s.nodes[tenantID] = make(map[string]*models.IdentityNode)
	}
	if s.resources[tenantID] == nil {
		s.resources[tenantID] = make(map[string]*models.ResourceModel)
	}
	if s.credentials[tenantID] == nil {
		s.credentials[tenantID] = make(map[string]*models.CredentialModel)
	}

	// Add principal node
	s.nodes[tenantID][principalID] = &models.IdentityNode{
		ID:         principalID,
		TenantID:   tenantID,
		EntityType: "Principal",
		Label:      fmt.Sprintf("Principal %s", principalID),
		Properties: map[string]string{"type": "Agent"},
	}

	// Add workload node
	s.nodes[tenantID][id] = &models.IdentityNode{
		ID:         id,
		TenantID:   tenantID,
		EntityType: "Workload",
		Label:      name,
		Properties: map[string]string{
			"spiffe_id": spiffeID,
			"policy_id": policyID,
		},
	}

	// Add OWNS edge: Principal -> Workload
	s.relationships[tenantID] = append(s.relationships[tenantID], &models.RelationshipModel{
		ID:                fmt.Sprintf("rel_owns_%s_%s", principalID, id),
		TenantID:          tenantID,
		SourceID:          principalID,
		TargetID:          id,
		RelationshipType:  "OWNS",
		Kind:              "Direct",
		Confidence:        1.0,
		SourceAttribution: "control_plane",
		ValidFromUnix:     now,
		Metadata:          map[string]string{},
	})

	return w, nil
}

func (s *Service) GetWorkload(id string) (*models.Workload, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.workloads[id]
	return w, ok
}

func (s *Service) ListWorkloads() []*models.Workload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]*models.Workload, 0, len(s.workloads))
	for _, w := range s.workloads {
		res = append(res, w)
	}
	return res
}

func (s *Service) ListWorkloadsByTenant(tenantID string) []*models.Workload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]*models.Workload, 0)
	for _, w := range s.workloads {
		if w.TenantID == tenantID {
			res = append(res, w)
		}
	}
	return res
}

func (s *Service) VerifyWorkloadOwnership(workloadID, tenantID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.workloads[workloadID]
	if !ok {
		return false
	}
	return w.TenantID == tenantID
}

func (s *Service) UpdateSensorStatus(id string, status models.SensorHealthStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.workloads[id]
	if !ok {
		return fmt.Errorf("workload %s not found", id)
	}
	w.SensorStatus = status
	w.UpdatedAt = time.Now().Unix()
	return nil
}

// -----------------------------------------------------------------------------
// Phase 3: Identity Intelligence Subsystem APIs
// -----------------------------------------------------------------------------

func (s *Service) ListConnectors() []models.ConnectorStatusModel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connectors
}

func (s *Service) TriggerDiscovery(tenantID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update connector timestamps
	now := time.Now().Unix()
	for i := range s.connectors {
		s.connectors[i].LastObserved = now
	}

	// Ensure tenant maps exist
	if s.nodes[tenantID] == nil {
		s.nodes[tenantID] = make(map[string]*models.IdentityNode)
	}
	if s.resources[tenantID] == nil {
		s.resources[tenantID] = make(map[string]*models.ResourceModel)
	}
	if s.credentials[tenantID] == nil {
		s.credentials[tenantID] = make(map[string]*models.CredentialModel)
	}

	// Register sample resources if none exist
	if len(s.resources[tenantID]) == 0 {
		res1 := &models.ResourceModel{
			ID:           "res_db_customers",
			TenantID:     tenantID,
			ResourceType: "Database",
			Identifier:   "postgres://db.internal/customers",
			Labels:       map[string]string{"env": "production", "tier": "critical"},
		}
		res2 := &models.ResourceModel{
			ID:           "res_api_anthropic",
			TenantID:     tenantID,
			ResourceType: "ApiEndpoint",
			Identifier:   "https://api.anthropic.com/v1/messages",
			Labels:       map[string]string{"type": "llm_provider"},
		}
		s.resources[tenantID][res1.ID] = res1
		s.resources[tenantID][res2.ID] = res2

		s.nodes[tenantID][res1.ID] = &models.IdentityNode{
			ID:         res1.ID,
			TenantID:   tenantID,
			EntityType: "Resource",
			Label:      res1.Identifier,
			Properties: res1.Labels,
		}
		s.nodes[tenantID][res2.ID] = &models.IdentityNode{
			ID:         res2.ID,
			TenantID:   tenantID,
			EntityType: "Resource",
			Label:      res2.Identifier,
			Properties: res2.Labels,
		}
	}

	return len(s.nodes[tenantID])
}

func (s *Service) GetGraph(tenantID string) *models.IdentityGraphViewModel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nodeMap := s.nodes[tenantID]
	nodes := make([]models.IdentityNode, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, *n)
	}

	rawEdges := s.relationships[tenantID]
	edges := make([]models.RelationshipModel, 0, len(rawEdges))
	for _, e := range rawEdges {
		edges = append(edges, *e)
	}

	summary := map[string]int{
		"nodes": len(nodes),
		"edges": len(edges),
	}

	return &models.IdentityGraphViewModel{
		Nodes:   nodes,
		Edges:   edges,
		Summary: summary,
	}
}

func (s *Service) RegisterCredential(tenantID, workloadID, credType, issuer, audience string, scopes []string, expiresAtUnix int64, rawSecret []byte) (*models.CredentialModel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.credentials[tenantID] == nil {
		s.credentials[tenantID] = make(map[string]*models.CredentialModel)
	}
	if s.nodes[tenantID] == nil {
		s.nodes[tenantID] = make(map[string]*models.IdentityNode)
	}

	// Keyed HMAC fingerprint
	h := hmac.New(sha256.New, []byte(tenantID+"-salt-badger"))
	h.Write(rawSecret)
	fp := hex.EncodeToString(h.Sum(nil))

	b := make([]byte, 8)
	rand.Read(b)
	credID := fmt.Sprintf("cred_%s", hex.EncodeToString(b))
	now := time.Now().Unix()

	cred := &models.CredentialModel{
		ID:                    credID,
		TenantID:              tenantID,
		CredentialType:        credType,
		Issuer:                issuer,
		Audience:              audience,
		Scope:                 scopes,
		FingerprintHmacSha256: fp,
		IssuedAtUnix:          now,
		ExpiresAtUnix:         expiresAtUnix,
		IsRevoked:             false,
		LastUsedAtUnix:        now,
		UseCount:              1,
		AssociatedPrincipals:  []string{workloadID},
	}

	s.credentials[tenantID][credID] = cred

	// Add to graph
	s.nodes[tenantID][credID] = &models.IdentityNode{
		ID:         credID,
		TenantID:   tenantID,
		EntityType: "Credential",
		Label:      fmt.Sprintf("%s (%s)", credType, issuer),
		Properties: map[string]string{
			"issuer":      issuer,
			"fingerprint": fp[:16] + "...",
		},
	}

	// Add USES_CREDENTIAL edge
	s.relationships[tenantID] = append(s.relationships[tenantID], &models.RelationshipModel{
		ID:                fmt.Sprintf("rel_uses_%s_%s", workloadID, credID),
		TenantID:          tenantID,
		SourceID:          workloadID,
		TargetID:          credID,
		RelationshipType:  "USES_CREDENTIAL",
		Kind:              "Direct",
		Confidence:        1.0,
		SourceAttribution: "control_plane",
		ValidFromUnix:     now,
		Metadata:          map[string]string{},
	})

	return cred, nil
}

func (s *Service) ListCredentials(tenantID string) []*models.CredentialModel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*models.CredentialModel, 0)
	if creds, ok := s.credentials[tenantID]; ok {
		for _, c := range creds {
			res = append(res, c)
		}
	}
	return res
}

func (s *Service) RevokeCredential(tenantID, credID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if creds, ok := s.credentials[tenantID]; ok {
		if c, found := creds[credID]; found {
			c.IsRevoked = true
			return nil
		}
	}
	return fmt.Errorf("credential %s not found for tenant %s", credID, tenantID)
}

func (s *Service) ComputeEffectiveAccess(tenantID, entityID string) []*models.EffectivePermissionModel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	permissions := make([]*models.EffectivePermissionModel, 0)
	rawEdges := s.relationships[tenantID]

	// Find direct and inherited access edges
	for _, edge := range rawEdges {
		if edge.SourceID == entityID && edge.RelationshipType == "CAN_ACCESS" {
			ident := edge.TargetID
			if resMap, ok := s.resources[tenantID]; ok {
				if r, exists := resMap[edge.TargetID]; exists {
					ident = r.Identifier
				}
			}
			permissions = append(permissions, &models.EffectivePermissionModel{
				EntityID:           entityID,
				ResourceID:         edge.TargetID,
				ResourceIdentifier: ident,
				Action:             "read/write",
				Provenance:         "Direct",
				Confidence:         int(edge.Confidence * 100),
			})
		} else if edge.SourceID == entityID && edge.RelationshipType == "USES_CREDENTIAL" {
			// Find credential-associated target
			for _, cEdge := range rawEdges {
				if cEdge.SourceID == edge.TargetID && cEdge.RelationshipType == "CAN_ACCESS" {
					permissions = append(permissions, &models.EffectivePermissionModel{
						EntityID:           entityID,
						ResourceID:         cEdge.TargetID,
						ResourceIdentifier: cEdge.TargetID,
						Action:             "api_invoke",
						Provenance:         fmt.Sprintf("CredentialAssociated (%s)", edge.TargetID),
						Confidence:         90,
					})
				}
			}
		}
	}

	return permissions
}

func (s *Service) GetDriftFindings(tenantID string) []*models.IdentityFindingModel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	findings := make([]*models.IdentityFindingModel, 0)

	// Check for unrevoked expired credentials
	now := time.Now().Unix()
	if creds, ok := s.credentials[tenantID]; ok {
		for _, c := range creds {
			if now > c.ExpiresAtUnix && !c.IsRevoked {
				findings = append(findings, &models.IdentityFindingModel{
					ID:          fmt.Sprintf("fnd_exp_%s", c.ID),
					TenantID:    tenantID,
					FindingType: "ExpiredCredentialInUse",
					Severity:    "Medium",
					Title:       fmt.Sprintf("Expired Credential: %s", c.ID),
					Description: fmt.Sprintf("Credential %s (%s) has expired but is not revoked", c.ID, c.Issuer),
					EntityID:    c.ID,
					Evidence: map[string]string{
						"expires_at_unix": fmt.Sprintf("%d", c.ExpiresAtUnix),
						"issuer":          c.Issuer,
					},
					Remediation: "Revoke expired credential and re-issue a rotated token",
					DetectedAt:  now,
					Status:      "Open",
				})
			}
		}
	}

	// Append any stored findings
	if fList, ok := s.findings[tenantID]; ok {
		findings = append(findings, fList...)
	}

	return findings
}
