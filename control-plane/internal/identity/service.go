package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/badger-security/badger/control-plane/internal/models"
)

type Service struct {
	mu        sync.RWMutex
	workloads map[string]*models.Workload
}

func NewService() *Service {
	return &Service{
		workloads: make(map[string]*models.Workload),
	}
}

func (s *Service) RegisterWorkload(tenantID, principalID, name, policyID string, policyVer int) (*models.Workload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("wkl_%s", hex.EncodeToString(b))
	spiffeID := fmt.Sprintf("spiffe://badger.local/ns/%s/workload/%s", tenantID, id)

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
