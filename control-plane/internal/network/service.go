package network

import (
	"errors"
	"sync"
	"time"

	"github.com/badger-security/badger/control-plane/internal/models"
)

type Service struct {
	mu       sync.RWMutex
	policies map[string]*models.NetworkPolicyModel // workload_id -> policy
	history  map[string][]*models.NetworkPolicyModel
	events   []*models.NetworkDecisionEventModel
	stats    models.NetworkStatsModel
}

func NewService() *Service {
	s := &Service{
		policies: make(map[string]*models.NetworkPolicyModel),
		history:  make(map[string][]*models.NetworkPolicyModel),
		events:   make([]*models.NetworkDecisionEventModel, 0, 1000),
	}

	// Seed demo workloads
	s.seedDemoPolicies()
	return s
}

func (s *Service) seedDemoPolicies() {
	p1 := &models.NetworkPolicyModel{
		ID:                 "net-pol-finance-ledger",
		TenantID:           "finance-corp",
		WorkloadID:         "wkl-finance-ledger-01",
		Version:            1,
		DefaultAction:      "deny",
		BlockCloudMetadata: true,
		Rules: []models.NetworkRuleModel{
			{
				RuleID:          101,
				Direction:       "egress",
				DestinationCIDR: "10.20.0.0/16",
				MinPort:         443,
				MaxPort:         443,
				Protocol:        "tcp",
				Action:          "allow",
				Priority:        100,
				Description:     "Internal Core Banking API",
			},
			{
				RuleID:          102,
				Direction:       "egress",
				DestinationCIDR: "1.1.1.1/32",
				MinPort:         53,
				MaxPort:         53,
				Protocol:        "udp",
				Action:          "allow",
				Priority:        100,
				Description:     "Secure DNS Resolver",
			},
		},
		ValidFromUnix:  0,
		ValidUntilUnix: time.Now().Add(72 * time.Hour).Unix(),
		Signature:      "b891a27e4c2",
		Issuer:         "sec-ops",
	}
	s.policies[p1.WorkloadID] = p1

	// Initial decision events
	s.RecordEvent(&models.NetworkDecisionEventModel{
		EventID:            "net-evt-init-01",
		TimestampUnixNanos: time.Now().Add(-5 * time.Minute).UnixNano(),
		WorkloadID:         p1.WorkloadID,
		ProcessComm:        "ledger-agent",
		Family:             "IPv4",
		Protocol:           "TCP",
		DestinationIP:      "10.20.1.5",
		DestinationPort:    443,
		Action:             "allow",
		MatchedRuleID:      101,
		Reason:             "Matched policy rule 101",
		Provenance:         "cgroup_sock_addr",
	})

	s.RecordEvent(&models.NetworkDecisionEventModel{
		EventID:            "net-evt-init-02",
		TimestampUnixNanos: time.Now().Add(-2 * time.Minute).UnixNano(),
		WorkloadID:         p1.WorkloadID,
		ProcessComm:        "curl",
		Family:             "IPv4",
		Protocol:           "TCP",
		DestinationIP:      "169.254.169.254",
		DestinationPort:    80,
		Action:             "deny",
		MatchedRuleID:      999999,
		Reason:             "Blocked Cloud Metadata Access (169.254.169.254)",
		Provenance:         "cgroup_sock_addr",
	})
}

func (s *Service) DeployPolicy(policy *models.NetworkPolicyModel) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if policy.WorkloadID == "" {
		return errors.New("workload_id is required")
	}

	if existing, ok := s.policies[policy.WorkloadID]; ok {
		if policy.Version <= existing.Version {
			return errors.New("policy version regression rejected")
		}
		s.history[policy.WorkloadID] = append(s.history[policy.WorkloadID], existing)
	}

	s.policies[policy.WorkloadID] = policy
	return nil
}

func (s *Service) RollbackPolicy(workloadID string) (*models.NetworkPolicyModel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	history, ok := s.history[workloadID]
	if !ok || len(history) == 0 {
		return nil, errors.New("no prior policy version available for rollback")
	}

	prev := history[len(history)-1]
	s.history[workloadID] = history[:len(history)-1]
	s.policies[workloadID] = prev
	return prev, nil
}

func (s *Service) GetPolicy(workloadID string) (*models.NetworkPolicyModel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.policies[workloadID]
	return p, ok
}

func (s *Service) ListPolicies(tenantID string, isAdmin bool) []*models.NetworkPolicyModel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*models.NetworkPolicyModel, 0, len(s.policies))
	for _, p := range s.policies {
		if isAdmin || p.TenantID == tenantID {
			res = append(res, p)
		}
	}
	return res
}

func (s *Service) RecordEvent(e *models.NetworkDecisionEventModel) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.TotalConnections++
	if e.Action == "deny" {
		s.stats.DeniedConnections++
		s.stats.ViolationsCount++
	} else {
		s.stats.AllowedConnections++
	}

	if len(s.events) >= 1000 {
		s.events = s.events[1:]
	}
	s.events = append(s.events, e)
}

func (s *Service) ListEvents(limit int) []*models.NetworkDecisionEventModel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.events) {
		limit = len(s.events)
	}

	start := len(s.events) - limit
	res := make([]*models.NetworkDecisionEventModel, limit)
	copy(res, s.events[start:])
	return res
}

func (s *Service) GetStats() models.NetworkStatsModel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.stats
}
