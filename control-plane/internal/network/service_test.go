package network

import (
	"testing"
	"time"

	"github.com/badger-security/badger/control-plane/internal/models"
)

func TestNetworkServicePolicyAndRollback(t *testing.T) {
	svc := NewService()

	p1 := &models.NetworkPolicyModel{
		ID:            "pol-unit-1",
		TenantID:      "tenant-x",
		WorkloadID:    "wkl-unit-1",
		Version:       1,
		DefaultAction: "deny",
		Rules: []models.NetworkRuleModel{
			{
				RuleID:          1,
				Direction:       "egress",
				DestinationCIDR: "10.0.0.0/8",
				MinPort:         443,
				MaxPort:         443,
				Protocol:        "tcp",
				Action:          "allow",
				Priority:        100,
			},
		},
		ValidUntilUnix: time.Now().Add(1 * time.Hour).Unix(),
	}

	if err := svc.DeployPolicy(p1); err != nil {
		t.Fatalf("Failed to deploy p1: %v", err)
	}

	// Deploy v2
	p2 := &models.NetworkPolicyModel{
		ID:            "pol-unit-1",
		TenantID:      "tenant-x",
		WorkloadID:    "wkl-unit-1",
		Version:       2,
		DefaultAction: "deny",
		Rules:         p1.Rules,
	}

	if err := svc.DeployPolicy(p2); err != nil {
		t.Fatalf("Failed to deploy p2: %v", err)
	}

	curr, ok := svc.GetPolicy("wkl-unit-1")
	if !ok || curr.Version != 2 {
		t.Fatalf("Expected version 2, got %v", curr)
	}

	// Reject regression
	if err := svc.DeployPolicy(p1); err == nil {
		t.Fatalf("Expected regression error deploying v1 over v2")
	}

	// Rollback to v1
	rolledBack, err := svc.RollbackPolicy("wkl-unit-1")
	if err != nil {
		t.Fatalf("Failed to rollback: %v", err)
	}
	if rolledBack.Version != 1 {
		t.Fatalf("Expected rolled back version 1, got %d", rolledBack.Version)
	}
}

func TestNetworkServiceTelemetryAccounting(t *testing.T) {
	svc := NewService()
	initialStats := svc.GetStats()

	svc.RecordEvent(&models.NetworkDecisionEventModel{
		EventID:         "test-allow",
		WorkloadID:      "wkl-unit-1",
		DestinationIP:   "10.0.0.1",
		DestinationPort: 443,
		Action:          "allow",
	})

	svc.RecordEvent(&models.NetworkDecisionEventModel{
		EventID:         "test-deny",
		WorkloadID:      "wkl-unit-1",
		DestinationIP:   "169.254.169.254",
		DestinationPort: 80,
		Action:          "deny",
	})

	newStats := svc.GetStats()
	if newStats.TotalConnections != initialStats.TotalConnections+2 {
		t.Errorf("Expected total +2, got %d", newStats.TotalConnections)
	}
	if newStats.AllowedConnections != initialStats.AllowedConnections+1 {
		t.Errorf("Expected allowed +1, got %d", newStats.AllowedConnections)
	}
	if newStats.DeniedConnections != initialStats.DeniedConnections+1 {
		t.Errorf("Expected denied +1, got %d", newStats.DeniedConnections)
	}
}
