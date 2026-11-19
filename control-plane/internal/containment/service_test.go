package containment_test

import (
	"testing"

	"github.com/badger-security/badger/control-plane/internal/containment"
	"github.com/badger-security/badger/control-plane/internal/models"
)

func TestContainmentExecutionAndVerification(t *testing.T) {
	svc := containment.NewService()

	action, err := svc.ExecuteContainment("tenant-corp", "sec-admin", "wkl-101", "fnd-999", "SuspendWorkload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !action.Verified {
		t.Errorf("expected action to be verified")
	}
	if action.LifecycleState != "OutcomeVerified" {
		t.Errorf("expected LifecycleState OutcomeVerified, got %s", action.LifecycleState)
	}

	actions := svc.ListContainmentActions("tenant-corp")
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
}

func TestControlledRecoveryRequiresApproval(t *testing.T) {
	svc := containment.NewService()

	// Unapproved recovery must fail
	unapproved := &models.RecoveryRequestModel{
		WorkloadID:            "wkl-101",
		TenantID:              "tenant-corp",
		ApprovedBy:            "", // missing
		Reason:                "test",
		FindingsAcknowledged:  true,
		BaselinePolicyVersion: 1,
	}
	if _, err := svc.ExecuteRecovery(unapproved); err == nil {
		t.Errorf("expected error when approval identity is missing")
	}

	// Unacknowledged findings must fail
	unack := &models.RecoveryRequestModel{
		WorkloadID:            "wkl-101",
		TenantID:              "tenant-corp",
		ApprovedBy:            "sec-operator",
		Reason:                "test",
		FindingsAcknowledged:  false, // missing
		BaselinePolicyVersion: 1,
	}
	if _, err := svc.ExecuteRecovery(unack); err == nil {
		t.Errorf("expected error when findings are unacknowledged")
	}

	// Valid recovery succeeds
	valid := &models.RecoveryRequestModel{
		WorkloadID:            "wkl-101",
		TenantID:              "tenant-corp",
		ApprovedBy:            "sec-operator",
		Reason:                "Neutralized vulnerability",
		FindingsAcknowledged:  true,
		BaselinePolicyVersion: 1,
	}
	rec, err := svc.ExecuteRecovery(valid)
	if err != nil {
		t.Fatalf("unexpected error on valid recovery: %v", err)
	}
	if !rec.Verified {
		t.Errorf("expected recovery to be verified")
	}
}

func TestDeterministicRiskEvaluation(t *testing.T) {
	svc := containment.NewService()

	risk := svc.EvaluateWorkloadRisk("tenant-corp", "wkl-101", "Critical", 2, true)
	if risk.RiskScore < 80 {
		t.Errorf("expected risk score >= 80 for Critical workload with findings and net violations, got %d", risk.RiskScore)
	}
	if risk.Severity != "Critical" {
		t.Errorf("expected Critical severity, got %s", risk.Severity)
	}
	if len(risk.ContributingFactors) < 3 {
		t.Errorf("expected at least 3 contributing factors, got %d", len(risk.ContributingFactors))
	}
}

func TestIntegrationsList(t *testing.T) {
	svc := containment.NewService()

	integs := svc.ListIntegrations()
	if len(integs) < 6 {
		t.Errorf("expected at least 6 supported enterprise integrations, got %d", len(integs))
	}
}
