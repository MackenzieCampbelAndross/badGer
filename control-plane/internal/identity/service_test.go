package identity_test

import (
	"testing"

	"github.com/badger-security/badger/control-plane/internal/identity"
	"github.com/badger-security/badger/control-plane/internal/models"
)

func TestWorkloadRegistrationAndSpiffe(t *testing.T) {
	svc := identity.NewService()

	wkl, err := svc.RegisterWorkload("tenant-corp", "prn:agent-1", "recon-agent", "pol-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wkl.State != models.StateRegistered {
		t.Errorf("expected state registered, got %s", wkl.State)
	}

	spiffeID, ok := wkl.Metadata["spiffe_id"]
	if !ok || spiffeID == "" {
		t.Errorf("expected non-empty spiffe_id in metadata")
	}

	retrieved, found := svc.GetWorkload(wkl.ID)
	if !found || retrieved.Name != "recon-agent" {
		t.Errorf("expected to retrieve workload %s", wkl.ID)
	}
}
