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

func TestIdentityIntelligenceGraphAndDrift(t *testing.T) {
	svc := identity.NewService()

	// 1. Connectors list
	connectors := svc.ListConnectors()
	if len(connectors) < 4 {
		t.Fatalf("expected at least 4 connectors, got %d", len(connectors))
	}

	// 2. Register Workload and verify Graph
	wkl, err := svc.RegisterWorkload("tenant-test", "prn:agent-test", "test-agent", "pol-test", 1)
	if err != nil {
		t.Fatalf("unexpected error registering workload: %v", err)
	}

	// Trigger discovery
	discoveredCount := svc.TriggerDiscovery("tenant-test")
	if discoveredCount == 0 {
		t.Errorf("expected discovered nodes > 0, got %d", discoveredCount)
	}

	graph := svc.GetGraph("tenant-test")
	if len(graph.Nodes) < 2 {
		t.Errorf("expected at least 2 nodes in graph, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) < 1 {
		t.Errorf("expected at least 1 edge in graph, got %d", len(graph.Edges))
	}

	// 3. Register Credential & Fingerprint
	cred, err := svc.RegisterCredential(
		"tenant-test",
		wkl.ID,
		"ApiKey",
		"OpenAI",
		"api.openai.com",
		[]string{"models.read"},
		1000, // expired timestamp
		[]byte("secret-test-token"),
	)
	if err != nil {
		t.Fatalf("failed to register credential: %v", err)
	}
	if cred.FingerprintHmacSha256 == "" || cred.FingerprintHmacSha256 == "secret-test-token" {
		t.Errorf("invalid HMAC fingerprint: %s", cred.FingerprintHmacSha256)
	}

	// 4. Drift findings: should identify expired credential
	findings := svc.GetDriftFindings("tenant-test")
	if len(findings) == 0 {
		t.Errorf("expected drift finding for expired credential, got 0")
	}

	// 5. Revocation
	if err := svc.RevokeCredential("tenant-test", cred.ID); err != nil {
		t.Fatalf("failed to revoke credential: %v", err)
	}
	creds := svc.ListCredentials("tenant-test")
	if len(creds) == 0 || !creds[0].IsRevoked {
		t.Errorf("expected credential to be marked revoked")
	}
}
