package auth_test

import (
	"testing"
	"time"

	"github.com/badger-security/badger/control-plane/internal/auth"
)

func TestTokenValidation(t *testing.T) {
	tm := auth.NewTokenManager("secret-key")

	// 1. Valid token
	ctx, err := tm.ValidateAuthHeader("Bearer token-finance-agent")
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if ctx.TenantID != "finance-corp" {
		t.Errorf("expected tenant finance-corp, got %s", ctx.TenantID)
	}

	// 2. Missing header
	_, err = tm.ValidateAuthHeader("")
	if err != auth.ErrUnauthenticated {
		t.Errorf("expected ErrUnauthenticated for empty header, got %v", err)
	}

	// 3. Invalid token
	_, err = tm.ValidateAuthHeader("Bearer invalid-token-xyz")
	if err != auth.ErrUnauthenticated {
		t.Errorf("expected ErrUnauthenticated for invalid token, got %v", err)
	}

	// 4. Revoked token
	token := tm.IssueToken("test-revoke-tok", "tenant-test", "prn:test", auth.RoleAgent, 1*time.Hour)
	err = tm.RevokeToken(token.TokenString)
	if err != nil {
		t.Fatalf("unexpected error revoking token: %v", err)
	}
	_, err = tm.ValidateAuthHeader("Bearer test-revoke-tok")
	if err != auth.ErrTokenRevoked {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}

	// 5. Expired token
	tm.IssueToken("test-expired-tok", "tenant-test", "prn:test", auth.RoleAgent, -1*time.Hour)
	_, err = tm.ValidateAuthHeader("Bearer test-expired-tok")
	if err != auth.ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}
