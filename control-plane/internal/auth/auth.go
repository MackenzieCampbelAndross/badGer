package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnauthenticated = errors.New("unauthenticated: missing or invalid authorization token")
	ErrUnauthorized    = errors.New("unauthorized: insufficient tenant permissions")
	ErrTokenRevoked    = errors.New("unauthorized: token has been revoked")
	ErrTokenExpired    = errors.New("unauthorized: token has expired")
)

type Role string

const (
	RoleAgent            Role = "agent"
	RoleOperator         Role = "operator"
	RoleAdmin            Role = "admin"
	RolePlatformAdmin    Role = "Platform Administrator"
	RoleSecurityAdmin    Role = "Security Administrator"
	RoleSecurityAnalyst  Role = "Security Analyst"
	RolePlatformEngineer Role = "Platform Engineer"
	RoleAuditor          Role = "Auditor"
)

// HasPermission validates if a role has the required permission
func HasPermission(role Role, perm string) bool {
	if role == RoleAdmin || role == RolePlatformAdmin {
		return true // Platform/System Admin has wildcard access
	}

	switch role {
	case RoleSecurityAdmin:
		return strings.HasPrefix(perm, "containment:") ||
			strings.HasPrefix(perm, "policies:") ||
			strings.HasPrefix(perm, "findings:") ||
			strings.HasPrefix(perm, "audit:") ||
			strings.HasPrefix(perm, "workloads:") ||
			strings.HasPrefix(perm, "identities:") ||
			strings.HasPrefix(perm, "integrations:") ||
			strings.HasPrefix(perm, "risk:")
	case RoleSecurityAnalyst:
		return perm == "findings:read" || perm == "findings:write" ||
			perm == "containment:read" || perm == "containment:simulate" ||
			perm == "policies:read" || perm == "audit:read" ||
			perm == "workloads:read" || perm == "identities:read" ||
			perm == "risk:read" || perm == "integrations:read"
	case RolePlatformEngineer:
		return strings.HasPrefix(perm, "workloads:") ||
			perm == "policies:read" || perm == "containment:read" ||
			strings.HasPrefix(perm, "integrations:")
	case RoleAuditor:
		return perm == "audit:read" || perm == "findings:read" ||
			perm == "policies:read" || perm == "identities:read" ||
			perm == "containment:read" || perm == "workloads:read"
	case RoleOperator:
		return true // General operator
	case RoleAgent:
		return perm == "events:write" || perm == "workloads:read" || perm == "policies:read"
	default:
		return false
	}
}

type Token struct {
	TokenString string    `json:"token_string"`
	TenantID    string    `json:"tenant_id"`
	PrincipalID string    `json:"principal_id"`
	Role        Role      `json:"role"`
	ExpiresAt   time.Time `json:"expires_at"`
	Revoked     bool      `json:"revoked"`
}

type AuthContext struct {
	TenantID    string
	PrincipalID string
	Role        Role
}

type TokenManager struct {
	mu     sync.RWMutex
	tokens map[string]*Token
	secret string
}

func NewTokenManager(secret string) *TokenManager {
	tm := &TokenManager{
		tokens: make(map[string]*Token),
		secret: secret,
	}

	// Seed standard tenant tokens for testing and operation
	tm.IssueToken("token-adversarial-agent", "tenant-adversarial", "prn:tenant-adversarial:agent", RoleAgent, 24*time.Hour)
	tm.IssueToken("token-finance-agent", "finance-corp", "prn:finance:ledger-agent", RoleAgent, 24*time.Hour)
	tm.IssueToken("token-dev-agent", "dev-team", "prn:dev:code-agent", RoleAgent, 24*time.Hour)
	tm.IssueToken("token-admin-operator", "system-admin", "prn:admin:operator", RoleAdmin, 24*time.Hour)
	tm.IssueToken("token-platform-admin", "system-admin", "prn:admin:platform-admin", RolePlatformAdmin, 24*time.Hour)
	tm.IssueToken("token-security-admin", "system-admin", "prn:sec:security-admin", RoleSecurityAdmin, 24*time.Hour)
	tm.IssueToken("token-security-analyst", "finance-corp", "prn:sec:analyst", RoleSecurityAnalyst, 24*time.Hour)
	tm.IssueToken("token-platform-engineer", "dev-team", "prn:eng:engineer", RolePlatformEngineer, 24*time.Hour)
	tm.IssueToken("token-auditor", "system-admin", "prn:audit:auditor", RoleAuditor, 24*time.Hour)

	return tm
}

func (tm *TokenManager) IssueToken(tokenStr, tenantID, principalID string, role Role, duration time.Duration) *Token {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	t := &Token{
		TokenString: tokenStr,
		TenantID:    tenantID,
		PrincipalID: principalID,
		Role:        role,
		ExpiresAt:   time.Now().Add(duration),
		Revoked:     false,
	}
	tm.tokens[tokenStr] = t
	return t
}

func (tm *TokenManager) RevokeToken(tokenStr string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	t, ok := tm.tokens[tokenStr]
	if !ok {
		return fmt.Errorf("token not found")
	}
	t.Revoked = true
	return nil
}

func (tm *TokenManager) ValidateAuthHeader(authHeader string) (*AuthContext, error) {
	if authHeader == "" {
		return nil, ErrUnauthenticated
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, ErrUnauthenticated
	}
	rawToken := parts[1]

	tm.mu.RLock()
	defer tm.mu.RUnlock()

	token, ok := tm.tokens[rawToken]
	if !ok {
		return nil, ErrUnauthenticated
	}

	if token.Revoked {
		return nil, ErrTokenRevoked
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return &AuthContext{
		TenantID:    token.TenantID,
		PrincipalID: token.PrincipalID,
		Role:        token.Role,
	}, nil
}

// ComputeEventHMAC computes a cryptographic signature for an event payload
func ComputeEventHMAC(eventID, workloadID, secretKey string) string {
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(eventID))
	h.Write([]byte(workloadID))
	return hex.EncodeToString(h.Sum(nil))
}
