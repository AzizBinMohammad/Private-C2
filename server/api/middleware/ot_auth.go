package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// OTAuthToken represents an authentication token for OT assessment operations.
// Provides time-limited, scope-restricted access for OT operators.
type OTAuthToken struct {
	TokenID      string    `json:"token_id"`
	OperatorID   string    `json:"operator_id"`
	EngagementID string    `json:"engagement_id"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        []string  `json:"scope"` // Allowed operations
	ApprovedBy   string    `json:"approved_by,omitempty"` // Second operator for dual auth
	Revoked      bool      `json:"revoked"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedBy    string    `json:"revoked_by,omitempty"`
}

// OTAuthManager manages OT authentication tokens.
type OTAuthManager struct {
	mu     sync.RWMutex
	tokens map[string]*OTAuthToken
	// MaxTokenLifetime is the maximum duration a token can be valid.
	MaxTokenLifetime time.Duration
	// RequireDualAuth requires a second operator to approve token issuance.
	RequireDualAuth bool
}

// NewOTAuthManager creates a new OT auth manager.
func NewOTAuthManager(maxLifetime time.Duration, dualAuth bool) *OTAuthManager {
	return &OTAuthManager{
		tokens:           make(map[string]*OTAuthToken),
		MaxTokenLifetime: maxLifetime,
		RequireDualAuth:  dualAuth,
	}
}

// IssueToken creates a new OT auth token.
func (m *OTAuthManager) IssueToken(ctx context.Context, operatorID, engagementID string, scope []string, duration time.Duration, approvedBy string) (*OTAuthToken, error) {
	// Verify the operator has ot.assess permission
	role := GetOperatorRole(ctx)
	if !HasPermission(role, PermOTAssess) {
		return nil, fmt.Errorf("operator does not have ot.assess permission")
	}

	// Enforce dual auth if required
	if m.RequireDualAuth && approvedBy == "" {
		return nil, fmt.Errorf("dual authorization required: approved_by must be set")
	}
	if m.RequireDualAuth && approvedBy == operatorID {
		return nil, fmt.Errorf("dual authorization requires a different approving operator")
	}

	// Enforce max lifetime
	if duration > m.MaxTokenLifetime {
		duration = m.MaxTokenLifetime
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	now := time.Now()
	token := &OTAuthToken{
		TokenID:      hex.EncodeToString(tokenBytes),
		OperatorID:   operatorID,
		EngagementID: engagementID,
		IssuedAt:     now,
		ExpiresAt:    now.Add(duration),
		Scope:        scope,
		ApprovedBy:   approvedBy,
	}

	m.mu.Lock()
	m.tokens[token.TokenID] = token
	m.mu.Unlock()

	return token, nil
}

// ValidateToken checks if a token is valid and returns it.
func (m *OTAuthManager) ValidateToken(tokenID string) (*OTAuthToken, error) {
	m.mu.RLock()
	token, ok := m.tokens[tokenID]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("token not found")
	}

	if token.Revoked {
		return nil, fmt.Errorf("token has been revoked")
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	return token, nil
}

// RevokeToken revokes an OT auth token.
func (m *OTAuthManager) RevokeToken(tokenID, revokedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	token, ok := m.tokens[tokenID]
	if !ok {
		return fmt.Errorf("token not found")
	}

	now := time.Now()
	token.Revoked = true
	token.RevokedAt = &now
	token.RevokedBy = revokedBy

	return nil
}

// RevokeAllForEngagement revokes all tokens for an engagement.
func (m *OTAuthManager) RevokeAllForEngagement(engagementID, revokedBy string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	now := time.Now()
	for _, token := range m.tokens {
		if token.EngagementID == engagementID && !token.Revoked {
			token.Revoked = true
			token.RevokedAt = &now
			token.RevokedBy = revokedBy
			count++
		}
	}

	return count
}

// CleanExpired removes expired tokens from the store.
func (m *OTAuthManager) CleanExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	count := 0
	for id, token := range m.tokens {
		if now.After(token.ExpiresAt) {
			delete(m.tokens, id)
			count++
		}
	}

	return count
}

// ListActiveTokens returns all active (non-revoked, non-expired) tokens for an engagement.
func (m *OTAuthManager) ListActiveTokens(engagementID string) []*OTAuthToken {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var active []*OTAuthToken
	now := time.Now()
	for _, token := range m.tokens {
		if token.EngagementID == engagementID && !token.Revoked && now.Before(token.ExpiresAt) {
			active = append(active, token)
		}
	}

	return active
}

// HasScope checks if a token authorizes a specific operation.
func (t *OTAuthToken) HasScope(operation string) bool {
	for _, s := range t.Scope {
		if s == operation || s == "*" {
			return true
		}
	}
	return false
}

// IsValid checks if the token is currently valid.
func (t *OTAuthToken) IsValid() bool {
	return !t.Revoked && time.Now().Before(t.ExpiresAt)
}

// TimeRemaining returns the time until the token expires.
func (t *OTAuthToken) TimeRemaining() time.Duration {
	remaining := time.Until(t.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}
