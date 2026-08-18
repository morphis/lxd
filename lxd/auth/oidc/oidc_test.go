package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/canonical/lxd/lxd/auth/encryption"
	"github.com/canonical/lxd/lxd/db/cluster"
)

// Test_verifySessionToken_expiredReturnsSessionID verifies that verifySessionToken returns the parsed session ID
// when the session token has expired. This ensures the caller can drive the refresh flow instead of dereferencing
// a nil pointer.
func Test_verifySessionToken_expiredReturnsSessionID(t *testing.T) {
	clusterUUID := uuid.Must(uuid.NewRandom()).String()
	sessionID := uuid.Must(uuid.NewV7())

	secret := cluster.AuthSecret{
		Value:        make([]byte, 64),
		CreationDate: time.Now().UTC().Add(-time.Hour),
	}

	verifier := &Verifier{
		clusterUUID: clusterUUID,
		secretsFunc: func(ctx context.Context) (cluster.AuthSecrets, error) {
			return cluster.AuthSecrets{secret}, nil
		},
	}

	expiredAt := time.Now().UTC().Add(-time.Minute)
	sessionToken, err := encryption.GetOIDCSessionToken(secret.Value, sessionID, clusterUUID, expiredAt)
	require.NoError(t, err)

	returnedID, _, err := verifier.verifySessionToken(context.Background(), sessionToken)
	require.Error(t, err)
	assert.True(t, errors.Is(err, jwt.ErrTokenExpired), "Expected error to wrap jwt.ErrTokenExpired, got: %v", err)
	assert.NotNil(t, returnedID, "Expected returned session ID to be non-nil on expiry path")
	assert.Equal(t, sessionID, *returnedID)
}
