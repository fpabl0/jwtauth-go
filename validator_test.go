package jwtauth

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testClaims struct {
	SimpleClaims
	Role string `json:"role"`
}

func TestValidator(t *testing.T) {
	privateKey, err := os.ReadFile("test_data/private_key.pem")
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	publicKey, err := os.ReadFile("test_data/public_key.pem")
	require.NoError(t, err)
	require.NotNil(t, publicKey)

	g, err := NewGenerator(privateKey)
	require.NoError(t, err)
	require.NotNil(t, g)

	now := time.Now()

	tk, err := g.GenerateToken(&testClaims{
		Role: "admin",
		SimpleClaims: SimpleClaims{
			TokenUse:  "access",
			Issuer:    "otter",
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(1 * time.Minute).Unix(),
			ClientID:  "otter-client",
		},
	})
	require.NoError(t, err)

	v, err := NewValidator(publicKey)
	require.NoError(t, err)
	require.NotNil(t, v)

	claims := &testClaims{
		SimpleClaims: SimpleClaims{
			ExpectedIssuer:   "otter",
			ExpectedClientID: "otter-client",
			ExpectedTokenUse: "access",
		},
	}
	err = v.Validate(tk, claims)
	require.NoError(t, err)

	assert.Equal(t, "admin", claims.Role)
}

func TestValidator_MismatchKeys(t *testing.T) {
	privateKey, err := os.ReadFile("test_data/other_private_key.pem")
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	publicKey, err := os.ReadFile("test_data/public_key.pem")
	require.NoError(t, err)
	require.NotNil(t, publicKey)

	g, err := NewGenerator(privateKey)
	require.NoError(t, err)
	require.NotNil(t, g)

	now := time.Now()

	tk, err := g.GenerateToken(&testClaims{
		Role: "admin",
		SimpleClaims: SimpleClaims{
			TokenUse:  "access",
			Issuer:    "otter",
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(1 * time.Minute).Unix(),
			ClientID:  "otter-client",
		},
	})
	require.NoError(t, err)

	v, err := NewValidator(publicKey)
	require.NoError(t, err)
	require.NotNil(t, v)

	claims := &testClaims{
		SimpleClaims: SimpleClaims{
			ExpectedIssuer:   "otter",
			ExpectedClientID: "otter-client",
			ExpectedTokenUse: "access",
		},
	}
	err = v.Validate(tk, claims)
	require.Error(t, err)
	assert.Equal(t, "validate token: crypto/rsa: verification error", err.Error())
}
