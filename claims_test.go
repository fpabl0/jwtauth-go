package jwtauth

import (
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimpleClaimsValid(t *testing.T) {
	c := SimpleClaims{
		ExpectedClientID: "my-client-id",
		ExpectedIssuer:   "cognito",
		ExpectedTokenUse: "access",
		timeNow:          mockTime("09:15:53"),
	}

	// --- Verify expiration
	c.ExpiresAt = mockTime("08:10:21")().Unix()
	err := c.Valid()
	require.Error(t, err)
	verr := err.(*jwt.ValidationError)
	assert.Equal(t, verr.Errors, jwt.ValidationErrorExpired)
	require.Error(t, verr.Inner)
	assert.Equal(t, "token expired", verr.Inner.Error())

	// clear for next test
	c.ExpiresAt = mockTime("10:15:00")().Unix()

	// --- Verify issued at
	c.IssuedAt = mockTime("11:37:11")().Unix()
	err = c.Valid()
	require.Error(t, err)
	verr = err.(*jwt.ValidationError)
	assert.Equal(t, verr.Errors, jwt.ValidationErrorIssuedAt)
	require.Error(t, verr.Inner)
	assert.Equal(t, "invalid token claims issued at", verr.Inner.Error())

	// clear for next test
	c.IssuedAt = mockTime("09:00:00")().Unix()

	// --- Verify app client id
	c.ClientID = "hacker-client"
	err = c.Valid()
	require.Error(t, err)
	verr = err.(*jwt.ValidationError)
	assert.Equal(t, verr.Errors, jwt.ValidationErrorClaimsInvalid)
	require.Error(t, verr.Inner)
	assert.Equal(t, "invalid token claims app client id", verr.Inner.Error())

	// clear for next test
	c.ClientID = "my-client-id"

	// --- Verify issuer
	c.Issuer = "hacker-issuer"
	err = c.Valid()
	require.Error(t, err)
	verr = err.(*jwt.ValidationError)
	assert.Equal(t, verr.Errors, jwt.ValidationErrorIssuer)
	require.Error(t, verr.Inner)
	assert.Equal(t, "invalid token claims issuer", verr.Inner.Error())

	// clear for next test
	c.Issuer = "cognito"

	// --- Verify token use
	c.TokenUse = "id"
	err = c.Valid()
	require.Error(t, err)
	verr = err.(*jwt.ValidationError)
	assert.Equal(t, verr.Errors, jwt.ValidationErrorClaimsInvalid)
	require.Error(t, verr.Inner)
	assert.Equal(t, "invalid token claims token use", verr.Inner.Error())

	// clear for next test
	c.TokenUse = "access"

	// --- Valid ok no errors
	err = c.Valid()
	assert.NoError(t, err)
}

// ===============================================================
// Privates
// ===============================================================

func mockTime(hourStr string) func() time.Time {
	return func() time.Time {
		tm, err := time.ParseInLocation("2006 15:04:05", fmt.Sprintf("2021 %s", hourStr), time.Local)
		if err != nil {
			panic(err)
		}
		return tm
	}
}
