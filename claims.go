package jwtauth

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Claims for token.
type Claims interface {
	jwt.Claims
}

// SimpleClaims define simple claims.
type SimpleClaims struct {
	TokenUse  string `json:"token_use"`
	Issuer    string `json:"iss"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	ClientID  string `json:"client_id"`

	ExpectedIssuer   string `json:"-"`
	ExpectedClientID string `json:"-"`
	ExpectedTokenUse string `json:"-"`

	timeNow func() time.Time `json:"-"` // added for tests purposes
}

// Valid implements jwt.Claims interface
func (c *SimpleClaims) Valid() error {
	const op = "StandardClaims.Valid"
	timeNow := c.timeNow
	if timeNow == nil {
		timeNow = time.Now
	}
	now := timeNow().Unix()

	if !c.verifyExpiresAt(now) {
		return &jwt.ValidationError{
			Inner:  errors.New("token expired"),
			Errors: jwt.ValidationErrorExpired,
		}
	}
	if !c.verifyIssuedAt(now) {
		return &jwt.ValidationError{
			Inner:  errors.New("invalid token claims issued at"),
			Errors: jwt.ValidationErrorIssuedAt,
		}
	}
	if !c.verifyClientID() {
		return &jwt.ValidationError{
			Inner:  errors.New("invalid token claims app client id"),
			Errors: jwt.ValidationErrorClaimsInvalid,
		}
	}
	if !c.verifyIssuer() {
		return &jwt.ValidationError{
			Inner:  errors.New("invalid token claims issuer"),
			Errors: jwt.ValidationErrorIssuer,
		}
	}
	if !c.verityTokenUse() {
		return &jwt.ValidationError{
			Inner:  errors.New("invalid token claims token use"),
			Errors: jwt.ValidationErrorClaimsInvalid,
		}
	}

	return nil
}

func (c *SimpleClaims) verifyExpiresAt(now int64) bool {
	return now <= c.ExpiresAt
}

func (c *SimpleClaims) verifyIssuedAt(now int64) bool {
	return now >= c.IssuedAt
}

func (c *SimpleClaims) verifyClientID() bool {
	return c.ClientID == c.ExpectedClientID
}

func (c *SimpleClaims) verifyIssuer() bool {
	return c.Issuer == c.ExpectedIssuer
}

func (c *SimpleClaims) verityTokenUse() bool {
	return c.TokenUse == c.ExpectedTokenUse
}
