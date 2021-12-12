package jwtauth

import (
	"crypto/rsa"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// Validator validates a Token.
type Validator struct {
	publicKey *rsa.PublicKey
}

// NewValidator creates a new jwt validator.
func NewValidator(publicKey []byte) (*Validator, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}
	return &Validator{publicKey: key}, nil
}

// Validate validates the passed token using the public key.
func (v *Validator) Validate(token string, claims Claims) error {
	_, err := jwt.ParseWithClaims(token, claims, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return v.publicKey, nil
	})
	if err != nil {
		return fmt.Errorf("validate token: %w", err)
	}
	return nil
}
