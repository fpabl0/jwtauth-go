package jwtauth

import (
	"crypto/rsa"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// Generator defines token generator.
type Generator struct {
	privateKey *rsa.PrivateKey
}

// NewGenerator creates a new token generator.
func NewGenerator(privateKey []byte) (*Generator, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}
	return &Generator{
		privateKey: key,
	}, nil
}

// GenerateToken generates a token signed with the private key.
func (g *Generator) GenerateToken(claims Claims) (string, error) {
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(g.privateKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}
	return token, nil
}
