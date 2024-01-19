package vault_backend

import (
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt"
)

// Test Creation of Public Key and That JWT is Signed Correctly

func TestJWTGen(t *testing.T) {

	// Generate a Random Private Key
	private_key := GenRandomPrivateKey(2048)

	// Generate a JWT
	jwt_token, err := GenerateJWTFromConfig(JwtConfig{
		Audience:    "aud",
		Issuer:      "iss",
		Subject:     "sub",
		Expiration:  3600,
		NotBefore:   0,
		IssuedAt:    0,
		PublicKeyId: "kid",
	}, private_key, jwt.SigningMethodRS256)

	if err != nil {
		t.Errorf("Failed to generate JWT: %v", err)
	}

	// Verify JWT
	token, err := jwt.Parse(jwt_token, func(token *jwt.Token) (interface{}, error) {
		return &private_key.PublicKey, nil
	})

	fmt.Println(token.Claims)
	t.Log(token.Claims)

	if err != nil {
		t.Errorf("Failed to verify JWT: %v", err)
	}
}
