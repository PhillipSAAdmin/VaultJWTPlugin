package vault_backend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/golang-jwt/jwt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type JwtConfig struct {
	Audience    string
	Issuer      string
	Subject     string
	Expiration  int
	NotBefore   int
	IssuedAt    int
	PublicKeyId string
}

// Generate a random Private Key (RSA-2048, 4096, etc.) with a Certain Length

func GenRandomPrivateKey(length int) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)

	return string(privKeyPem)
}

func GenerateJWTFromConfig(config JwtConfig, private_key string, method jwt.SigningMethod) (string, error) {
	token := jwt.New(method)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["kid"] = config.PublicKeyId
	// Add other claims as needed

	// Decode private key
	privKeyBlock, _ := pem.Decode([]byte(private_key))
	if privKeyBlock == nil {
		return "", fmt.Errorf("No PEM data found")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("Failed to parse private key: %v", err)
	}

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("Failed to sign token: %v", err)
	}

	return tokenString, nil
}

func (b *JWKS_Vault_Backend) JWTConfigurationSet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

}
