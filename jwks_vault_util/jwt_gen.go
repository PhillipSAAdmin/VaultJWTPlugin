package jwks_vault_util

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
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

func GenRandomPrivateKey(length int) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}

	return privateKey
}

func GenerateJWTFromConfig(config JwtConfig, private_key *rsa.PrivateKey, method jwt.SigningMethod) (string, error) {
	token := jwt.New(method)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["kid"] = config.PublicKeyId
	// Add other claims as needed
	claims["aud"] = config.Audience
	claims["iss"] = config.Issuer
	claims["sub"] = config.Subject
	// claims["iat"] =
	claims["exp"] = time.Now().Add(time.Duration(config.Expiration) * time.Second).Unix()
	claims["iat"] = time.Now().Unix()

	// Sign and get the complete encoded token as a string
	token.Claims = claims

	// Does THis Sign The ENtire Thing ???
	tokenString, err := token.SignedString(private_key)
	if err != nil {
		return "", fmt.Errorf("Failed to sign token: %v", err)
	}
	return tokenString, nil
}

func VerifyJWTString(tokenString string, public_key *rsa.PublicKey) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return public_key, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}
