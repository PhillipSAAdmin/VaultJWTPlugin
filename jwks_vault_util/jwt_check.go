package jwks_vault_util

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt"
	"github.com/hashicorp/vault/sdk/logical"
)

// Function That Takes the Logical Storage, and the Key id, and returns the Public Key (Just The Bytes)

func GetPublicKeyFromStorage(storage logical.Storage, key_id string) ([]byte, error) {

	// Read the Public Key from the Storage
	entry, err := storage.Get(context.Background(), "publickey"+key_id)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("No Public Key Found")
	}

	// Convert the Public Key to Bytes
	public_key := entry.Value

	return public_key, nil
}

// Function Takes a JWT string and a Public Key  (Just The Bytes) and Verifies the JWT (returns JWT, error)

func VerifyJWT(json_token string, public_key []byte) (*jwt.Token, error) {

	// Convert public_key to rsa.PublicKey

	pub_key, err := jwt.ParseRSAPublicKeyFromPEM(public_key)

	// Verify Token Signature
	token, err := jwt.Parse(json_token, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// Return the public key
		return pub_key, nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}
