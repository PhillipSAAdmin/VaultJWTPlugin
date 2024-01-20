package vault_backend

import (
	"context"

	"github.com/PhillipSAAdmin/JWKS_VAULT_PLUGIN/jwks_vault_util"
	"github.com/golang-jwt/jwt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func checkConfigPath(b *JWKS_Vault_Backend) *framework.Path {
	var checkConfigPath = &framework.Path{
		Pattern: "verify",
		Fields: map[string]*framework.FieldSchema{
			"JWT": {
				Type:        framework.TypeString,
				Description: "The JWT to check",
			},
		},
		ExistenceCheck: b.CheckConfigExistence,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.CheckConfigRead,
		},
	}
	return checkConfigPath
}

func (b *JWKS_Vault_Backend) CheckConfigExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	return true, nil
}

func (b *JWKS_Vault_Backend) CheckConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	jwt_string := data.Get("JWT").(string)

	// Create JWT from JWT String
	jwt_token, err := jwt.Parse(jwt_string, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	kid, ok := jwt_token.Claims.(jwt.MapClaims)["kid"].(string)
	if !ok {
		return nil, err
	}

	key_bytes, err := jwks_vault_util.GetPublicKeyFromStorage(req.Storage, kid)
	if err != nil {
		return nil, err
	}

	// Use KeyBytes and JWT to Verify the JWT
	_, err = jwks_vault_util.VerifyJWT(jwt_string, key_bytes)

	if err != nil {
		return nil, err
	}

	// Find The key for the Token (engineID)

	return &logical.Response{
		Data: map[string]interface{}{
			"valid": true,
		},
	}, nil
}
