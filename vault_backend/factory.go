package vault_backend

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type JWKS_Vault_Backend struct {
	*framework.Backend
	lock sync.RWMutex
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {

	// Create a new instance of our backend
	b := backend()

	// Initialize the backend
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	// Return the backend
	return b, nil
}

func (b *JWKS_Vault_Backend) pathRandomDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	//Delete Storage Random Key
	err := req.Storage.Delete(ctx, "random_string")
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"random": "s",
		},
	}, nil
}

func backend() *JWKS_Vault_Backend {
	var b = JWKS_Vault_Backend{}
	b.Backend = &framework.Backend{
		Help: "Generate a Random Key That Delegates Tokens For a Path",
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: CreateBackend(&b),
		Secrets: []*framework.Secret{
			// token : string
			{Type: "token",
				Fields: map[string]*framework.FieldSchema{
					"token": {
						Type:        framework.TypeString,
						Description: "The token.",
					},
				},
				Renew:  b.RenewCredentials,
				Revoke: b.RevokeCredentials,
			},
		},
		BackendType: logical.TypeLogical,
	}
	// Initialize our backend
	//b.Backend.Initialize()
	return &b
}

func (b *JWKS_Vault_Backend) randomConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	return &logical.Response{
		Data: map[string]interface{}{
			"random_string": "SDSDSD",
		},
	}, nil
}

func CreateBackend(b *JWKS_Vault_Backend) []*framework.Path {

	paths := []*framework.Path{
		engineConfigPath(b),
		roleConfigPath(b),
		credConfigPath(b),
		//Test Reach
		{
			Pattern: "test",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.testReach,
					Summary:  "Test Reach",
				},
			},
		},
	}

	return paths
}
