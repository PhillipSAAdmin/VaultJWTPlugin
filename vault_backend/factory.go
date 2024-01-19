package vault_backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

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

func randomString(length int) {
	panic("unimplemented")
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
		Paths: []*framework.Path{
			// Add our paths here
			{
				Pattern: "random",
				Fields: map[string]*framework.FieldSchema{
					"length": {
						Type:        framework.TypeInt,
						Description: "The length of the random string to generate",
						Default:     123123,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathRandom,
					//logical.CreateOperation: b.pathRandomCreate,
				},
			},
			{
				Pattern: "config",
				Fields: map[string]*framework.FieldSchema{
					"random_string": {
						Type:        framework.TypeString,
						Description: "The random string to generate",
						Default:     "SDSDSD",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.randomConfigRead,
					//logical.CreateOperation: b.pathRandomCreate,
					//"create":              b.pathRandomCreate,
					"update": b.pathRandomCreate,
					//"delete":              b.pathRandomCreate,
				},
			},
			{
				Pattern: "config2",
				Fields: map[string]*framework.FieldSchema{
					"random_string": {
						Type:        framework.TypeString,
						Description: "The random string to generate",
						Default:     "SDSDSD",
					},
				},
				ExistenceCheck: b.checkExistence,
				Operations: map[logical.Operation]framework.OperationHandler{

					logical.ReadOperation: &framework.PathOperation{
						Callback: b.randomConfigRead,
						Summary:  "read Configuration Stufff",
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.pathRandomCreate,
						Summary:  "update Configuration Stufff",
					},
					logical.CreateOperation: &framework.PathOperation{
						Callback: b.pathRandomCreate,
						Summary:  "create Configuration Stufff",
					},
					logical.DeleteOperation: &framework.PathOperation{
						Callback: b.pathRandomDelete,
						Summary:  "delete Configuration Stufff",
					},
				},
			},
		},
		Secrets:     []*framework.Secret{},
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

func (b *JWKS_Vault_Backend) checkExistence(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {

	// Check If The Key random_string exists
	_, err := req.Storage.Get(ctx, "random_string")
	if err != nil {
		return false, err
	}

	return true, nil
}
