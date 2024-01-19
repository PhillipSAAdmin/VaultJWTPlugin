package vault_backend

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type RoleConfigStorage struct {
	Subject string
	Max_TTL int
	Engine  string
	Role    string
}

func roleConfigPath(b *JWKS_Vault_Backend) *framework.Path {
	var roleConfigPath = &framework.Path{
		Pattern: "config/role/<role-id>",
		Fields: map[string]*framework.FieldSchema{
			"TTL": {
				Type:        framework.TypeDurationSecond,
				Description: "The TTL for the token",
			},
			"Subject": {
				Type:        framework.TypeString,
				Description: "The subject for the token",
			},
			"Engine": {
				Type:        framework.TypeString,
				Description: "The engine for the token",
			},
			"Role": {
				Type:        framework.TypeString,
				Description: "The role for the token",
				Default:     "default",
			},
		},
		ExistenceCheck: b.RoleConfigExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.RoleConfigRead,
				Summary:  "Get Current Configuration Of Role",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.RoleConfigWrite,
				Summary:  "Set Configuration Of Role",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.RoleConfigWrite,
				Summary:  "Set Configuration Of Role",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.RoleConfigDelete,
				Summary:  "Set Configuration Of Role",
			},
		},
	}
	return roleConfigPath
}

func (b *JWKS_Vault_Backend) RoleConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	// Get Role ID From Path (role_id)
	role_id := strings.Split(req.Path, "/")[2]

	// Get The Config (Previous Stored as logical.StorageEntryJSON)
	entry, err := req.Storage.Get(ctx, "user"+role_id)

	if err != nil {
		return false, err
	}

	if entry == nil {
		return false, nil
	}

	return true, nil
}

func (b *JWKS_Vault_Backend) RoleConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Want to Write Configuration Parameters to the Storage Backend

	// Max TTL to Request
	max_ttl := req.Data["TTL"].(int)

	// Subject For Role
	subject := req.Data["Subject"].(string)

	// Engine For Role
	engine := req.Data["Engine"].(string)

	// Role For Role
	role := req.Data["Role"].(string)

	// Write to Storage Backend as JSON, Using Role of Current User
	key_user := "user" + role

	// Write to Storage Backend, key_user as key and Json of Type RoleConfigStorage as Value
	entry, err := logical.StorageEntryJSON(key_user, RoleConfigStorage{
		Subject: subject,
		Max_TTL: max_ttl,
		Engine:  engine,
		Role:    role,
	})

	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)

	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"subject_entered": subject,
			"max_ttl":         max_ttl,
			"engine":          engine,
			"role":            role,
		},
	}, nil

}

func (b *JWKS_Vault_Backend) RoleConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// Get Role ID From Path (role_id)
	role_id := strings.Split(req.Path, "/")[2]

	// Get The Config (Previous Stored as logical.StorageEntryJSON)
	entry, err := req.Storage.Get(ctx, "user"+role_id)

	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("No config found for role %s", role_id)
	}

	var config RoleConfigStorage
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"config": config,
		},
	}, nil
}

func (b *JWKS_Vault_Backend) RoleConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	//
	// Get Role ID From Path (role_id)

	role_id := strings.Split(req.Path, "/")[1]

	// Get The Config (Previous Stored as logical.StorageEntryJSON)

	entry, err := req.Storage.Get(ctx, "user"+role_id)

	if err != nil {

		return nil, err

	}

	if entry == nil {

		return nil, fmt.Errorf("No config found for role %s", role_id)

	}

	// Delete The Config

	err = req.Storage.Delete(ctx, "user"+role_id)

	if err != nil {

		return nil, err

	}

	return &logical.Response{
		Data: map[string]interface{}{
			"config": "deleted",
		},
	}, nil
}
