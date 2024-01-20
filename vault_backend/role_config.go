package vault_backend

import (
	"context"
	"fmt"

	"github.com/PhillipSAAdmin/JWKS_VAULT_PLUGIN/enumerations"
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
		Pattern: "role/(?P<roleid>.*)", //, string(enumerations.RoleConfigRoleid)), //"config/role/(?P<role-id>.*)",
		Fields: map[string]*framework.FieldSchema{
			"roleid": {
				Type:        framework.TypeString,
				Description: "The role id",
			},
			string(enumerations.RoleConfigTTL): {
				Type:        framework.TypeDurationSecond,
				Description: "The TTL for the token",
			},
			string(enumerations.RoleConfigSubject): {
				Type:        framework.TypeString,
				Description: "The subject for the token",
			},
			string(enumerations.RoleConfigEngineId): {
				Type:        framework.TypeString,
				Description: "The engine for the token",
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
	//role_id := strings.Split(req.Path, "/")[2]

	role_id := req.Data[string(enumerations.RoleConfigRoleid)].(string)

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
	max_ttl, ok := req.Data[string(enumerations.RoleConfigTTL)].(int)
	if !ok {
		return nil, fmt.Errorf("No %s found, Or Not Int", string(enumerations.RoleConfigTTL))
	}

	// Subject For Role
	subject, ok := req.Data[string(enumerations.RoleConfigSubject)].(string)
	if !ok {
		return nil, fmt.Errorf("No %s found, Or Not String", string(enumerations.RoleConfigSubject))
	}

	// Engine For Role
	engine, ok := req.Data[string(enumerations.RoleConfigEngineId)].(string)
	if !ok {
		return nil, fmt.Errorf("No %s found, Or Not String", string(enumerations.RoleConfigEngineId))
	}

	// Role For Role
	role, ok := data.Get("roleid").(string) //req.Data[string(enumerations.RoleConfigRoleid)].(string)
	if !ok {
		return nil, fmt.Errorf("No %s found, Or Not String", string(enumerations.RoleConfigRoleid))
	}

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
	role_id, ok := req.Data[string(enumerations.RoleConfigRoleid)].(string)
	if !ok {
		return nil, fmt.Errorf("No %s found, Or Not String", string(enumerations.RoleConfigRoleid))
	}

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

	role_id := req.Data[string(enumerations.RoleConfigRoleid)].(string)

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
