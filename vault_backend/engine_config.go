package vault_backend

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	jwks_vault_util "github.com/PhillipSAAdmin/JWKS_VAULT_PLUGIN/jwks_vault_util"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type EngineConfigStorage struct {
	Id              string
	AllowedSubjects []string
	Issuer          string
	Audience        string
	TTL             int
}

func engineConfigPath(b *JWKS_Vault_Backend) *framework.Path {
	var engineConfigPath = &framework.Path{
		Pattern: "config/(?P<engineid>.*)",
		Fields: map[string]*framework.FieldSchema{
			"engineid": {
				Type:        framework.TypeString,
				Description: "The engine id",
			},
			"TTL": {
				Type:        framework.TypeDurationSecond,
				Description: "The TTL for the token",
				Default:     3600,
			},
			"Audience": {
				Type:        framework.TypeString,
				Description: "The audience for the token",
				Default:     "vault",
			},
			"Issuer": {
				Type:        framework.TypeString,
				Description: "The issuer for the token",
				Default:     "vault",
			},
			"Allowed_Subjects": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Allowed Subjects For Token",
				Default:     "vault",
			},
		},
		ExistenceCheck: b.EngineConfigExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.EngineConfigRead,
				Summary:  "Get Current Configuration Of Engine",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.EngineConfigWrite,
				Summary:  "Set Configuration Of Engine",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.EngineConfigWrite,
				Summary:  "Set Configuration Of Engine",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.EngineConfigDelete,
				Summary:  "Delete Configuration Of Engine",
			},
		},
	}
	return engineConfigPath
}

func (b *JWKS_Vault_Backend) EngineConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	//Get Engine ID From Path (jwt_engine)
	//jwt_engine := strings.Split(req.Path, "/")[1]
	//jwt_engine, ok := req.Data["engineid"].(string)
	jwt_engine, ok := data.Get("engineid").(string)
	if !ok {
		return false, fmt.Errorf("No Engine ID Specified")
	}

	if jwt_engine == "" {
		return false, fmt.Errorf("No Engine ID Specified")
	}

	// Check If Engine Exists
	entry, err := req.Storage.Get(ctx, "config/"+jwt_engine)

	if err != nil {
		return false, err
	}

	if entry == nil {
		return false, nil
	}

	return true, nil
}

func (b *JWKS_Vault_Backend) EngineConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	//Get Engine ID From Path (jwt_engine)
	//jwt_engine := strings.Split(req.Path, "/")[1]
	jwt_engine := data.Get("engineid").(string)

	allowed_subjects, ok := data.Get("Allowed_Subjects").([]string)
	if !ok {
		return nil, fmt.Errorf("Subject must be a string List")
	}

	issuer, ok := data.Get("Issuer").(string)
	if !ok {
		return nil, fmt.Errorf("Issuer must be a string")
	}
	audience, ok := data.Get("Audience").(string)
	if !ok {
		return nil, fmt.Errorf("Audience must be a string")
	}

	expiration, ok := data.Get("TTL").(int)

	if !ok {
		return nil, fmt.Errorf("Expiration must be an int")
	}

	//FOr Now Just Create 1 Single Private - Public Key Pair

	private_key := jwks_vault_util.GenRandomPrivateKey(2048)

	public_key := private_key.PublicKey

	// Store Each Of these Keys in the Storage Backend
	// Convert Private Key to PEM Format
	privKeyBytes := x509.MarshalPKCS1PrivateKey(private_key)
	privKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)

	// Convert Public Key to PEM Format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&public_key)
	if err != nil {
		return nil, err
	}
	// Create an Entry for the Private Key

	// Create an Entry for the Public Key

	req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "private_key" + jwt_engine,
		Value: privKeyPem,
	})

	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)

	req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "public_key" + jwt_engine,
		Value: pubKeyPem,
	})

	// Now Store This Information Into Engine Config
	entry, err := logical.StorageEntryJSON("config/"+jwt_engine, &EngineConfigStorage{
		Id:              jwt_engine,
		AllowedSubjects: allowed_subjects,
		Issuer:          issuer,
		Audience:        audience,
		TTL:             expiration,
	})
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	//Return Config Object To User

	return &logical.Response{
		Data: map[string]interface{}{
			"config": entry.Value,
		},
	}, nil
}

func (b *JWKS_Vault_Backend) EngineConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	//Get Authenticated Role of Vault USer
	//role := req.EntityID
	//role := data.Get("role").(string)

	//Get ENgine Id From Path
	//jwt_engine := strings.Split(req.Path, "/")[1]
	jwt_engine := data.Get("engineid").(string)

	// Get The Config (Previous Stored as logical.StorageEntryJSON)
	entry, err := req.Storage.Get(ctx, "config/"+jwt_engine)

	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("No config found for engine %s", jwt_engine)
	}

	var config2 EngineConfigStorage
	if err := entry.DecodeJSON(&config2); err != nil {
		return nil, err
	}

	data2 := map[string]interface{}{
		"config": config2,
	}

	return &logical.Response{
		Data: data2,
	}, nil

	// If Not Root User, Check If User Has Access To Engine
	// Get The Config (Previous Stored as logical.StorageEntryJSON)
	entry, err = req.Storage.Get(ctx, "config/"+jwt_engine)
	if err != nil {
		return nil, err
	}
	//Check If One of the Allowed Subjects
	var config EngineConfigStorage
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	// Check If User Has Access To Engine

	data3 := map[string]interface{}{
		"config": config,
	}

	return &logical.Response{
		Data: data3,
	}, nil

	return nil, fmt.Errorf("User %s does not have access to engine %s", req.EntityID, jwt_engine)
}

func (b *JWKS_Vault_Backend) EngineConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	//Delete Associated Keys
	jwt_engine := strings.Split(req.Path, "/")[1]
	private_key_to_delete := "private_key" + jwt_engine
	req.Storage.Delete(ctx, private_key_to_delete)

	// Also, Delete Public Key
	public_key_to_delete := "public_key" + jwt_engine
	req.Storage.Delete(ctx, public_key_to_delete)

	//Also Delete Config For Engine
	config_to_delete := "config/" + jwt_engine
	req.Storage.Delete(ctx, config_to_delete)

	return &logical.Response{
		Data: map[string]interface{}{
			"config": "Config Deleted",
		},
	}, nil
}
