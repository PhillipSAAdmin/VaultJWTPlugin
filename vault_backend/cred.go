package vault_backend

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	jwks_vault_util "github.com/PhillipSAAdmin/JWKS_VAULT_PLUGIN/jwks_vault_util"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func credConfigPath(b *JWKS_Vault_Backend) *framework.Path {
	// This is the path that will be used grant credentials

	var credConfigPath = &framework.Path{
		Pattern: "cred/(?P<roleid>.*)",
		Fields: map[string]*framework.FieldSchema{
			"roleid": {
				Type:        framework.TypeString,
				Description: "The role id",
			},
			"Requested_TTL": {
				Type:        framework.TypeDurationSecond,
				Description: "The TTL for the token",
				Default:     3600,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.CredConfigRead,
				Summary:  "Get Current Configuration Of Role",
			},
		},
	}
	return credConfigPath
}

/**
 *
 * Logic Should Be As Follow
 *
 * Use the role-id to get the role config
 *
 * Check The Requested_TTL
 * Check The Max_TTL
 * Check the Max TTL for the Engine (using the engine name in the config for the role and the engine name in the config for the backend)
 *
 * If All These Check
 *
 * Grant a JWT TOken
 *
 * With The Subject From the Config For THe ROle
 * WIth the Issuer From the Config From the Backend
 * With the Audience From the Config From the Backend
 * With the Expiration From the Requested_TTL or the Max_TTL (Which ever is smaller)
 *
 * Sign The JWT Token With the Private Key From the Config From the Backend (Later Add Multiple Keys + Rotations)
 *
 * Return The JWT Token
 */
func (b *JWKS_Vault_Backend) CredConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the role-id from the request
	role_id, ok := data.Get("roleid").(string)
	if !ok {
		return nil, fmt.Errorf("Role ID Not Found")
	}
	// Get the role config from the storage
	role_config, err := req.Storage.Get(ctx, "user"+role_id)
	if err != nil {
		return nil, err
	}
	if role_config == nil {
		return nil, fmt.Errorf("Role Config Does Not Exist")
	}
	// Unmarshal the role confi

	var role_config_struct RoleConfigStorage

	err = role_config.DecodeJSON(&role_config_struct)
	if err != nil {
		return nil, err
	}

	// Get the engine name from the role config
	engine_name := role_config_struct.Engine

	// Get the Engine Config from the engine_name
	engine_config, err := req.Storage.Get(ctx, "config/"+engine_name)
	if err != nil {
		return nil, err
	}

	var engine_config_struct EngineConfigStorage

	// Unmarshal the backend config
	err = engine_config.DecodeJSON(&engine_config_struct)
	if err != nil {
		return nil, err
	}

	//Find Limiting TTL
	limiting_ttl := min(role_config_struct.Max_TTL, engine_config_struct.TTL)

	// Get the requested TTL from the request
	requested_ttl, ok := data.Get("Requested_TTL").(int)
	if !ok {
		return nil, fmt.Errorf("Requested TTL Not Found")
	}

	// Check if valid requested TTL
	if requested_ttl > limiting_ttl {
		return nil, fmt.Errorf("Requested TTL is greater than the max TTL")
	}

	// Get the subject from the role config
	subject := role_config_struct.Subject
	issuer := engine_config_struct.Issuer
	audience := engine_config_struct.Audience

	// Check if the role config exists
	if role_config == nil {
		return nil, fmt.Errorf("Role Config Does Not Exist")
	}

	// Check if the backend config exists
	if engine_config == nil {
		return nil, fmt.Errorf("Backend Config Does Not Exist")
	}

	// Check if the subject exists
	if subject == "" {
		return nil, fmt.Errorf("Subject Does Not Exist")
	}

	// Create a new JWT Token
	token := jwt.New(jwt.SigningMethodRS256)

	claims := token.Claims.(jwt.MapClaims)

	//Create a Key, Rather at the beggining of publishing

	//UUID
	keyid := uuid.New().String()

	//Generate a Random Private KEy
	privkey := jwks_vault_util.GenRandomPrivateKey(2048)
	pubkey := privkey.PublicKey

	// Store Public Key Bytes, Keep in DER
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&pubkey)
	if err != nil {
		return nil, err
	}

	// Convert Public Key to PEM Format
	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)

	// Store at key+keyid
	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "publickey" + keyid,
		Value: pubKeyPem,
	})

	if err != nil {
		return nil, err
	}

	// Store Private Key Bytes
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)

	// Store at privkey+keyid
	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "privatekey" + keyid,
		Value: privKeyPem,
	})

	if err != nil {
		return nil, err
	}

	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Duration(requested_ttl) * time.Second).Unix()
	claims["sub"] = subject
	claims["iss"] = issuer
	claims["aud"] = audience
	claims["kid"] = keyid

	token.Claims = claims

	// Sign the token with the private key
	tokenString, err := token.SignedString(privkey)

	// Check if the token was signed
	if err != nil {
		return nil, fmt.Errorf("Token Could Not Be Signed")
	}

	// Return the token
	return &logical.Response{
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{
				TTL: time.Duration(requested_ttl) * time.Second,
			},
			InternalData: map[string]interface{}{
				"token":    tokenString,
				"key_uuid": keyid,
			},
		},
		Data: map[string]interface{}{
			"token": tokenString,
		},
	}, nil

}

func (b *JWKS_Vault_Backend) RevokeCredentials(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//Remove Existence of UUID Key That Signed the credentials
	key := req.Secret.InternalData["key_uuid"]
	err := req.Storage.Delete(ctx, "publickey"+key.(string))

	if err != nil {
		return nil, err
	}
	err = req.Storage.Delete(ctx, "privatekey"+key.(string))
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *JWKS_Vault_Backend) RenewCredentials(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the Key PEM From The Storage
	key := req.Secret.InternalData["key_uuid"]

	// Get the private key from the Key Storage
	private_key_bytes, err := req.Storage.Get(ctx, "privatekey"+key.(string))
	if err != nil {
		return nil, err
	}
	// Decode it to rsa.PrivateKey and generate a new token
	private_key, err := jwt.ParseRSAPrivateKeyFromPEM(private_key_bytes.Value)
	if err != nil {
		return nil, err
	}

	// Create Jwt
	token := jwt.New(jwt.SigningMethodRS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Duration(req.Secret.LeaseOptions.TTL) * time.Second).Unix()
	claims["sub"] = req.Secret.InternalData["sub"]
	claims["iss"] = req.Secret.InternalData["iss"]
	claims["aud"] = req.Secret.InternalData["aud"]
	claims["kid"] = key

	token.Claims = claims

	// Sign the token with the private key
	tokenString, err := token.SignedString(private_key)

	// Check if the token was signed
	if err != nil {
		return nil, fmt.Errorf("Token Could Not Be Signed")
	}

	// Return the token
	return &logical.Response{
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{
				TTL: req.Secret.LeaseOptions.TTL,
			},
			InternalData: map[string]interface{}{
				"token":    tokenString,
				"key_uuid": key,
			},
		},
		Data: map[string]interface{}{
			"token": tokenString,
		},
	}, nil

}
