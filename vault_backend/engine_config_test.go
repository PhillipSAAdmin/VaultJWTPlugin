package vault_backend

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/PhillipSAAdmin/JWKS_VAULT_PLUGIN/enumerations"
	"github.com/golang-jwt/jwt"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfigWrite(t *testing.T) {
	// Create a new backend
	b, storage := getTestBackend(t)

	// Prepare the data for the write operation
	data := map[string]interface{}{
		// ... other data ...
		"TTL":              3600,
		"Audience":         "vault",
		"Issuer":           "vault",
		"Allowed_Subjects": []string{"vault"},
	}

	// Create a new request
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "test/447",
		Data:      data,
		Storage:   storage,
	}

	// Call the function to test
	resp, err := b.HandleRequest(context.Background(), req)
	t.Log(resp.Error())
	t.Log(resp.Data)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Check the response
	// ...
	if resp == nil {
		t.Fatalf("resp is nil")
	}

	req2 := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "test/1235",
		Storage:   storage,
		Data:      data,
	}

	resp2, err2 := b.HandleRequest(context.Background(), req2)
	t.Log(resp2.Error())
	t.Log(resp2.Data)
	if err2 != nil {
		t.Fatalf("err: %s", err2)
	}

}

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	// Create a new backend

	// Create a new in-memory storage
	//storage := &logical.InmemStorage{}
	//config := logical.TestBackendConfig()

	b := backend()
	storage := &logical.InmemStorage{}

	/*configReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/4",
		Storage:   storage,
	}
	if _, err := b.HandleRequest(context.Background(), configReq); err != nil {
		t.Fatal(err)
	}*/
	return b, storage
}

func TestConfigWrite2(t *testing.T) {
	// Create a new backend
	b, storage := getTestBackend(t)

	engineid := "447"

	// Prepare the data for the write operation
	data := map[string]interface{}{
		// ... other data ...
		"TTL":              3600,
		"Audience":         "vault",
		"Issuer":           "vault",
		"Allowed_Subjects": []string{"vault", "user", "sice"},
	}

	// Create a new request
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("config/%s", engineid),
		Data:      data,
		Storage:   storage,
	}

	// Call the function to test
	resp, err := b.HandleRequest(context.Background(), req)
	t.Log("Data + Error")
	var data2 map[string]interface{}
	t.Log(resp.Data)

	var bytes []byte = resp.Data["config"].([]byte)

	//Json Decode It
	err = json.Unmarshal(bytes, &data2)

	t.Log(data2)

	t.Log(resp.Error())
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Check the response
	// ...
	if resp == nil {
		t.Fatalf("resp is nil")
	}

	req2 := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("config/%s", engineid),
		Storage:   storage,
		Data:      data,
	}

	resp2, err2 := b.HandleRequest(context.Background(), req2)
	t.Log(resp2.Error())
	t.Log(resp2.Data)
	if err2 != nil {
		t.Fatalf("err: %s", err2)
	}
	// Now Test Creating a Role
	roleData := map[string]interface{}{
		string(enumerations.RoleConfigTTL):      1800,
		string(enumerations.RoleConfigSubject):  "vault_test",
		string(enumerations.RoleConfigEngineId): engineid,
	}

	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/4857",
		Data:      roleData,
		Storage:   storage,
	}

	roleResp, roleErr := b.HandleRequest(context.Background(), roleReq)
	t.Log(roleResp.Error())
	//t.Log(roleResp.Data)
	if roleErr != nil {
		t.Fatalf("err: %s", roleErr)
	}

	/**
	 * Now Test Whether The User Can Generate A Token
	 * 1. The Role ID is 4857
	 * 2. The Engine ID is 447
	 * 3. Get Creds For Role 4857
	 * 4. Make sure it matches the issuer and audience from the first role we created
	 * 5. Make sure its signed
	 * 6. Make sure its valid -> Get the public key from the storage
	 * 7. To get THe Public Key, check the kid from the token, and get the public key from the storage at the key "publickey" + kid
	 */

	// Get creds/4857
	credsReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "cred/4857",
		Storage:   storage,
		Data: map[string]interface{}{
			"Requested_TTL": 400,
		},
	}

	credsResp, credsErr := b.HandleRequest(context.Background(), credsReq)

	if credsErr != nil {
		t.Fatalf("err: %s", credsErr)
	}

	t.Log(credsResp.Error())

	t.Log(credsResp.Data)

	keyid := credsResp.Secret.InternalData["key_uuid"]
	// Get the public key from the storage
	entry, err := storage.Get(context.Background(), fmt.Sprintf("publickey%s", keyid))
	if err != nil {
		t.Errorf("Error Getting Public Key  %s From Storage", credsResp.Data["kid"])
	}

	t.Log(entry)

	// Get the public key from the storage
	pubkey := entry.Value
	//Conver Bytes to rsa.PrivateKey
	rsapubkey, err := x509.ParsePKIXPublicKey(pubkey)
	if err != nil {
		t.Errorf("Error Parsing Public Key  %s From Storage", credsResp.Data["kid"])
	}

	// Verify Token Signature
	token, err := jwt.Parse(credsResp.Secret.InternalData["token"].(string), func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// Return the public key
		return rsapubkey, nil
	})
	if err != nil {
		t.Errorf("Error Parsing Token %s", credsResp.Secret.InternalData["token"].(string))
	}

	// Check Claims, Make sure they match the ones we set
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Errorf("Error Parsing Claims %s", token.Claims)
	}

	// Check Issuer
	if claims["iss"] != data2["issuer"] {
		t.Errorf("Issuer Does Not Match")
	}

	// Check Audience
	if claims["aud"] != data2["audience"] {
		t.Errorf("Audience Does Not Match")
	}

	// Check Subject
	if claims["sub"] != roleData["subject"] {
		t.Errorf("Subject Does Not Match")
	}

}
