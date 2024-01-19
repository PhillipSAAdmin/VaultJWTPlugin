package vault_backend

import (
	"context"
	"testing"

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
		Operation: logical.ReadOperation,
		Path:      "config/5",
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

}

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	// Create a new backend

	// Create a new in-memory storage
	//storage := &logical.InmemStorage{}
	//config := logical.TestBackendConfig()

	b := backend()
	storage := &logical.InmemStorage{}

	// Configure the backend
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
