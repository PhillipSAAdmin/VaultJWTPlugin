package vault_backend

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type JWKS_Vault_Backend struct {
	*framework.Backend
	lock sync.RWMutex
}

func (b *JWKS_Vault_Backend) pathRandom(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the length from the request

	length := data.Get("length").(int)
	random_string, err := req.Storage.Get(ctx, "random_string")
	if err != nil {
		return nil, fmt.Errorf("could not read random_string from storage: %v, set in config first", err)
	}

	// Generate a random string
	randomString := "SDSDSIOD" + strconv.Itoa(length) + string(random_string.Value)
	/*if err != nil {
		return nil, nil
	}*/

	// Return the response
	return &logical.Response{
		Data: map[string]interface{}{
			"random": randomString,
		},
	}, nil

}

func (b *JWKS_Vault_Backend) pathRandomCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	s, ok := data.Get("random_string").(string)
	if !ok {
		return nil, fmt.Errorf("could not random_string convert to string ")
	}

	fmt.Println(s)

	err := req.Storage.Put(ctx, &logical.StorageEntry{
		Key:      "random_string",
		Value:    []byte(s),
		SealWrap: true,
	})
	if err != nil {
		return nil, fmt.Errorf("could not write random_string to storage: %v", err)
	}
	private := data.Get("random_string").(string)

	b.Logger().Info("private", "private", private)

	entry := logical.StorageEntry{
		Key:   "random_string",
		Value: []byte(private),
	}

	if err := req.Storage.Put(ctx, &entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			//"random_string": "s",
			"random": private,
		},
	}, nil
}
