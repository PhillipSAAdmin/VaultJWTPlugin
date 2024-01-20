package vault_backend

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *JWKS_Vault_Backend) testReach(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"random": "s",
		},
	}, nil
}

func (b *JWKS_Vault_Backend) testReach2(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	//Get [range] pathParameter
	//ranger, ok := data.GetOk("range")

	ranger := strings.Split(req.Path, "/")[1]
	ok := true
	if !ok {
		return nil, nil
	}

	// Get The Config (Previous Stored as logical.StorageEntryJSON)
	entry, err := req.Storage.Get(ctx, "rrrr")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"random": "s" + ranger + string(entry.Value),
		},
	}, nil
}

func (b *JWKS_Vault_Backend) testReachPut2(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	//Get [range] pathParameter
	//ranger, ok := data.GetOk("range")

	//ranger := strings.Split(req.Path, "/")[1]
	ranger := data.Get("range").(string)

	//Put Storage Random Key
	err := req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "rrrr",
		Value: []byte(ranger),
	})
	if err != nil {
		return nil, err
	}

	ok := true
	if !ok {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"random": "s" + ranger,
		},
	}, nil
}
