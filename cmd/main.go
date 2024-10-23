package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/core/types"
)

type backend struct {
	*framework.Backend
	logger hclog.Logger
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		logger: conf.Logger,
	}
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(`
		The Ethereum Transaction Signer plugin allows for signing Ethereum
		transactions without exposing private keys.
		`),
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathKeys(),
				b.pathSignTransaction(),
			},
		),
		BackendType: logical.TypeLogical,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *backend) pathKeys() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key",
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "Ethereum private key in hexadecimal format",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleKeyCreate,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleKeyCreate,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleKeyRead,
			},
		},
		ExistenceCheck: b.handleExistenceCheck,
		HelpSynopsis:    "Manage Ethereum private keys",
		HelpDescription: "Create, update, and read Ethereum private keys",
	}
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	b.logger.Debug("handleExistenceCheck called", "path", req.Path)
	
	name := data.Get("name").(string)
	entry, err := req.Storage.Get(ctx, "keys/"+name)
	if err != nil {
		return false, fmt.Errorf("error checking if key exists: %w", err)
	}

	return entry != nil, nil
}

func (b *backend) handleKeyCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.logger.Debug("handleKeyCreate called", "path", req.Path)
	
	name, ok := data.GetOk("name")
	if !ok {
		b.logger.Error("name not provided")
		return nil, errors.New("name not provided")
	}
	b.logger.Debug("Name received", "name", name)

	privateKey, ok := data.GetOk("private_key")
	if !ok {
		b.logger.Error("private_key not provided")
		return nil, errors.New("private_key not provided")
	}
	b.logger.Debug("Private key received", "key_length", len(privateKey.(string)))

	// Remove '0x' prefix if present
	privateKeyStr := strings.TrimPrefix(privateKey.(string), "0x")

	// Validate private key format
	privateKeyBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		b.logger.Error("Invalid private key format", "error", err)
		return nil, fmt.Errorf("invalid private key format: %w", err)
	}

	// Ensure the private key is 32 bytes long
	if len(privateKeyBytes) != 32 {
		b.logger.Error("Invalid private key length", "length", len(privateKeyBytes))
		return nil, fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privateKeyBytes))
	}

	// Store the private key
	entry := &logical.StorageEntry{
		Key:   "keys/" + name.(string),
		Value: privateKeyBytes,
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		b.logger.Error("Failed to store private key", "error", err)
		return nil, fmt.Errorf("failed to store private key: %w", err)
	}

	b.logger.Info("Successfully stored private key", "name", name)

	return &logical.Response{
		Data: map[string]interface{}{
			"success": true,
		},
	}, nil
}

func (b *backend) handleKeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    b.logger.Debug("handleKeyRead called", "path", req.Path)

    name := data.Get("name").(string)

    entry, err := req.Storage.Get(ctx, "keys/"+name)
    if err != nil {
        b.logger.Error("Failed to retrieve key", "error", err)
        return nil, fmt.Errorf("failed to retrieve key: %w", err)
    }
    if entry == nil {
        return nil, nil
    }

    // Return metadata only
    return &logical.Response{
        Data: map[string]interface{}{
            "name":       name,
            "key_exists": true,
            "key_length": len(entry.Value),
        },
    }, nil
}

func (b *backend) pathSignTransaction() *framework.Path {
	return &framework.Path{
		Pattern: "sign-transaction",
		Fields: map[string]*framework.FieldSchema{
			"raw_transaction": {
				Type:        framework.TypeString,
				Description: "The raw transaction to sign",
			},
			"key_name": {
				Type:        framework.TypeString,
				Description: "The name of the key to use for signing",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.signTransaction,
			},
		},
		HelpSynopsis:    "Sign an Ethereum transaction",
		HelpDescription: "Sign an Ethereum transaction using a stored private key",
	}
}

func (b *backend) signTransaction(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rawTxHex := data.Get("raw_transaction").(string)
	keyName := data.Get("key_name").(string)

	// Remove '0x' prefix if present
	rawTxHex = strings.TrimPrefix(rawTxHex, "0x")

	// Retrieve the private key
	entry, err := req.Storage.Get(ctx, "keys/"+keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if entry == nil {
		return nil, errors.New("key not found")
	}

	privateKeyECDSA, err := crypto.ToECDSA(entry.Value)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}

	// Decode the raw transaction
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		b.logger.Error("Failed to decode raw transaction hex", "error", err)
		return nil, fmt.Errorf("error decoding raw transaction hex: %w", err)
	}

	// Parse the raw transaction into a types.Transaction object
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(rawTxBytes); err != nil {
		b.logger.Error("Failed to unmarshal raw transaction", "error", err)
		return nil, fmt.Errorf("error unmarshalling transaction: %w", err)
	}

	// Sign the transaction
	// Note: We're using HomesteadSigner here as in your example.
	// You might want to use a different signer based on your requirements.
	signer := types.HomesteadSigner{}
	signedTx, err := types.SignTx(tx, signer, privateKeyECDSA)
	if err != nil {
		b.logger.Error("Failed to sign transaction", "error", err)
		return nil, fmt.Errorf("error signing transaction: %w", err)
	}

	// Serialize the signed transaction
	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		b.logger.Error("Failed to marshal signed transaction", "error", err)
		return nil, fmt.Errorf("error encoding signed transaction: %w", err)
	}

	b.logger.Info("Transaction signed successfully", 
		"type", signedTx.Type(),
		"hash", signedTx.Hash().Hex())

	// Return the signed transaction
	return &logical.Response{
		Data: map[string]interface{}{
			"signed_transaction": "0x" + hex.EncodeToString(signedTxBytes),
		},
	}, nil
}

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
