//go:build pq

package core

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	_ "github.com/lib/pq"
	"github.com/pocketbase/dbx"
)

type VaultConfig struct {
	Address string
	Token   string
	Timeout time.Duration
}

func DefaultVaultConfig() *VaultConfig {
	return &VaultConfig{
		Address: os.Getenv("VAULT_ADDR"),
		Token:   os.Getenv("VAULT_TOKEN"),
		Timeout: 10 * time.Second,
	}
}

func old_resolveConnectionString(ctx context.Context, cfg *VaultConfig, connStr string) (string, error) {
	// Handle dynamic credentials case
	if isDynamicCreds(connStr) {
		return getDynamicCreds(ctx, cfg, connStr)
	}

	// Original resolution logic for static credentials
	parts := strings.Split(connStr, "://")
	if len(parts) != 2 {
		return connStr, nil // Not a standard connection string, return as-is
	}

	credsAndRest := strings.Split(parts[1], "@")
	if len(credsAndRest) != 2 {
		return connStr, nil // No credentials in standard format, return as-is
	}

	creds := strings.Split(credsAndRest[0], ":")
	if len(creds) != 2 {
		return connStr, nil // No password or not in user:pass format
	}

	// Check if username or password are Vault references
	resolve := func(value string) (string, error) {
		if strings.HasPrefix(value, "vault:") {
			path, field, err := parseVaultRef(value)
			if err != nil {
				return "", err
			}
			return getFromVault(ctx, cfg, path, field)
		}
		return value, nil
	}

	username, err := resolve(creds[0])
	if err != nil {
		return "", fmt.Errorf("failed to resolve username: %w", err)
	}

	password, err := resolve(creds[1])
	if err != nil {
		return "", fmt.Errorf("failed to resolve password: %w", err)
	}

	// Reconstruct the connection string
	return fmt.Sprintf("%s://%s:%s@%s",
		parts[0],
		username,
		password,
		credsAndRest[1]), nil
}

func connectDB(dbPath string) (*dbx.DB, error) {
	var connStr string
	if strings.Contains(dbPath, "logs.db") {
		connStr = os.Getenv("LOGS_DATABASE")
	} else {
		connStr = os.Getenv("DATABASE")
	}

	vaultCfg := DefaultVaultConfig()
	ctx, cancel := context.WithTimeout(context.Background(), vaultCfg.Timeout)
	defer cancel()

	resolvedConnStr, err := resolveConnectionString(ctx, vaultCfg, connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve connection string: %w", err)
	}
	fmt.Printf("%s\n",resolvedConnStr)

	// MustOpen returns (*dbx.DB, error) - we need to handle both
	db, err := dbx.MustOpen("postgres", resolvedConnStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}

// Helper functions that need to be defined
func isDynamicCreds(connStr string) bool {
	parts := strings.Split(connStr, "://")
	if len(parts) != 2 {
		return false
	}
	return strings.HasPrefix(parts[1], "vault:dynamic:")
}

func parseVaultRef(ref string) (path, field string, err error) {
	parts := strings.Split(ref, ":")
	if len(parts) != 3 || parts[0] != "vault" {
		return "", "", fmt.Errorf("invalid vault reference format")
	}
	return parts[1], parts[2], nil
}

// getDynamicCreds retrieves dynamic database credentials from Vault
func getDynamicCreds(ctx context.Context, cfg *VaultConfig, connStr string) (string, error) {
    // Extract the vault path from the connection string
    parts := strings.SplitN(connStr, "://vault:dynamic:", 2)
    if len(parts) != 2 {
        return "", fmt.Errorf("invalid dynamic credentials format")
    }

    // Split the remaining part at @ to separate path from host
    pathAndRest := strings.SplitN(parts[1], "@", 2)
    if len(pathAndRest) != 2 {
        return "", fmt.Errorf("invalid dynamic credentials format")
    }

    path := pathAndRest[0]
    rest := pathAndRest[1]

    client, err := api.NewClient(&api.Config{
        Address: cfg.Address,
    })
    if err != nil {
        return "", fmt.Errorf("failed to create vault client: %w", err)
    }
    client.SetToken(cfg.Token)

    // Read dynamic credentials from Vault
    secret, err := client.Logical().ReadWithContext(ctx, path)
    if err != nil {
        return "", fmt.Errorf("failed to read vault secret: %w", err)
    }
    if secret == nil || secret.Data == nil {
        return "", fmt.Errorf("no data found at vault path %s", path)
    }

    // Extract username and password from the dynamic credentials
    username, ok := secret.Data["username"].(string)
    if !ok {
        return "", fmt.Errorf("username not found in dynamic credentials")
    }

    password, ok := secret.Data["password"].(string)
    if !ok {
        return "", fmt.Errorf("password not found in dynamic credentials")
    }

    // Reconstruct the connection string with actual credentials
    return fmt.Sprintf("postgresql://%s:%s@%s", username, password, rest), nil
}

// getFromVault retrieves a secret from Vault
func getFromVault(ctx context.Context, cfg *VaultConfig, path, field string) (string, error) {
	client, err := api.NewClient(&api.Config{
		Address: cfg.Address,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create vault client: %w", err)
	}
	client.SetToken(cfg.Token)

	secret, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to read vault secret: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no data found at vault path %s", path)
	}

	value, ok := secret.Data[field].(string)
	if !ok {
		return "", fmt.Errorf("field %s not found or not a string in vault path %s", field, path)
	}

	return value, nil
}

func resolveConnectionString(ctx context.Context, cfg *VaultConfig, connStr string) (string, error) {
    // Check if this is a direct reference to static credentials in Vault
    if strings.HasPrefix(connStr, "vault://") {
        // Format: "vault://secret/data/path#field" or "vault://database/static-creds/role"
        return getStaticSecretFromVault(ctx, cfg, connStr)
    }

    // Handle dynamic credentials case
    if isDynamicCreds(connStr) {
        return getDynamicCreds(ctx, cfg, connStr)
    }

    // Handle case where entire connection string is stored in Vault
    if strings.HasPrefix(connStr, "vault:") && !strings.Contains(connStr, "@") {
        path, field, err := parseVaultRef(connStr)
        if err != nil {
            return "", err
        }
        return getFromVault(ctx, cfg, path, field)
    }

    // Original resolution logic for static credentials with embedded Vault references
    parts := strings.Split(connStr, "://")
    if len(parts) != 2 {
        return connStr, nil // Not a standard connection string, return as-is
    }

    credsAndRest := strings.Split(parts[1], "@")
    if len(credsAndRest) != 2 {
        return connStr, nil // No credentials in standard format, return as-is
    }

    creds := strings.Split(credsAndRest[0], ":")
    if len(creds) != 2 {
        return connStr, nil // No password or not in user:pass format
    }

    // Check if username or password are Vault references
    resolve := func(value string) (string, error) {
        if strings.HasPrefix(value, "vault:") {
            path, field, err := parseVaultRef(value)
            if err != nil {
                return "", err
            }
            return getFromVault(ctx, cfg, path, field)
        }
        return value, nil
    }

    username, err := resolve(creds[0])
    if err != nil {
        return "", fmt.Errorf("failed to resolve username: %w", err)
    }

    password, err := resolve(creds[1])
    if err != nil {
        return "", fmt.Errorf("failed to resolve password: %w", err)
    }

    // Reconstruct the connection string
    return fmt.Sprintf("%s://%s:%s@%s",
        parts[0],
        username,
        password,
        credsAndRest[1]), nil
}

func getStaticSecretFromVault(ctx context.Context, cfg *VaultConfig, vaultRef string) (string, error) {
    // Create Vault client
    client, err := api.NewClient(&api.Config{
        Address: cfg.Address,
    })
    if err != nil {
        return "", fmt.Errorf("failed to create vault client: %w", err)
    }
    client.SetToken(cfg.Token)

    // Remove the vault:// prefix and extract path
    path := strings.TrimPrefix(vaultRef, "vault://")
    secretPath := strings.TrimPrefix(path, "secret/data/")

    // Get the secret from Vault
    secret, err := client.KVv2("secret").Get(ctx, secretPath)
    if err != nil {
        return "", fmt.Errorf("failed to get vault secret: %w", err)
    }

    // Get the connection URL template
    connURL, ok := secret.Data["connection_url"].(string)
    if !ok {
        return "", fmt.Errorf("connection_url not found in vault secret")
    }

    // Get credentials
    username, uOk := secret.Data["username"].(string)
    password, pOk := secret.Data["password"].(string)
    if !uOk || !pOk {
        return "", fmt.Errorf("username or password missing in vault secret")
    }

    // Replace placeholders if they exist
    connURL = strings.ReplaceAll(connURL, "{{username}}", username)
    connURL = strings.ReplaceAll(connURL, "{{password}}", password)

    // If URL still doesn't contain credentials, prepend them
    if !strings.Contains(connURL, "@") {
        // Extract the part after postgresql://
        dbPart := strings.TrimPrefix(connURL, "postgresql://")
        connURL = fmt.Sprintf("postgresql://%s:%s@%s", username, password, dbPart)
    }

    return connURL, nil
}
