package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// keyVaultClouds are the Key Vault host suffixes of the Azure clouds. A
// token goes only to a vault under one of them, over https.
var keyVaultClouds = []string{".vault.azure.net", ".vault.azure.cn", ".vault.usgovcloudapi.net", ".vault.microsoftazure.de"}

// keyVaultBase is the address of a vault host; tests point it at a local
// server.
var keyVaultBase = func(host string) string { return "https://" + host }

var (
	keyVaultName    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$`)
	keyVaultSecret  = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}$`)
	keyVaultVersion = regexp.MustCompile(`^[0-9A-Fa-f]{32}$`)
)

// keyVaultHost is the host of a vault written as a name (myvault, in the
// public cloud) or a full host (myvault.vault.azure.cn), and the Azure AD
// resource its tokens are for.
func keyVaultHost(v string) (host, resource string, err error) {
	v = strings.ToLower(v)
	name, suffix := v, keyVaultClouds[0]
	if i := strings.IndexByte(v, '.'); i >= 0 {
		name, suffix = v[:i], ""
		for _, s := range keyVaultClouds {
			if v[i:] == s {
				suffix = s
			}
		}
		if suffix == "" {
			return "", "", fmt.Errorf("%q is not a Key Vault host (it ends in %s)", v, strings.Join(keyVaultClouds, ", "))
		}
	}
	if !keyVaultName.MatchString(name) {
		return "", "", fmt.Errorf("%q is not a Key Vault name (3 to 24 letters, digits and dashes)", name)
	}
	return name + suffix, "https://" + suffix[1:], nil
}

// KeyVaultResource is the Azure AD resource for the vault of an azure-kv:
// path (VAULT/NAME), which is the one an Azure CLI token must be for:
// https://vault.azure.cn for shop.vault.azure.cn. It is the public cloud's
// for a vault name without a host, or one that is not valid.
func KeyVaultResource(path string) string {
	vault, _, _ := strings.Cut(path, "/")
	if _, res, err := keyVaultHost(vault); err == nil {
		return res
	}
	return "https://vault.azure.net"
}

// AzureSecret reads a Key Vault secret. path is VAULT/NAME or
// VAULT/NAME/VERSION; without a version it is the current one.
func AzureSecret(ctx context.Context, path string) (string, error) {
	parts := strings.Split(path, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return "", fmt.Errorf("write azure-kv:VAULT/NAME, for example azure-kv:shop-vault/db-password")
	}
	host, resource, err := keyVaultHost(parts[0])
	if err != nil {
		return "", err
	}
	if !keyVaultSecret.MatchString(parts[1]) {
		return "", fmt.Errorf("%q is not a Key Vault secret name (letters, digits and dashes)", parts[1])
	}
	u := keyVaultBase(host) + "/secrets/" + parts[1]
	if len(parts) == 3 {
		if !keyVaultVersion.MatchString(parts[2]) {
			return "", fmt.Errorf("%q is not a Key Vault secret version (32 hex digits)", parts[2])
		}
		u += "/" + parts[2]
	}
	tok, err := AzureToken(ctx, resource)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u+"?api-version=7.4", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := azureClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("key vault %s: %v", host, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		Value *string                        `json:"value"`
		Error struct{ Code, Message string } `json:"error"`
	}
	_ = json.Unmarshal(body, &r)
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return "", fmt.Errorf("%w: key vault %s did not take the login: %s", ErrAzureLogin, host, firstOf(r.Error.Message, resp.Status))
	case resp.StatusCode == http.StatusForbidden:
		return "", fmt.Errorf("key vault %s: %s (the login needs the Key Vault Secrets User role, or an access policy that allows Get on secrets)",
			host, firstOf(r.Error.Message, resp.Status))
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("key vault %s: %s (%s)", host, firstOf(r.Error.Message, resp.Status), firstOf(r.Error.Code, resp.Status))
	case r.Value == nil:
		return "", fmt.Errorf("key vault %s: the answer holds no secret value", host)
	}
	return *r.Value, nil
}
