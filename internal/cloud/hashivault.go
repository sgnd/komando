package cloud

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VaultKV reads one field of a KV secret from HashiCorp Vault or OpenBao,
// the way `vault kv get -field=FIELD PATH` does: PATH starts with the mount
// ("secret/shop/db"), KV version 1 or 2 is found out from the mount. The
// address and token come from the same places the CLI uses: VAULT_ADDR,
// VAULT_TOKEN or ~/.vault-token, VAULT_NAMESPACE, VAULT_CACERT.
func VaultKV(ctx context.Context, path, field string) (string, error) {
	addr := strings.TrimRight(firstOf(os.Getenv("VAULT_ADDR"), os.Getenv("BAO_ADDR"), "https://127.0.0.1:8200"), "/")
	token := firstOf(UnlockEnv("VAULT_TOKEN"), UnlockEnv("BAO_TOKEN"), tokenFile(".vault-token"), tokenFile(".bao-token"))
	if token == "" {
		return "", errors.New("vault: no token (set VAULT_TOKEN, or log in once so ~/.vault-token exists)")
	}
	client, err := vaultHTTP()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	get := func(p string) (int, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", addr+"/v1/"+strings.TrimLeft(p, "/"), nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("X-Vault-Token", token)
		req.Header.Set("X-Vault-Request", "true")
		if ns := firstOf(os.Getenv("VAULT_NAMESPACE"), os.Getenv("BAO_NAMESPACE")); ns != "" {
			req.Header.Set("X-Vault-Namespace", ns)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, fmt.Errorf("vault: %v", err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, b, err
	}

	path = strings.Trim(path, "/")
	mount, version := "", "1"
	if code, b, err := get("sys/internal/ui/mounts/" + path); err != nil {
		return "", err
	} else if code == http.StatusOK {
		var m struct {
			Data struct {
				Path    string            `json:"path"`
				Options map[string]string `json:"options"`
			} `json:"data"`
		}
		if json.Unmarshal(b, &m) == nil {
			mount, version = strings.Trim(m.Data.Path, "/"), firstOf(m.Data.Options["version"], "1")
		}
	}
	url := path
	if version == "2" && mount != "" {
		url = mount + "/data/" + strings.TrimPrefix(strings.TrimPrefix(path, mount), "/")
	}
	code, b, err := get(url)
	if err != nil {
		return "", err
	}
	switch code {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", fmt.Errorf("vault: no secret at %s", path)
	case http.StatusForbidden:
		return "", fmt.Errorf("vault: permission denied reading %s (is the token valid and allowed to read it?)", path)
	default:
		var e struct{ Errors []string }
		_ = json.Unmarshal(b, &e)
		return "", fmt.Errorf("vault: %d %s", code, strings.Join(e.Errors, "; "))
	}
	var r struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	data := r.Data
	if version == "2" {
		inner, _ := data["data"].(map[string]any)
		data = inner
	}
	v, ok := data[field]
	if !ok {
		return "", fmt.Errorf("vault: %s has no field %q", path, field)
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	j, _ := json.Marshal(v)
	return string(j), nil
}

func tokenFile(name string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// vaultHTTP trusts the system roots, plus VAULT_CACERT when set.
func vaultHTTP() (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if f := firstOf(os.Getenv("VAULT_CACERT"), os.Getenv("BAO_CACERT")); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("vault: VAULT_CACERT: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("vault: VAULT_CACERT holds no certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}
