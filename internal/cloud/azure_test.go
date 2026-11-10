package cloud

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// azureEnv clears every Azure login the test machine may have and points
// komando's Azure addresses at the given servers.
func azureEnv(t *testing.T, aad *httptest.Server, imds string) {
	t.Helper()
	for _, k := range []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_FEDERATED_TOKEN_FILE",
		"AZURE_AUTHORITY_HOST", "IDENTITY_ENDPOINT", "IDENTITY_HEADER"} {
		t.Setenv(k, "")
	}
	t.Setenv("AZURE_CONFIG_DIR", t.TempDir())
	sa, sc, si, sb := azureAuthority, azureClient, azureIMDS, keyVaultBase
	t.Cleanup(func() { azureAuthority, azureClient, azureIMDS, keyVaultBase = sa, sc, si, sb })
	if aad != nil {
		azureAuthority, azureClient = aad.URL, aad.Client()
		keyVaultBase = func(host string) string { return aad.URL + "/" + host }
	}
	azureIMDS = imds
}

// fakeJWT is a token with a tid claim, like Azure AD's.
func fakeJWT(tid string) string {
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"tid":"` + tid + `"}`))
	return "eyJhbGciOiJub25lIn0." + p + ".sig"
}

// fakeAzure is Azure AD's token endpoint and a Key Vault in one server.
func fakeAzure(t *testing.T) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/tenant1/oauth2/v2.0/token":
			_ = r.ParseForm()
			ok := r.Form.Get("grant_type") == "client_credentials" && r.Form.Get("client_id") == "app1" &&
				(r.Form.Get("client_secret") == "s3cret" || r.Form.Get("client_assertion") == "fed-jwt")
			if !ok {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\r\nTrace ID: 1"}`)
				return
			}
			fmt.Fprintf(w, `{"access_token":"tok-%s","expires_in":3599}`, strings.TrimSuffix(r.Form.Get("scope"), "/.default"))
		case strings.HasPrefix(r.URL.Path, "/shop.vault.azure.net/secrets/"):
			if r.URL.Query().Get("api-version") == "" {
				w.WriteHeader(400)
				return
			}
			if r.Header.Get("Authorization") != "Bearer tok-https://vault.azure.net" {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":{"code":"Unauthorized","message":"bad token"}}`)
				return
			}
			switch strings.TrimPrefix(r.URL.Path, "/shop.vault.azure.net/secrets/") {
			case "db":
				fmt.Fprint(w, `{"value":"{\"password\":\"kv-pw\"}","id":"x"}`)
			case "db/0123456789abcdef0123456789abcdef":
				fmt.Fprint(w, `{"value":"old-pw"}`)
			case "locked":
				w.WriteHeader(403)
				fmt.Fprint(w, `{"error":{"code":"Forbidden","message":"no secrets get permission"}}`)
			default:
				w.WriteHeader(404)
				fmt.Fprint(w, `{"error":{"code":"SecretNotFound","message":"A secret with (name/id) x was not found"}}`)
			}
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestAzureServicePrincipalAndKeyVault(t *testing.T) {
	srv := fakeAzure(t)
	defer srv.Close()
	azureEnv(t, srv, "http://127.0.0.1:1/none")
	t.Setenv("AZURE_TENANT_ID", "tenant1")
	t.Setenv("AZURE_CLIENT_ID", "app1")
	t.Setenv("AZURE_CLIENT_SECRET", "s3cret")
	ctx := context.Background()
	if v, err := AzureSecret(ctx, "shop/db"); err != nil || v != `{"password":"kv-pw"}` {
		t.Fatalf("secret: %q %v", v, err)
	}
	if v, err := AzureSecret(ctx, "SHOP.vault.azure.net/db/0123456789abcdef0123456789abcdef"); err != nil || v != "old-pw" {
		t.Errorf("a version: %q %v", v, err)
	}
	if _, err := AzureSecret(ctx, "shop/nope"); err == nil || !strings.Contains(err.Error(), "SecretNotFound") {
		t.Errorf("missing: %v", err)
	}
	if _, err := AzureSecret(ctx, "shop/locked"); err == nil || !strings.Contains(err.Error(), "Key Vault Secrets User") {
		t.Errorf("forbidden: %v", err)
	}
	t.Setenv("AZURE_CLIENT_SECRET", "wrong")
	_, err := AzureSecret(ctx, "shop/db")
	if !errors.Is(err, ErrAzureLogin) || !strings.Contains(err.Error(), "AADSTS7000215") || strings.Contains(err.Error(), "Trace ID") ||
		strings.Contains(err.Error(), "wrong") {
		t.Errorf("a wrong secret: %v", err)
	}
	t.Setenv("AZURE_CLIENT_SECRET", "")
	fed := filepath.Join(t.TempDir(), "token")
	os.WriteFile(fed, []byte("fed-jwt\n"), 0o600)
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", fed)
	if v, err := AzureSecret(ctx, "shop/db"); err != nil || v == "" {
		t.Errorf("workload identity: %q %v", v, err)
	}
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", filepath.Join(t.TempDir(), "gone"))
	if _, err := AzureToken(ctx, "https://vault.azure.net"); !errors.Is(err, ErrAzureLogin) {
		t.Errorf("a missing token file: %v", err)
	}
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	t.Setenv("AZURE_CLIENT_SECRET", "s3cret")
	t.Setenv("AZURE_AUTHORITY_HOST", "http://login.example.com")
	if _, err := AzureToken(ctx, "https://vault.azure.net"); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Errorf("a plain-http sign-in host: %v", err)
	}
	t.Setenv("AZURE_AUTHORITY_HOST", srv.URL+"/")
	if tok, err := AzureToken(ctx, "https://vault.azure.net"); err != nil || tok != "tok-https://vault.azure.net" {
		t.Errorf("AZURE_AUTHORITY_HOST: %q %v", tok, err)
	}
	t.Setenv("AZURE_TENANT_ID", "../evil")
	if _, err := AzureToken(ctx, "https://vault.azure.net"); err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Errorf("a bad tenant: %v", err)
	}
}

func TestKeyVaultRefForms(t *testing.T) {
	azureEnv(t, nil, "http://127.0.0.1:1/none")
	for _, bad := range []string{"shop", "shop/a/b/c", "shop.evil.com/db", "shop.vault.azure.net.evil.com/db", "x/db", "shop/db_1", "shop/db/v1", "-shop/db"} {
		if _, err := AzureSecret(context.Background(), bad); err == nil || errors.Is(err, ErrAzureLogin) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	for v, want := range map[string]string{"shop": "https://vault.azure.net", "shop.vault.azure.cn": "https://vault.azure.cn",
		"shop.vault.usgovcloudapi.net": "https://vault.usgovcloudapi.net"} {
		if _, res, err := keyVaultHost(v); err != nil || res != want {
			t.Errorf("%s: %s %v", v, res, err)
		}
	}
}

func TestAzureNoLogin(t *testing.T) {
	azureEnv(t, nil, "http://127.0.0.1:1/none")
	_, err := AzureSecret(context.Background(), "shop/db")
	if !errors.Is(err, ErrAzureLogin) || !strings.Contains(err.Error(), "not running on Azure") {
		t.Errorf("no login: %v", err)
	}
	if h := AzureLoginHint("https://vault.azure.net"); !strings.Contains(h, "AZURE_CLIENT_SECRET") || !strings.Contains(h, "--resource https://vault.azure.net") {
		t.Errorf("hint: %s", h)
	}
}

func TestAzureCLIToken(t *testing.T) {
	azureEnv(t, nil, "http://127.0.0.1:1/none")
	now := time.Now()
	exp := func(d time.Duration) string { return fmt.Sprint(now.Add(d).Unix()) }
	cache := `{"AccessToken":{
	 "a":{"secret":"arm","target":"https://management.core.windows.net//.default","realm":"t1","expires_on":"` + exp(time.Hour) + `"},
	 "b":{"secret":"vault-old","target":"https://vault.azure.net/user_impersonation https://vault.azure.net/.default","realm":"t1","expires_on":"` + exp(2*time.Minute) + `"},
	 "c":{"secret":"vault","target":"https://vault.azure.net/.default","realm":"t1","expires_on":"` + exp(50*time.Minute) + `"},
	 "d":{"secret":"vault-t2","target":"https://vault.azure.net/.default","realm":"t2","expires_on":"` + exp(80*time.Minute) + `"}}}`
	os.WriteFile(filepath.Join(os.Getenv("AZURE_CONFIG_DIR"), "msal_token_cache.json"), []byte(cache), 0o600)
	if tok, err := AzureToken(context.Background(), "https://vault.azure.net"); err != nil || tok != "vault-t2" {
		t.Errorf("most time left: %q %v", tok, err)
	}
	t.Setenv("AZURE_TENANT_ID", "t1")
	if tok := azureCLIToken("https://vault.azure.net", "t1", now); tok != "vault" {
		t.Errorf("tenant: %q", tok)
	}
	if tok := azureCLIToken("https://management.core.windows.net/", "t1", now); tok != "arm" {
		t.Errorf("ARM: %q", tok)
	}
	if tok := azureCLIToken("https://vault.azure.net", "t1", now.Add(time.Hour)); tok != "" {
		t.Errorf("expired: %q", tok)
	}
	if tok := azureCLIToken("https://storage.azure.com", "", now); tok != "" {
		t.Errorf("another resource: %q", tok)
	}
}

func TestAzureManagedIdentity(t *testing.T) {
	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/imds" && r.Header.Get("Metadata") == "true" && q.Get("api-version") != "":
			if q.Get("client_id") == "nobody" {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":"invalid_request","error_description":"Identity not found"}`)
				return
			}
			fmt.Fprintf(w, `{"access_token":"mi-%s","expires_on":"1"}`, q.Get("resource"))
		case r.URL.Path == "/appservice" && r.Header.Get("X-IDENTITY-HEADER") == "h1":
			fmt.Fprintf(w, `{"access_token":"app-%s"}`, q.Get("resource"))
		default:
			w.WriteHeader(400)
			fmt.Fprint(w, `{"statusCode":400,"message":"bad request"}`)
		}
	}))
	defer imds.Close()
	azureEnv(t, nil, imds.URL+"/imds")
	ctx := context.Background()
	if tok, err := AzureToken(ctx, "https://vault.azure.net"); err != nil || tok != "mi-https://vault.azure.net" {
		t.Errorf("IMDS: %q %v", tok, err)
	}
	t.Setenv("AZURE_CLIENT_ID", "nobody")
	if _, err := AzureToken(ctx, "https://vault.azure.net"); !errors.Is(err, ErrAzureLogin) || !strings.Contains(err.Error(), "Identity not found") {
		t.Errorf("no such identity: %v", err)
	}
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("IDENTITY_ENDPOINT", imds.URL+"/appservice")
	t.Setenv("IDENTITY_HEADER", "h1")
	if tok, err := AzureToken(ctx, "https://vault.azure.net"); err != nil || tok != "app-https://vault.azure.net" {
		t.Errorf("App Service: %q %v", tok, err)
	}
	t.Setenv("IDENTITY_HEADER", "wrong")
	if _, err := AzureToken(ctx, "https://vault.azure.net"); err == nil || !strings.Contains(err.Error(), "bad request") {
		t.Errorf("App Service refused: %v", err)
	}
}

func TestAzureTenant(t *testing.T) {
	if got := AzureTenant(fakeJWT("72f988bf-86f1-41af-91ab-2d7cd011db47")); got != "72f988bf-86f1-41af-91ab-2d7cd011db47" {
		t.Errorf("tid: %q", got)
	}
	for _, bad := range []string{"", "a.b", "a.!!.c", fakeJWT("../x"), "a." + base64.RawURLEncoding.EncodeToString([]byte("nojson")) + ".c"} {
		if got := AzureTenant(bad); got != "" {
			t.Errorf("%q: %q", bad, got)
		}
	}
}
