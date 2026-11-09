package cli

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/registry"
	"github.com/sgnd/komando/internal/store"
)

func TestACRResource(t *testing.T) {
	for host, want := range map[string]string{
		"myregistry.azurecr.io":     "https://management.core.windows.net/",
		"MyRegistry.azurecr.io:443": "https://management.core.windows.net/",
		"shop01.azurecr.cn":         "https://management.core.chinacloudapi.cn/",
		"shop01.azurecr.us":         "https://management.core.usgovcloudapi.net/",
		"evil.azurecr.io.example":   "", "a.azurecr.io": "", "my-reg.azurecr.io": "", "ghcr.io": "",
	} {
		if got := acrResource(host); got != want {
			t.Errorf("acrResource(%q) = %q, want %q", host, got, want)
		}
	}
}

// An ACR conn without --password-ref trades the Azure login for the
// registry's own refresh token; the Azure token never becomes the password.
func TestACRLoginFromAzure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path == "/oauth2/exchange" && r.Form.Get("access_token") == "aad-good" {
			fmt.Fprint(w, `{"refresh_token":"acr-refresh"}`)
			return
		}
		w.WriteHeader(401)
		fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","message":"no AcrPull"}]}`)
	}))
	defer srv.Close()
	saved := azureToken
	defer func() { azureToken = saved }()
	t.Setenv("AZURE_TENANT_ID", "")
	ctx := context.Background()
	pool, err := registry.CAPool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	open := func() *registry.Client {
		return registry.New(strings.TrimPrefix(srv.URL, "https://"), registry.TLS{RootCAs: pool}, "", "", nil)
	}

	var asked string
	azureToken = func(_ context.Context, res string) (string, error) { asked = res; return "aad-good", nil }
	rc := open()
	if err := cloudRegistryLogin(ctx, &store.Conn{Name: "acr"}, "shop01.azurecr.io:443", rc); err != nil {
		t.Fatal(err)
	}
	if rc.User != registry.ACRUser || rc.Password != "acr-refresh" || asked != "https://management.core.windows.net/" {
		t.Errorf("login %q %q, asked for %q", rc.User, rc.Password, asked)
	}

	rc = registry.New("shop01.azurecr.io", registry.TLS{}, "me", "own", nil)
	if err := cloudRegistryLogin(ctx, &store.Conn{PasswordRef: "secret:acr"}, "shop01.azurecr.io", rc); err != nil || rc.Password != "own" {
		t.Errorf("a conn with --password-ref keeps it: %v %q", err, rc.Password)
	}
	rc = registry.New("ghcr.io", registry.TLS{}, "me", "", nil)
	if err := cloudRegistryLogin(ctx, &store.Conn{}, "ghcr.io", rc); err != nil || rc.User != "me" {
		t.Errorf("another registry: %v %q", err, rc.User)
	}

	// an unchecked certificate never gets the Azure token, which is good
	// for the whole subscription
	asked = ""
	unchecked := registry.New(strings.TrimPrefix(srv.URL, "https://"), registry.TLS{SkipVerify: true}, "", "", nil)
	if e := toErr(cloudRegistryLogin(ctx, &store.Conn{}, "shop01.azurecr.io", unchecked)); e.Code != "USAGE" || !strings.Contains(e.Message, "skip-verify") || asked != "" {
		t.Errorf("skip-verify: %+v, asked for %q", e, asked)
	}

	azureToken = func(context.Context, string) (string, error) { return "aad-other", nil }
	e := toErr(cloudRegistryLogin(ctx, &store.Conn{}, "shop01.azurecr.io", open()))
	if e.Code != "REGISTRY_AUTH" || !strings.Contains(e.Message, "no AcrPull") || !strings.Contains(e.Hint, "AcrPull") {
		t.Errorf("refused: %+v", e)
	}

	azureToken = func(context.Context, string) (string, error) {
		return "", fmt.Errorf("%w: nothing here", cloud.ErrAzureLogin)
	}
	e = toErr(cloudRegistryLogin(ctx, &store.Conn{}, "shop01.azurecr.io", open()))
	if e.Code != "AZURE_LOGIN_REQUIRED" || !strings.Contains(e.Hint, "AZURE_CLIENT_SECRET") || !strings.Contains(e.Hint, "`az login`") {
		t.Errorf("no login: %+v", e)
	}
	azureToken = func(context.Context, string) (string, error) { return "", errors.New("dial: no route") }
	if e := toErr(cloudRegistryLogin(ctx, &store.Conn{}, "shop01.azurecr.io", open())); e.Code != "AZURE_FAILED" {
		t.Errorf("other failure: %+v", e)
	}
}

func TestGoogleRegistryHosts(t *testing.T) {
	for host, want := range map[string]bool{
		"europe-west1-docker.pkg.dev": true, "us-docker.pkg.dev:443": true, "gcr.io": true, "EU.gcr.io": true, "asia.gcr.io": true,
		"docker.pkg.dev": false, "k8s.gcr.io": false, "gcr.io.example.com": false, "evil-docker.pkg.dev.example": false, "ghcr.io": false,
	} {
		if got := isGoogleRegistry(host); got != want {
			t.Errorf("isGoogleRegistry(%q) = %v", host, got)
		}
	}
}

// A Google registry logs in with a Google access token as the password of
// oauth2accesstoken; without any Google credentials it stays anonymous.
func TestGoogleRegistryLogin(t *testing.T) {
	saved := gcpToken
	defer func() { gcpToken = saved }()
	ctx := context.Background()
	gcpToken = func(context.Context) (string, error) { return "ya29.reg", nil }
	rc := registry.New("europe-west1-docker.pkg.dev", registry.TLS{}, "", "", nil)
	if err := cloudRegistryLogin(ctx, &store.Conn{}, "europe-west1-docker.pkg.dev", rc); err != nil || rc.User != "oauth2accesstoken" || rc.Password != "ya29.reg" {
		t.Errorf("login: %v %q %q", err, rc.User, rc.Password)
	}
	rc = registry.New("gcr.io", registry.TLS{}, "_json_key", "{key}", nil)
	if err := cloudRegistryLogin(ctx, &store.Conn{PasswordRef: "secret:gar-key"}, "gcr.io", rc); err != nil || rc.User != "_json_key" {
		t.Errorf("a service account key keeps its login: %v %q", err, rc.User)
	}
	if e := toErr(cloudRegistryLogin(ctx, &store.Conn{}, "gcr.io", registry.New("gcr.io", registry.TLS{Plain: true}, "", "", nil))); e.Code != "USAGE" {
		t.Errorf("plain http: %+v", e)
	}
	// the cloud-platform token is good for the whole project: never to an
	// unchecked certificate
	unchecked := registry.New("gcr.io", registry.TLS{SkipVerify: true}, "", "", nil)
	if e := toErr(cloudRegistryLogin(ctx, &store.Conn{}, "gcr.io", unchecked)); e.Code != "USAGE" || !strings.Contains(e.Message, "skip-verify") || unchecked.Password != "" {
		t.Errorf("skip-verify: %+v %q", e, unchecked.Password)
	}

	gcpToken = func(context.Context) (string, error) {
		return "", fmt.Errorf("%w (%w): could not find default credentials", cloud.ErrGCPLogin, cloud.ErrGCPNoCredentials)
	}
	rc = registry.New("gcr.io", registry.TLS{}, "", "", nil)
	if err := cloudRegistryLogin(ctx, &store.Conn{}, "gcr.io", rc); err != nil || rc.User != "" {
		t.Errorf("no credentials stays anonymous: %v %q", err, rc.User)
	}
	gcpToken = func(context.Context) (string, error) {
		return "", fmt.Errorf("%w: oauth2: invalid_grant", cloud.ErrGCPLogin)
	}
	e := toErr(cloudRegistryLogin(ctx, &store.Conn{}, "us-docker.pkg.dev", registry.New("us-docker.pkg.dev", registry.TLS{}, "", "", nil)))
	if e.Code != "GCP_LOGIN_REQUIRED" || !strings.Contains(e.Hint, "gcloud auth application-default login") || !strings.Contains(e.Message, "invalid_grant") {
		t.Errorf("an expired login: %+v", e)
	}
}
