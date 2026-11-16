package cloud

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// refuseFiles makes CheckLocalFile refuse path, as the cli does for an AI
// agent and a protected file; it returns what was asked about.
func refuseFiles(t *testing.T, path string) *[]string {
	t.Helper()
	var asked []string
	saved := CheckLocalFile
	t.Cleanup(func() { CheckLocalFile = saved })
	CheckLocalFile = func(what, p string) error {
		asked = append(asked, what+"="+p)
		if p == path {
			return errRefused
		}
		return nil
	}
	return &asked
}

var errRefused = errors.New("refused: a private key")

// AZURE_FEDERATED_TOKEN_FILE names any file of this computer, and its
// contents go to the sign-in host: the file is checked first, and a
// refused one is neither read nor sent.
func TestAzureFederatedFileIsChecked(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	azureEnv(t, srv, "http://127.0.0.1:1/none")
	key := filepath.Join(t.TempDir(), "id_ed25519")
	os.WriteFile(key, []byte("PRIVATE KEY"), 0o600)
	t.Setenv("AZURE_TENANT_ID", "tenant1")
	t.Setenv("AZURE_CLIENT_ID", "app1")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", key)
	asked := refuseFiles(t, key)
	_, err := AzureToken(context.Background(), "https://vault.azure.net")
	if !errors.Is(err, errRefused) {
		t.Errorf("a refused token file: %v", err)
	}
	if errors.Is(err, ErrAzureLogin) {
		t.Errorf("the refusal is not a login problem a person fixes by signing in: %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("the sign-in host got %d requests", hits.Load())
	}
	if len(*asked) != 1 || (*asked)[0] != "AZURE_FEDERATED_TOKEN_FILE="+key {
		t.Errorf("asked: %q", *asked)
	}
}

// AZURE_AUTHORITY_HOST picks one of Azure's own sign-in hosts (the national
// clouds), never another https host: the client secret or the token file
// goes there.
func TestAzureAuthorityIsAnAzureHost(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	azureEnv(t, nil, "http://127.0.0.1:1/none")
	azureClient = srv.Client()
	t.Setenv("AZURE_TENANT_ID", "tenant1")
	t.Setenv("AZURE_CLIENT_ID", "app1")
	t.Setenv("AZURE_CLIENT_SECRET", "s3cret")
	for _, h := range []string{srv.URL, "https://login.example.com", "https://login.microsoftonline.com.example.com", "https://login.microsoftonline.com@" + strings.TrimPrefix(srv.URL, "https://")} {
		t.Setenv("AZURE_AUTHORITY_HOST", h)
		_, err := AzureToken(context.Background(), "https://vault.azure.net")
		if !errors.Is(err, ErrAzureLogin) || !strings.Contains(err.Error(), "AZURE_AUTHORITY_HOST") {
			t.Errorf("%s: %v", h, err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("another host got the client secret: %d requests", hits.Load())
	}
	for _, h := range []string{"https://login.microsoftonline.com", "https://login.microsoftonline.us/", "https://login.chinacloudapi.cn", "https://LOGIN.microsoftonline.com/"} {
		if _, ok := azureAuthorityHost(h); !ok {
			t.Errorf("%s is one of Azure's", h)
		}
	}
}

// AWS_WEB_IDENTITY_TOKEN_FILE, or web_identity_token_file of a profile in
// the file AWS_CONFIG_FILE names, is read and sent to the STS endpoint the
// environment names: it is checked like any file whose contents komando
// sends, before anything is read.
func TestAWSWebIdentityFileIsChecked(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(400) }))
	defer srv.Close()
	awsEnv(t)
	key := filepath.Join(t.TempDir(), "id_ed25519")
	os.WriteFile(key, []byte("PRIVATE KEY"), 0o600)
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("AWS_ENDPOINT_URL", srv.URL)
	t.Setenv("AWS_ENDPOINT_URL_STS", srv.URL) // AWSConfig sets it for the process: not another test's server
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
	refuseFiles(t, key)

	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/r")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", key)
	if _, err := AWSCredentials(context.Background(), ""); !errors.Is(err, errRefused) {
		t.Errorf("from the environment: %v", err)
	}
	if _, err := ECRToken(context.Background(), "default", "eu-west-1"); !errors.Is(err, errRefused) {
		t.Errorf("ECR login from the environment: %v", err)
	}
	t.Setenv("AWS_ROLE_ARN", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")

	cfg := "[profile web]\nrole_arn = arn:aws:iam::123456789012:role/r\nweb_identity_token_file = " + key + "\n"
	if err := os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AWSCredentials(context.Background(), "web"); !errors.Is(err, errRefused) {
		t.Errorf("from a profile: %v", err)
	}
	if _, _, _, err := AWSProfileAccess(context.Background(), "web", os.Getenv("AWS_CONFIG_FILE"), os.Getenv("AWS_SHARED_CREDENTIALS_FILE")); !errors.Is(err, errRefused) {
		t.Errorf("AWSProfileAccess: %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("the endpoint got %d requests", hits.Load())
	}
	// a token file that is allowed is used as before
	ok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(ok, []byte("jwt"), 0o600)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/r")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", ok)
	if _, err := AWSCredentials(context.Background(), ""); errors.Is(err, errRefused) || hits.Load() == 0 {
		t.Errorf("an allowed token file: %v, %d requests", err, hits.Load())
	}
}
