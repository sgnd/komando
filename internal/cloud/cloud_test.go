package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// awsEnv isolates the AWS SDK from the developer's own ~/.aws.
func awsEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, k := range []string{"AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	return home
}

func TestVaultKV(t *testing.T) {
	var gotToken, gotNS atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken.Store(r.Header.Get("X-Vault-Token"))
		gotNS.Store(r.Header.Get("X-Vault-Namespace"))
		switch r.URL.Path {
		case "/v1/sys/internal/ui/mounts/secret/shop":
			io.WriteString(w, `{"data":{"path":"secret/","options":{"version":"2"}}}`)
		case "/v1/secret/data/shop":
			io.WriteString(w, `{"data":{"data":{"db_password":"pw2","port":5432}}}`)
		case "/v1/sys/internal/ui/mounts/kv1/app":
			io.WriteString(w, `{"data":{"path":"kv1/","options":{}}}`)
		case "/v1/kv1/app":
			io.WriteString(w, `{"data":{"token":"pw1"}}`)
		case "/v1/sys/internal/ui/mounts/secret/locked", "/v1/secret/data/locked":
			if strings.HasPrefix(r.URL.Path, "/v1/sys") {
				io.WriteString(w, `{"data":{"path":"secret/","options":{"version":"2"}}}`)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"errors":["permission denied"]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"errors":[]}`)
		}
	}))
	defer srv.Close()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("VAULT_NAMESPACE", "team-a")

	if _, err := VaultKV(context.Background(), "secret/shop", "db_password"); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Errorf("no token: %v", err)
	}
	os.WriteFile(filepath.Join(home, ".vault-token"), []byte("tok-from-file\n"), 0o600)

	for _, c := range []struct{ path, field, want string }{
		{"secret/shop", "db_password", "pw2"},
		{"/secret/shop/", "port", "5432"},
		{"kv1/app", "token", "pw1"},
	} {
		got, err := VaultKV(context.Background(), c.path, c.field)
		if err != nil || got != c.want {
			t.Errorf("%s#%s: %q %v, want %q", c.path, c.field, got, err, c.want)
		}
	}
	if gotToken.Load() != "tok-from-file" || gotNS.Load() != "team-a" {
		t.Errorf("token %v, namespace %v", gotToken.Load(), gotNS.Load())
	}
	for path, want := range map[string]string{"secret/locked": "permission denied", "secret/nope": "no secret", "secret/shop#": ""} {
		if path == "secret/shop#" {
			if _, err := VaultKV(context.Background(), "secret/shop", "nope"); err == nil || !strings.Contains(err.Error(), "no field") {
				t.Errorf("missing field: %v", err)
			}
			continue
		}
		if _, err := VaultKV(context.Background(), path, "x"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
	}
}

func TestGCPSecret(t *testing.T) {
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/v1/projects/my-proj/secrets/db-pass/versions/latest:access":
			io.WriteString(w, `{"payload":{"data":"`+base64.StdEncoding.EncodeToString([]byte("gcp-pw"))+`"}}`)
		case "/v1/projects/other/secrets/x/versions/3:access":
			io.WriteString(w, `{"payload":{"data":"`+base64.StdEncoding.EncodeToString([]byte("v3"))+`"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":{"message":"Secret not found","status":"NOT_FOUND"}}`)
		}
	}))
	defer srv.Close()
	savedE, savedC := gcpSecretEndpoint, gcpCredentials
	defer func() { gcpSecretEndpoint, gcpCredentials = savedE, savedC }()
	gcpSecretEndpoint = srv.URL
	gcpCredentials = func(context.Context) (*google.Credentials, error) {
		return &google.Credentials{ProjectID: "my-proj", TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "ya29.test"})}, nil
	}
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")

	if got, err := GCPSecret(context.Background(), "db-pass", ""); err != nil || got != "gcp-pw" {
		t.Errorf("project from credentials: %q %v", got, err)
	}
	if auth.Load() != "Bearer ya29.test" {
		t.Errorf("authorization: %v", auth.Load())
	}
	if got, err := GCPSecret(context.Background(), "projects/other/secrets/x/versions/3", ""); err != nil || got != "v3" {
		t.Errorf("full name: %q %v", got, err)
	}
	if _, err := GCPSecret(context.Background(), "missing", ""); err == nil || !strings.Contains(err.Error(), "Secret not found") {
		t.Errorf("not found: %v", err)
	}
	gcpCredentials = func(context.Context) (*google.Credentials, error) {
		return nil, errors.New("could not find default credentials")
	}
	if _, err := GCPSecret(context.Background(), "db-pass", "p"); !errors.Is(err, ErrGCPLogin) {
		t.Errorf("no credentials: %v", err)
	}
}

func TestGcloudProject(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLOUDSDK_CONFIG", dir)
	os.MkdirAll(filepath.Join(dir, "configurations"), 0o700)
	os.WriteFile(filepath.Join(dir, "active_config"), []byte("work\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "configurations", "config_work"), []byte("[auth]\nproject = wrong\n[core]\naccount = a@b\nproject = from-gcloud\n"), 0o600)
	if got := gcloudProject(); got != "from-gcloud" {
		t.Errorf("got %q", got)
	}
}

// fakeAWS answers AWS JSON-protocol calls by their X-Amz-Target.
func fakeAWS(t *testing.T, answers map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		a, ok := answers[target]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"__type":"ResourceNotFoundException","message":"no such thing"}`)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		io.WriteString(w, a)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAWSSecretAndECR(t *testing.T) {
	awsEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_REGION", "eu-west-1")
	srv := fakeAWS(t, map[string]string{
		"secretsmanager.GetSecretValue": `{"SecretString":"{\"password\":\"pw\"}"}`,
		"AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken": `{"authorizationData":[{"authorizationToken":"` +
			base64.StdEncoding.EncodeToString([]byte("AWS:ecr-pw")) + `"}]}`,
	})
	t.Setenv("AWS_ENDPOINT_URL", srv.URL)

	if got, err := AWSSecret(context.Background(), "shop/db"); err != nil || got != `{"password":"pw"}` {
		t.Errorf("secret: %q %v", got, err)
	}
	if got, err := ECRToken(context.Background(), "", "eu-west-1"); err != nil || got != "ecr-pw" {
		t.Errorf("ecr: %q %v", got, err)
	}
	if arnPart("arn:aws:secretsmanager:ap-southeast-1:123:secret:x", 3) != "ap-southeast-1" || arnPart("plain", 3) != "" {
		t.Error("arnPart")
	}
}

func TestAWSProfiles(t *testing.T) {
	home := awsEnv(t)
	os.WriteFile(filepath.Join(home, "credentials"), []byte("[prod]\naws_access_key_id = AKIAPROD\naws_secret_access_key = s\n"), 0o600)
	c, err := AWSCredentials(context.Background(), "prod")
	if err != nil || c.AccessKeyID != "AKIAPROD" {
		t.Fatalf("static profile: %+v %v", c, err)
	}
	if _, err := AWSCredentials(context.Background(), "nope"); !AWSProfileMissing(err) {
		t.Errorf("missing profile: %v", err)
	}
}

// TestAWSSSOLogin runs the whole SSO flow against fake AWS endpoints: the
// device login writes the cache file, then the SDK turns it into keys.
func TestAWSSSOLogin(t *testing.T) {
	home := awsEnv(t)
	os.WriteFile(filepath.Join(home, "config"), []byte(`[profile dev]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = Admin
region = eu-west-1

[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
sso_region = eu-west-1
`), 0o600)
	var polls atomic.Int32
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/client/register":
			io.WriteString(w, `{"clientId":"cid","clientSecret":"csecret","clientSecretExpiresAt":`+itoa(time.Now().Add(90*24*time.Hour).Unix())+`}`)
		case "/device_authorization":
			io.WriteString(w, `{"deviceCode":"dev","userCode":"ABCD-EFGH","verificationUriComplete":"https://device.sso/?code=ABCD-EFGH","interval":1,"expiresIn":60}`)
		case "/token":
			if polls.Add(1) == 1 {
				w.Header().Set("X-Amzn-Errortype", "AuthorizationPendingException")
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, `{"error":"authorization_pending"}`)
				return
			}
			io.WriteString(w, `{"accessToken":"sso-access","expiresIn":3600,"refreshToken":"sso-refresh","tokenType":"Bearer"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer oidc.Close()
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Sso_bearer_token") != "sso-access" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"roleCredentials":{"accessKeyId":"ASIASSO","secretAccessKey":"s","sessionToken":"t","expiration":`+
			itoa(time.Now().Add(time.Hour).UnixMilli())+`}}`)
	}))
	defer portal.Close()
	saved := ssoOIDCEndpoint
	defer func() { ssoOIDCEndpoint = saved }()
	ssoOIDCEndpoint = oidc.URL
	t.Setenv("AWS_ENDPOINT_URL_SSO", portal.URL)

	var shown string
	path, err := AWSSSOLogin(context.Background(), "dev", func(url, code string) { shown = code + " " + url })
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if shown != "ABCD-EFGH https://device.sso/?code=ABCD-EFGH" {
		t.Errorf("shown %q", shown)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 || !strings.HasPrefix(path, filepath.Join(home, ".aws", "sso", "cache")) {
		t.Fatalf("cache file %s: %v %v", path, fi, err)
	}
	var cache map[string]any
	b, _ := os.ReadFile(path)
	json.Unmarshal(b, &cache)
	if cache["accessToken"] != "sso-access" || cache["refreshToken"] != "sso-refresh" || cache["clientId"] != "cid" {
		t.Errorf("cache %v", cache)
	}
	c, err := AWSCredentials(context.Background(), "dev")
	if err != nil || c.AccessKeyID != "ASIASSO" {
		t.Fatalf("keys from the SSO login: %+v %v", c, err)
	}

	// a profile without SSO says so
	os.WriteFile(filepath.Join(home, "config"), []byte("[profile plain]\nregion = eu-west-1\n"), 0o600)
	if _, err := AWSSSOLogin(context.Background(), "plain", func(string, string) {}); err == nil || !strings.Contains(err.Error(), "does not use SSO") {
		t.Errorf("non-SSO profile: %v", err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestGCPAccessTokenErrors(t *testing.T) {
	saved := gcpCredentials
	defer func() { gcpCredentials = saved }()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("APPDATA", home)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	gcpCredentials = func(context.Context) (*google.Credentials, error) {
		return nil, errors.New("could not find default credentials")
	}
	if _, err := GCPAccessToken(context.Background()); !errors.Is(err, ErrGCPLogin) || !errors.Is(err, ErrGCPNoCredentials) {
		t.Errorf("no credentials: %v", err)
	}
	// a key file that is set but missing is a broken login, not none
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(home, "missing.json"))
	gcpCredentials = saved
	if _, err := GCPAccessToken(context.Background()); !errors.Is(err, ErrGCPLogin) || errors.Is(err, ErrGCPNoCredentials) {
		t.Errorf("a missing key file: %v", err)
	}
	// so is a gcloud login file that does not parse
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	adc := filepath.Join(home, ".config", "gcloud")
	if runtime.GOOS == "windows" {
		adc = filepath.Join(home, "gcloud")
	}
	if err := os.MkdirAll(adc, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adc, "application_default_credentials.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GCPAccessToken(context.Background()); !errors.Is(err, ErrGCPLogin) || errors.Is(err, ErrGCPNoCredentials) {
		t.Errorf("a broken gcloud login: %v", err)
	}
	gcpCredentials = func(context.Context) (*google.Credentials, error) {
		return &google.Credentials{TokenSource: failingSource{}}, nil
	}
	if _, err := GCPAccessToken(context.Background()); !errors.Is(err, ErrGCPLogin) || errors.Is(err, ErrGCPNoCredentials) {
		t.Errorf("a login that fails: %v", err)
	}
}

type failingSource struct{}

func (failingSource) Token() (*oauth2.Token, error) { return nil, errors.New("invalid_grant") }
