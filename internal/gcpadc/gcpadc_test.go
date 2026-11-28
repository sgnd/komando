package gcpadc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/transport"
)

const scope = "https://www.googleapis.com/auth/cloud-platform"

// adcFile writes cfg as the file GOOGLE_APPLICATION_CREDENTIALS names.
func adcFile(t *testing.T, cfg map[string]any) {
	t.Helper()
	b, _ := json.Marshal(cfg)
	p := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", p)
}

func external(tokenURL, file string) map[string]any {
	return map[string]any{"type": "external_account", "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "token_url": tokenURL, "credential_source": map[string]any{"file": file}}
}

// use asks for a token when Find gave credentials, as every caller does.
func use(t *testing.T) error {
	t.Helper()
	creds, err := Find(context.Background(), scope)
	if err != nil {
		return err
	}
	_, err = creds.TokenSource.Token()
	return err
}

// An external_account file names a local file and the address its contents
// go to. The address has to be Google's, over https; a file an AI agent
// may not send is refused before it is read.
func TestExternalAccountGoesToGoogleOnly(t *testing.T) {
	var hits atomic.Int32
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = r.ParseForm()
		got.Store(r.Form.Get("subject_token"))
		w.WriteHeader(400)
	}))
	defer srv.Close()
	key := filepath.Join(t.TempDir(), "id_ed25519")
	os.WriteFile(key, []byte("PRIVATE KEY"), 0o600)

	for _, u := range []string{srv.URL + "/token", "https://sts.example.com/v1/token", "https://sts.googleapis.com.example.com/v1/token",
		"http://sts.googleapis.com/v1/token", "https://sts.googleapis.com@" + strings.TrimPrefix(srv.URL, "http://") + "/v1/token"} {
		adcFile(t, external(u, key))
		err := use(t)
		if err == nil || !strings.Contains(err.Error(), "token_url") {
			t.Errorf("token_url %s: %v", u, err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("an address that is not Google's got the file: %d requests, %q", hits.Load(), got.Load())
	}
	cfg := external("https://sts.googleapis.com/v1/token", key)
	cfg["service_account_impersonation_url"] = srv.URL + "/v1/projects/-/serviceAccounts/x:generateAccessToken"
	adcFile(t, cfg)
	if _, err := Find(context.Background(), scope); err == nil || !strings.Contains(err.Error(), "service_account_impersonation_url") {
		t.Errorf("an impersonation address that is not Google's: %v", err)
	}
	user := map[string]any{"type": "external_account_authorized_user", "audience": "//iam.googleapis.com/locations/global/workforcePools/p/providers/x",
		"refresh_token": "r", "client_id": "c", "client_secret": "s", "token_url": srv.URL + "/token"}
	adcFile(t, user)
	if err := use(t); err == nil || !strings.Contains(err.Error(), "token_url") || hits.Load() != 0 {
		t.Errorf("a workforce login file with another token_url: %v, %d requests", err, hits.Load())
	}

	// Google's address, but a file the hook refuses
	refused := errors.New("refused: a private key")
	var asked []string
	saved := CheckLocalFile
	defer func() { CheckLocalFile = saved }()
	CheckLocalFile = func(what, p string) error {
		asked = append(asked, what+"="+p)
		if p == key {
			return refused
		}
		return nil
	}
	adcFile(t, external("https://sts.googleapis.com/v1/token", key))
	_, err := Find(context.Background(), scope)
	var fe *FileError
	if !errors.As(err, &fe) || !errors.Is(fe.Err, refused) {
		t.Errorf("a refused credential_source.file: %v", err)
	}
	if len(asked) != 1 || !strings.Contains(asked[0], "credential_source.file") {
		t.Errorf("asked: %q", asked)
	}
	// an allowed file, Google's regional and plain addresses: found
	ok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(ok, []byte("jwt"), 0o600)
	for _, u := range []string{"https://sts.googleapis.com/v1/token", "https://sts.us-east1.rep.googleapis.com/v1/token"} {
		adcFile(t, external(u, ok))
		if _, err := Find(context.Background(), scope); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// The usual files pass as before: a gcloud login, and the well-known file
// when GOOGLE_APPLICATION_CREDENTIALS is not set.
func TestUsualFiles(t *testing.T) {
	adcFile(t, map[string]any{"type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r"})
	if _, err := Find(context.Background(), scope); err != nil {
		t.Errorf("a gcloud login: %v", err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", home)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	dir := filepath.Join(home, ".config", "gcloud")
	if runtime.GOOS == "windows" {
		dir = filepath.Join(home, "gcloud")
	}
	os.MkdirAll(dir, 0o700)
	b, _ := json.Marshal(external("https://sts.example.com/v1/token", "/nonexistent"))
	os.WriteFile(filepath.Join(dir, "application_default_credentials.json"), b, 0o600)
	if _, err := Find(context.Background(), scope); err == nil || !strings.Contains(err.Error(), "token_url") {
		t.Errorf("the well-known file is checked too: %v", err)
	}
}

// A file can wrap one kind of login in another (impersonated_service_account
// holds source_credentials): what is inside is checked the same way.
func TestNestedCredentialsAreChecked(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(400) }))
	defer srv.Close()
	key := filepath.Join(t.TempDir(), "id_ed25519")
	os.WriteFile(key, []byte("PRIVATE KEY"), 0o600)
	adcFile(t, map[string]any{"type": "impersonated_service_account",
		"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/x@p.iam.gserviceaccount.com:generateAccessToken",
		"source_credentials":                external(srv.URL+"/t", key)})
	if err := use(t); err == nil || !strings.Contains(err.Error(), "token_url") || hits.Load() != 0 {
		t.Errorf("an external_account inside source_credentials: %v, %d requests", err, hits.Load())
	}
	adcFile(t, map[string]any{"type": "impersonated_service_account", "service_account_impersonation_url": srv.URL + "/x",
		"source_credentials": map[string]any{"type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r"}})
	if _, err := Find(context.Background(), scope); err == nil || !strings.Contains(err.Error(), "service_account_impersonation_url") {
		t.Errorf("an impersonation address that is not Google's: %v", err)
	}
}

// "On googleapis.com" is not enough: a bucket there takes uploads from
// anyone. The login goes to Google's token services only.
func TestOnlyGooglesTokenServices(t *testing.T) {
	key := filepath.Join(t.TempDir(), "token")
	os.WriteFile(key, []byte("jwt"), 0o600)
	for _, u := range []string{"https://storage.googleapis.com/upload/storage/v1/b/bucket/o?uploadType=media&name=x",
		"https://sts.googleapis.com/v1/token?x=1", "https://sts.googleapis.com/other", "https://pubsub.googleapis.com/v1/token"} {
		adcFile(t, external(u, key))
		if _, err := Find(context.Background(), scope); err == nil || !strings.Contains(err.Error(), "token_url") {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// For an AI agent's environment only the two plain kinds of file are
// used (a gcloud login, a service account key): every other kind reads
// files, runs programs or calls addresses the file names. The login is
// then made from the bytes that were checked, not from a second read.
func TestAgentEnvironmentUsesPlainFilesOnly(t *testing.T) {
	defer transport.DistrustEnv()()
	ok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(ok, []byte("jwt"), 0o600)
	exe := external("https://sts.googleapis.com/v1/token", "")
	exe["credential_source"] = map[string]any{"executable": map[string]any{"command": "/tmp/x"}}
	for name, cfg := range map[string]map[string]any{
		"external_account":             external("https://sts.googleapis.com/v1/token", ok),
		"external_account, executable": exe,
		"impersonated_service_account": {"type": "impersonated_service_account", "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/x",
			"source_credentials": map[string]any{"type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r"}},
	} {
		adcFile(t, cfg)
		var fe *FileError
		_, err := Find(context.Background(), scope)
		var oe *out.Error
		if !errors.As(err, &fe) || !strings.Contains(err.Error(), "AI agent") || !errors.As(err, &oe) || oe.Code != "NEEDS_PERSON" {
			t.Errorf("%s: %v", name, err)
		}
	}
	adcFile(t, map[string]any{"type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r"})
	if _, err := Find(context.Background(), scope); err != nil {
		t.Errorf("a gcloud login: %v", err)
	}
}

// In an AI agent's environment a file that cannot be read, or is no
// JSON, is refused: it is never handed to the Google library, which
// would read the path a second time (a named pipe answers each read
// with something else).
func TestAgentEnvironmentReadsTheFileOnce(t *testing.T) {
	defer transport.DistrustEnv()()
	p := filepath.Join(t.TempDir(), "adc.json")
	os.WriteFile(p, []byte("x"), 0o600)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", p)
	var fe *FileError
	if _, err := Find(context.Background(), scope); !errors.As(err, &fe) {
		t.Errorf("a file that is no JSON: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "gone.json"))
	if _, err := Find(context.Background(), scope); !errors.As(err, &fe) {
		t.Errorf("a file that is not there: %v", err)
	}
}

// C671: with no login file, a key's or an AI agent's run takes this
// machine's own account from the metadata server, through the metadata
// library's own client: komando's transport (and so a gate dialer, which
// Find is never handed) carries none of it.
func TestNoFileTakesTheMachineAccountFromTheMetadataServer(t *testing.T) {
	defer transport.DistrustEnv()()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", home)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	var tokens atomic.Int32
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Metadata-Flavor", "Google")
		if strings.HasSuffix(r.URL.Path, "/service-accounts/default/token") {
			tokens.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"machine","expires_in":3600,"token_type":"Bearer"}`))
			return
		}
		w.Write([]byte("p"))
	}))
	defer md.Close()
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(md.URL, "http://"))
	var viaKomando atomic.Int32
	komando := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		viaKomando.Add(1)
		return nil, errors.New("komando's transport")
	})}
	creds, err := Find(context.WithValue(context.Background(), oauth2.HTTPClient, komando), scope)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := creds.TokenSource.Token()
	if err != nil || tok.AccessToken != "machine" || tokens.Load() != 1 || viaKomando.Load() != 0 {
		t.Errorf("token %v %v; metadata server asked %d times, komando's transport %d", tok, err, tokens.Load(), viaKomando.Load())
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
