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
