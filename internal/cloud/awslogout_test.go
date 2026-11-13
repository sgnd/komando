package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
)

// saveSSOCache writes a cache file as aws sso login (or komando login
// aws) leaves it for key.
func saveSSOCache(t *testing.T, key string, c map[string]string) string {
	t.Helper()
	p, err := ssocreds.StandardCachedTokenFilepath(key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	if err := writeTokenFile(p, b); err != nil {
		t.Fatal(err)
	}
	return p
}

const ssoConfig = `[profile dev]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = Admin

[profile ops]
sso_session = corp
sso_account_id = 444455556666
sso_role_name = Ops

[profile old]
sso_start_url = https://old.awsapps.com/start
sso_region = us-east-1
sso_account_id = 111122223333
sso_role_name = Admin

[profile keys]
region = eu-west-1

[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
sso_region = eu-west-1
`

// The SSO logins of the profiles: one per cache file with every profile
// that uses it; one that ran out without a refresh token is gone, one
// with a refresh token renews; a profile with keys has none.
func TestAWSSSOLogins(t *testing.T) {
	home := awsEnv(t)
	os.WriteFile(filepath.Join(home, "config"), []byte(ssoConfig), 0o600)
	later := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	saveSSOCache(t, "corp", map[string]string{"startUrl": "https://corp.awsapps.com/start", "region": "eu-west-1", "accessToken": "tok",
		"expiresAt": later, "refreshToken": "r", "registrationExpiresAt": later})
	saveSSOCache(t, "https://old.awsapps.com/start", map[string]string{"startUrl": "https://old.awsapps.com/start", "region": "us-east-1",
		"accessToken": "tok", "expiresAt": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	ls := AWSSSOLogins(context.Background(), []string{"dev", "ops", "old", "keys", "missing"})
	if len(ls) != 1 {
		t.Fatalf("logins %+v", ls)
	}
	l := ls[0]
	if len(l.Profiles) != 2 || l.Profiles[0] != "dev" || l.Profiles[1] != "ops" || l.Session != "corp" || !l.Renews ||
		l.StartURL != "https://corp.awsapps.com/start" || l.ExpiresAt.IsZero() || l.LoggedInAt.IsZero() {
		t.Errorf("login %+v", l)
	}
	b, _ := json.Marshal(l)
	if strings.Contains(string(b), `"tok"`) || strings.Contains(string(b), `"r"`) {
		t.Errorf("a token in the JSON: %s", b)
	}
}

// logout aws tells IAM Identity Center to end the token and deletes the
// cache file; when AWS cannot be reached the file still goes.
func TestAWSSSOLogout(t *testing.T) {
	home := awsEnv(t)
	os.WriteFile(filepath.Join(home, "config"), []byte(ssoConfig), 0o600)
	var got string
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path + " " + r.Header.Get("X-Amz-Sso_bearer_token")
	}))
	defer portal.Close()
	saved := ssoEndpoint
	defer func() { ssoEndpoint = saved }()
	ssoEndpoint = portal.URL
	later := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	p := saveSSOCache(t, "corp", map[string]string{"startUrl": "https://corp.awsapps.com/start", "region": "eu-west-1", "accessToken": "tok-1", "expiresAt": later})
	l, revoked, ok, err := AWSSSOLogout(context.Background(), "ops")
	if err != nil || !ok || !revoked || l.Session != "corp" {
		t.Fatalf("logout: %+v %v %v %v", l, revoked, ok, err)
	}
	if got != "/logout tok-1" {
		t.Errorf("AWS was told %q", got)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("the cache file is still there")
	}
	if _, _, ok, err := AWSSSOLogout(context.Background(), "dev"); ok || err != nil {
		t.Errorf("second logout: ok %v err %v", ok, err)
	}
	// AWS cannot be reached: the login on this computer still ends
	portal.Close()
	p = saveSSOCache(t, "corp", map[string]string{"startUrl": "https://corp.awsapps.com/start", "region": "eu-west-1", "accessToken": "tok-2", "expiresAt": later})
	if _, revoked, ok, err := AWSSSOLogout(context.Background(), "dev"); !ok || revoked || err != nil {
		t.Errorf("offline logout: revoked %v ok %v err %v", revoked, ok, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("offline: the cache file is still there")
	}
	if _, _, _, err := AWSSSOLogout(context.Background(), "keys"); err == nil {
		t.Error("a profile with keys has no SSO login to end")
	}
}
