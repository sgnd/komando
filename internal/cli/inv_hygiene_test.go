package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func TestDoctorConnHygiene(t *testing.T) {
	invHome(t)
	setSecret(t, "prd-minio", "x")
	setSecret(t, "prd-sudo", "x")
	st := &store.State{Hosts: map[string]*store.Host{}, Keys: map[string]*store.Key{}, Conns: map[string]*store.Conn{}, Vpns: map[string]*store.Vpn{}}
	st.Hosts["prd"] = &store.Host{Name: "prd", Address: "10.0.0.1", Port: 22, Protected: true, SudoRef: "secret:prd-sudo"}
	st.Conns["prd-minio"] = &store.Conn{Name: "prd-minio", Kind: "s3", URL: "s3://key@minio.prd/b", PasswordRef: "secret:prd-minio", Protected: true}
	// a dev conn with the production password
	st.Conns["dev-minio"] = &store.Conn{Name: "dev-minio", Kind: "s3", URL: "s3://key@minio.dev/b", PasswordRef: "secret:prd-minio"}
	// two conns to the same place
	st.Conns["app"] = &store.Conn{Name: "app", Kind: "postgres", URL: "postgres://postgres@10.0.0.2:5432/shop", Protected: true}
	st.Conns["db-shop"] = &store.Conn{Name: "db-shop", Kind: "postgres", URL: "postgres://postgres@10.0.0.2:5432/shop", Protected: true}
	// same URL through another path is another place
	st.Conns["db-other"] = &store.Conn{Name: "db-other", Kind: "postgres", URL: "postgres://postgres@10.0.0.2:5432/shop", Via: "prd", Protected: true}
	// on the protected server, not protected itself
	st.Conns["redis"] = &store.Conn{Name: "redis", Kind: "redis", URL: "redis://10.0.0.1:6379", Labels: map[string]string{"host": "prd"}}
	got := map[string]string{}
	for _, c := range inventoryChecks(tcl, st) {
		if c.Warning {
			got[c.Name] += c.Detail + "\n"
		}
	}
	for name, want := range map[string]string{
		"conn:dev-minio": "shares secret:prd-minio with protected conn prd-minio",
		"conn:db-shop":   "same kind, URL and --via as conn app",
		"conn:redis":     "label host=prd, a protected server",
	} {
		if !strings.Contains(got[name], want) {
			t.Errorf("%s: want %q, got %q", name, want, got[name])
		}
	}
	for _, name := range []string{"conn:prd-minio", "conn:app", "conn:db-other"} {
		if got[name] != "" {
			t.Errorf("%s warned: %s", name, got[name])
		}
	}
	if !strings.Contains(got["conn:dev-minio"], "`komando secret cp prd-minio NEW` and `komando conn edit dev-minio --password-ref secret:NEW`") {
		t.Errorf("dev-minio hint: %s", got["conn:dev-minio"])
	}
}

// show takes one name; a selector gets a hint that names the commands
// taking one instead of a bare "not found".
func TestShowSelectorHint(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--group", "acme")
	e := wantCode(t, "HOST_NOT_FOUND", "host", "show", "@acme")
	if !strings.Contains(e.Hint, "takes one host name") || !strings.Contains(e.Hint, "`komando list @acme`") {
		t.Errorf("hint: %s", e.Hint)
	}
	e = wantCode(t, "CONN_NOT_FOUND", "conn", "show", "web-*")
	if !strings.Contains(e.Hint, "`komando list 'web-*'`") {
		t.Errorf("glob hint: %s", e.Hint)
	}
	// a plain typo gets a suggestion (S-8.8)
	e = wantCode(t, "HOST_NOT_FOUND", "host", "show", "web2")
	if e.Suggestion != "web1" || !strings.Contains(e.Hint, "web1") {
		t.Errorf("typo: %+v", e)
	}
}
