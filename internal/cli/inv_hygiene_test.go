package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func TestDoctorConnHygiene(t *testing.T) {
	invHome(t)
	setSecret(t, "prd-minio", "x")
	setSecret(t, "prd-sudo", "x")
	st := &store.State{Hosts: map[string]*store.Host{}, Keys: map[string]*store.Key{}, Conns: map[string]*store.Conn{}, Vpns: map[string]*store.Vpn{}}
	st.Hosts["prd"] = &store.Host{Name: "prd", Address: "10.0.0.1", Port: 22, Protected: true, SudoRef: "credential:prd-sudo"}
	st.Conns["prd-minio"] = &store.Conn{Name: "prd-minio", Kind: "s3", URL: "s3://key@minio.prd/b", PasswordRef: "credential:prd-minio", Protected: true}
	// a dev conn with the production password
	st.Conns["dev-minio"] = &store.Conn{Name: "dev-minio", Kind: "s3", URL: "s3://key@minio.dev/b", PasswordRef: "credential:prd-minio"}
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
		"conn:dev-minio": "shares credential:prd-minio with protected conn prd-minio",
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
	// the way out names commands of this version (chief, 2026-11-28, with
	// rule R7): a credential of its own, then the conn's own edit
	hint := got["conn:dev-minio"]
	if !strings.Contains(hint, "`komando credential password add NEW`, then `komando ") || strings.Contains(hint, "secret cp") || strings.Contains(hint, "password-ref") {
		t.Fatalf("dev-minio hint: %s", hint)
	}
	_, edit, _ := strings.Cut(hint, "then `komando ")
	edit, _, _ = strings.Cut(edit, "`")
	words := strings.Fields(edit)
	if len(words) < 3 || !slices.Equal(words[len(words)-3:], []string{"dev-minio", "--credential", "NEW"}) {
		t.Fatalf("dev-minio edit line %q", edit)
	}
	cmd, _, err := newRoot(tcl).Find(words[:len(words)-3])
	if err != nil || cmd.Name() != "edit" || cmd.Flags().Lookup("credential") == nil {
		t.Errorf("%q names no edit with --credential: %v", edit, err)
	}
}

// show takes one name; a selector gets a hint that names the commands
// taking one instead of a bare "not found".
func TestShowSelectorHint(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1", "--group", "acme")
	e := wantCode(t, "TARGET_NOT_FOUND", "host", "ssh", "show", "@acme")
	if !strings.Contains(e.Hint, "takes one host name") || !strings.Contains(e.Hint, "`komando list @acme`") {
		t.Errorf("hint: %s", e.Hint)
	}
	e = wantCode(t, "TARGET_NOT_FOUND", "conn", "show", "web-*")
	if !strings.Contains(e.Hint, "`komando list 'web-*'`") {
		t.Errorf("glob hint: %s", e.Hint)
	}
	// a plain typo gets a suggestion (S-8.8)
	e = wantCode(t, "TARGET_NOT_FOUND", "host", "ssh", "show", "web2")
	if e.Suggestion != "web1" || !strings.Contains(e.Hint, "web1") {
		t.Errorf("typo: %+v", e)
	}
}
