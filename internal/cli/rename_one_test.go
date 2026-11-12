package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/vault"
)

// `komando rename OLD NEW` without --prefix renames the one entry named OLD
// through its own command; two kinds of one name, or none, are refused
// with the commands to use (C-V23).
func TestRenameOneEntry(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	if d := mustRun(t, "--dry-run", "rename", "web1", "web-01"); d["to"] != "web-01" {
		t.Errorf("dry run: %v", d)
	}
	if st, _ := loadState(); st.Hosts["web1"] == nil {
		t.Fatal("a dry run renamed it")
	}
	code, text := runMain(t, "rename", "web1", "web-01")
	if code != 0 || !strings.Contains(text, `"command":"host.mv"`) {
		t.Fatalf("rename web1: exit %d %s", code, text)
	}
	if st, _ := loadState(); st.Hosts["web-01"] == nil || st.Hosts["web1"] != nil {
		t.Fatal("web1 was not renamed")
	}
	if err := vault.Set("db-pass", "s3cret-value"); err != nil {
		t.Fatal(err)
	}
	if d := mustRun(t, "rename", "db-pass", "shop-db-pass"); d["to"] != "shop-db-pass" {
		t.Errorf("rename a secret: %v", d)
	}
	mustRun(t, "group", "add", "front", "web-01")
	if d := mustRun(t, "rename", "@front", "edge"); d["to"] != "edge" {
		t.Errorf("rename a group: %v", d)
	}
	if err := vault.Set("web-01", "other-value"); err != nil {
		t.Fatal(err)
	}
	e := wantCode(t, "USAGE", "rename", "web-01", "web-02")
	if !strings.Contains(e.Message, `"web-01" is a server and a secret`) ||
		!strings.Contains(e.Hint, "`komando host rename web-01 web-02` or `komando secret rename web-01 web-02`") {
		t.Errorf("two kinds: %+v", e)
	}
	e = wantCode(t, "USAGE", "rename", "nope", "x")
	if !strings.Contains(e.Hint, "komando rename --starts-with nope x --dry-run") {
		t.Errorf("none: %+v", e)
	}
	wantCode(t, "USAGE", "rename", "web-01", "web-02", "--notes")
	// --prefix keeps the prefix rename
	if d := mustRun(t, "--dry-run", "rename", "--prefix", "web-", "site-"); d["count"] == nil {
		t.Errorf("--prefix: %v", d)
	}
}
