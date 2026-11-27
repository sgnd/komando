package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// A password typed where the name of a credential belongs is refused, and
// it is in no answer, warning, audit record or saved server.
func TestBareCredentialNotInVaultIsRefused(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1")
	const typed = "Hunter2x"
	for _, args := range [][]string{
		{"host", "ssh", "edit", "web1", "--credential", typed},
		{"host", "ssh", "edit", "web1", "--sudo-credential", typed},
		{"host", "ssh", "add", "web2", "u@10.0.0.2", "--credential", typed},
		{"host", "winrm", "add", "win1", "Administrator@10.0.0.9", "--credential", typed},
	} {
		var stderr bytes.Buffer
		saved := tcl.out.Err
		tcl.out.Err = &stderr
		d, e := invRun(t, args...)
		tcl.out.Err = saved
		if e == nil || e.Code != "USAGE" || e.Exit != out.ExitUsage {
			t.Errorf("%v: want USAGE, got %+v", args, e)
			continue
		}
		if shown := fmt.Sprint(d, e.Message, e.Hint, stderr.String()); strings.Contains(shown, typed) {
			t.Errorf("%v: the typed value is repeated: %s", args, shown)
		}
	}
	if a := auditText(t); strings.Contains(a, typed) {
		t.Errorf("the typed value is in the audit log: %s", a)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(st); bytes.Contains(b, []byte(typed)) {
		t.Errorf("the typed value is in the server list: %s", b)
	}
}

// A bare name that is in the vault is that secret.
func TestBareCredentialInVaultIsTheSecret(t *testing.T) {
	invHome(t)
	if err := vault.Set(store.Save(), "web1-pw", "v"); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1")
	mustRun(t, "host", "ssh", "edit", "web1", "--credential", "web1-pw")
	if d := mustRun(t, "host", "ssh", "show", "web1"); d["password_ref"] != "credential:web1-pw" {
		t.Errorf("show: %v", d)
	}
}
