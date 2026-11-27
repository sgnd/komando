package cli

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealkey"
	"github.com/sgnd/komando/internal/sealrow"
	"github.com/sgnd/komando/internal/store"
)

// The audit log's os_user is the account komando runs as, on every
// system: Windows has no uid (os.Getuid is -1 there), so it must not read
// "uid -1".
func TestOSUser(t *testing.T) {
	if u := osUser(); u == "" || u == "unknown" || strings.HasPrefix(u, "uid -") {
		t.Fatalf("osUser() = %q", u)
	}
}

// A protected mark taken off with the row key alone (no policy key) stops
// every command with POLICY_MAC_FAILED naming the server: a load, and a
// read of the vault, which reaches the store without a load (toErr).
func TestPolicyMACStopsCommands(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web", "--address", "10.0.0.5", "--protected")
	t.Setenv("PW", "s3cret")
	mustRun(t, "secret", "set", "db-pass", "--from-env", "PW")
	master, err := store.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	rk, _ := sealkey.Derive(master, sealkey.RowsV3)
	k, _ := sealrow.NewKey(rk)
	d, err := sealdb.Open(context.Background(), store.DBPath(), k)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
		rows, err := tx.List(store.KindHost)
		if err != nil || len(rows) != 1 {
			return fmt.Errorf("hosts %d: %w", len(rows), err)
		}
		_, err = tx.Put(store.KindHost, rows[0].ID, bytes.Replace(rows[0].Data, []byte(`"protected":true`), []byte(`"protected":false`), 1))
		return err
	})
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"list"}, {"secret", "list"}} {
		if e := wantCode(t, "POLICY_MAC_FAILED", args...); !strings.Contains(e.Message, "server web") {
			t.Errorf("%v: %s", args, e.Message)
		}
	}
}

// GuardScript leaves the carried rules out, so only scripts komando writes
// whole, with no words a person or agent typed, may use it.
// A new caller must be added here on purpose, after review.
func TestGuardScriptCallers(t *testing.T) {
	// code lines only: common.go defines GuardScript, the others call it
	// with lines komando wrote; runOps (modules_run.go) uses Guard
	want := map[string]int{"common.go": 1, "pkg_security.go": 1, "docker_prune.go": 2}
	wantCheckScript := map[string]int{"common.go": 1}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	got, gotCheckScript := map[string]int{}, map[string]int{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			got[f] += strings.Count(line, "GuardScript(")
			gotCheckScript[f] += strings.Count(line, "policy.CheckScript")
		}
		maps.DeleteFunc(got, func(_ string, n int) bool { return n == 0 })
		maps.DeleteFunc(gotCheckScript, func(_ string, n int) bool { return n == 0 })
	}
	if !maps.Equal(got, want) {
		t.Errorf("GuardScript is used in %v, want only %v (komando's own scripts)", got, want)
	}
	if !maps.Equal(gotCheckScript, wantCheckScript) {
		t.Errorf("policy.CheckScript is used in %v, want only %v (GuardScript)", gotCheckScript, wantCheckScript)
	}
}

// The scripts komando writes for pkg security and docker prune still stop
// on the carried rules when the same text comes through exec.
func TestOwnScriptsThroughExecHitCarriedRules(t *testing.T) {
	srv := startFakeServer(t)
	tmp := t.TempDir()
	for name, c := range map[string]struct{ script, rule string }{
		"pkg security": {pkgSecScript(true, true, true), "rm-files"},
		"docker prune": {"docker system prune -f", "docker-prune"},
	} {
		p := filepath.Join(tmp, strings.ReplaceAll(name, " ", "-")+".sh")
		if err := os.WriteFile(p, []byte(c.script), 0o600); err != nil {
			t.Fatal(err)
		}
		err := runRoot(t, "exec", "prod", "--yes", "--script", p)
		if e := toErr(err); e == nil || e.Code != "POLICY_BLOCKED" || !strings.Contains(e.Message, c.rule) {
			t.Errorf("%s through exec: %v, want POLICY_BLOCKED naming %s", name, err, c.rule)
		}
		if n := len(srv.take()); n != 0 {
			t.Errorf("%s through exec ran %d times", name, n)
		}
	}
}

// A cancelled command (Ctrl-C, a signal) stops with CANCELLED: agents
// branch on the code and the exit, a person reads the text.
func TestCancelledErrorUnchanged(t *testing.T) {
	for name, e := range map[string]*out.Error{
		"toErr":   toErr(context.Canceled),
		"wrapped": toErr(fmt.Errorf("copy: %w", context.Canceled)),
	} {
		if e.Code != "CANCELLED" || e.Message != "interrupted" || e.Exit != out.ExitError {
			t.Errorf("%s: code %q, message %q, exit %d", name, e.Code, e.Message, e.Exit)
		}
		if want := "it stopped before the end (Ctrl-C or a signal); check what it left, then run it again"; e.Hint != want {
			t.Errorf("%s: hint %q, want %q", name, e.Hint, want)
		}
		if want := "Stopped (Ctrl-C) before the end; what already ran stays as it is"; e.TextMessage() != want {
			t.Errorf("%s: text message %q", name, e.TextMessage())
		}
		if want := "check what it left, then run it again"; e.TextHint() != want {
			t.Errorf("%s: text hint %q", name, e.TextHint())
		}
	}
}
