package cli

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// runCache runs komando in this process and returns what it printed.
func runCache(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRoot()
	root.SetArgs(args)
	var b strings.Builder
	saved := out.P.W
	out.P.W = &b
	defer func() { out.P.W = saved; out.P.Reset() }()
	err := root.Execute()
	return b.String(), err
}

// TestCacheRunScriptsNeedApproval: a read-only script (EVAL_RO, EVALSHA_RO,
// FCALL_RO) cannot write, but it can loop and leave Redis answering BUSY to
// every client; module code (TFCALL, RG.PYEXECUTE) can do anything; FUNCTION
// LOAD REPLACE swaps code the application calls. All of them need --write
// and --allow-dangerous, and --dry-run sends nothing.
// The conn has no server: a command that got as far as connecting fails
// with CACHE_CONNECT.
func TestCacheRunScriptsNeedApproval(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	defer func() { g.dryRun, store.DryRun = false, false }()
	if _, err := runCache(t, "-o", "json", "conn", "add", "c", "redis://127.0.0.1:1/0"); err != nil {
		t.Fatal(err)
	}
	code := func(err error) string {
		var e *out.Error
		if errors.As(err, &e) {
			return e.Code
		}
		return ""
	}
	for _, command := range [][]string{
		{"EVAL_RO", "while true do end", "0"},
		{"evalsha_ro", "e0e1f9fabfc9d4800c877a703b823ac0578ff8db", "0"},
		{"FCALL_RO", "app_get", "1", "k"},
		{"FUNCTION", "LOAD", "REPLACE", "#!lua name=app\nredis.register_function('app_get', function() return 1 end)"},
		{"TFCALL", "app.get", "0"},
		{"RG.PYEXECUTE", "GB().run()"},
		{"TFUNCTION", "LOAD", "REPLACE", "#!js api_version=1.0 name=app"},
	} {
		run := func(flags ...string) (string, error) {
			return runCache(t, append(append([]string{"-o", "json", "cache", "run", "c"}, flags...), append([]string{"--"}, command...)...)...)
		}
		if _, err := run(); code(err) != "WRITE_REQUIRES_FLAG" || !strings.Contains(err.Error(), "--allow-dangerous") {
			t.Errorf("%s: %v", command[0], err)
		}
		if _, err := run("--dry-run"); code(err) != "WRITE_REQUIRES_FLAG" {
			t.Errorf("%s --dry-run sent it: %v", command[0], err)
		}
		if _, err := run("--write"); code(err) != "POLICY_BLOCKED" {
			t.Errorf("%s --write: %v", command[0], err)
		}
		s, err := run("--write", "--dry-run")
		if err != nil || !strings.Contains(s, "nothing sent") || !strings.Contains(s, "POLICY_BLOCKED") {
			t.Errorf("%s --write --dry-run: %v\n%s", command[0], err, s)
		}
		g.dryRun, store.DryRun = false, false
	}
}

// TestCacheRunHidesPasswordsLive: an AI agent reads CONFIG GET without
// --write, so requirepass and masterauth must come out [hidden] (set
// KOMANDO_E2E_REDIS=host:port and KOMANDO_E2E_REDIS_PASSWORD to a server
// started with --requirepass and --masterauth).
func TestCacheRunHidesPasswordsLive(t *testing.T) {
	addr, pw := os.Getenv("KOMANDO_E2E_REDIS"), os.Getenv("KOMANDO_E2E_REDIS_PASSWORD")
	if addr == "" || pw == "" {
		t.Skip("set KOMANDO_E2E_REDIS=host:port and KOMANDO_E2E_REDIS_PASSWORD")
	}
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	t.Setenv("KOMANDO_TEST_REDIS_PW", pw) // an env: reference, which the vault redaction does not know
	if _, err := runCache(t, "-o", "json", "conn", "add", "c", "redis://"+addr+"/0", "--password-ref", "env:KOMANDO_TEST_REDIS_PW"); err != nil {
		t.Fatal(err)
	}
	asAgent(t, false, true)
	defer func() { out.P.Mask = false }()
	for _, format := range []string{"json", "text"} {
		for _, param := range []string{"requirepass", "masterauth", "*"} {
			s, err := runCache(t, "-o", format, "cache", "run", "c", "--", "CONFIG", "GET", param)
			if err != nil || strings.Contains(s, pw) || !strings.Contains(s, out.Hidden) {
				t.Errorf("%s CONFIG GET %s: %v\n%s", format, param, err, s)
			}
			if format == "text" && param != "*" && s != "1# "+param+": [hidden]\n" {
				t.Errorf("text: %q", s)
			}
		}
	}
}

// A command in one quoted argument is read as words, so "get foo" is the
// read GET, and MONITOR, which never returns, is refused before connecting.
func TestCacheRunQuotedCommand(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	defer func() { g.dryRun, store.DryRun = false, false }()
	if _, err := runCache(t, "-o", "json", "conn", "add", "c", "redis://127.0.0.1:1/0"); err != nil {
		t.Fatal(err)
	}
	code := func(err error) string {
		var e *out.Error
		if errors.As(err, &e) {
			return e.Code
		}
		return ""
	}
	if _, err := runCache(t, "-o", "json", "cache", "run", "c", "get foo"); code(err) != "CACHE_CONNECT" {
		t.Errorf("get foo: %v", err)
	}
	if _, err := runCache(t, "-o", "json", "cache", "run", "c", "--write", "--dry-run", "--", "MONITOR"); code(err) != "NOT_SUPPORTED" {
		t.Errorf("MONITOR: %v", err)
	}
}
