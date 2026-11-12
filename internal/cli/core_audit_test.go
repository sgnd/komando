package cli

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// An import with --overwrite skips a protected conn, as it skips a
// protected server, and its dry run says the same as the real run.
func TestImportOverwriteSkipsProtectedConn(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "r1", "redis://127.0.0.1:6379/0", "--protected")
	mustRun(t, "host", "add", "w1", "u@10.0.0.1", "--protected")
	mustRun(t, "conn", "add", "p1", "postgres://u@127.0.0.1/app")
	file := writeTemp(t, "exp.json", `{"format":"komando-export/1",
		"hosts":[{"name":"w1","address":"10.0.0.9","user":"u"}],
		"conns":[{"name":"r1","kind":"redis","url":"redis://127.0.0.1:6380/0"},
		         {"name":"p1","kind":"postgres","url":"postgres://u@127.0.0.1/other"}]}`)
	for _, dry := range []bool{true, false} {
		args := []string{"import", "komando", file, "--overwrite"}
		if dry {
			args = append(args, "--dry-run")
		}
		d := mustRun(t, args...)
		if got := fmt.Sprint(d["conns"]); got != "[p1]" {
			t.Errorf("dry run %v: conns %s, want [p1]", dry, got)
		}
		skipped := fmt.Sprint(d["skipped"])
		if !strings.Contains(skipped, "name:r1 reason:protected") || !strings.Contains(skipped, "name:w1 reason:protected") {
			t.Errorf("dry run %v: skipped %s", dry, skipped)
		}
	}
	if d := mustRun(t, "conn", "show", "r1"); !strings.Contains(fmt.Sprint(d["url"]), ":6379") {
		t.Errorf("the protected conn changed: %v", d)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "''",
		"root":                 "root",
		"/usr/local/bin/k":     "/usr/local/bin/k",
		"a b":                  "'a b'",
		"x;rm -rf ~":           "'x;rm -rf ~'",
		"it's":                 `'it'\''s'`,
		"$(id)":                "'$(id)'",
		"a\nb":                 "'a\nb'",
		"secret:web1-pass,x=1": "secret:web1-pass,x=1",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// host rm names every server and conn that goes through the server, so one
// round of edits clears them all.
func TestHostRmInUseNamesEveryUser(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "b1", "u@10.0.0.1")
	mustRun(t, "host", "add", "h1", "u@10.0.0.2", "--via", "b1")
	mustRun(t, "conn", "add", "c1", "redis://10.0.0.3:6379/0", "--via", "b1")
	e := wantCode(t, "HOST_IN_USE", "host", "rm", "b1")
	for _, want := range []string{"server h1", "conn c1"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("message %q lacks %q", e.Message, want)
		}
	}
	for _, want := range []string{"komando host edit h1 --unset via", "komando conn edit c1 --unset via"} {
		if !strings.Contains(e.Hint, want) {
			t.Errorf("hint %q lacks %q", e.Hint, want)
		}
	}
}

// key rm names every server that still uses the key, and its text says
// what happened in words, not as raw fields.
func TestKeyRmInUseAndText(t *testing.T) {
	invHome(t)
	mustRun(t, "key", "gen", "k1")
	mustRun(t, "host", "add", "a", "u@10.0.0.1", "--key", "k1")
	mustRun(t, "host", "add", "b", "u@10.0.0.2", "--key", "k1")
	e := wantCode(t, "KEY_IN_USE", "key", "rm", "k1")
	if !strings.Contains(e.Message, "a and b") || !strings.Contains(e.Hint, "host edit a b --key OTHER") {
		t.Errorf("want both servers named: %s / %s", e.Message, e.Hint)
	}
	mustRun(t, "host", "edit", "a", "b", "--unset", "key")
	txt := coreText(t, "key", "rm", "k1", "--delete-file")
	if !strings.Contains(txt, "removed key k1") || strings.Contains(txt, "file_deleted") {
		t.Errorf("text: %q", txt)
	}
}

// coreText runs komando with -o text and returns what it printed.
func coreText(t *testing.T, args ...string) string {
	t.Helper()
	g.dryRun, g.yes, store.DryRun = false, false, false
	root := newRoot()
	root.SetArgs(append([]string{"-o", "text"}, args...))
	var buf bytes.Buffer
	saved := out.P.W
	out.P.W = &buf
	defer func() { out.P.W = saved }()
	if err := root.Execute(); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return buf.String()
}

// import says what to run next, which names it replaced, and its dry run
// never says the rest "is in".
func TestImportNextReplacedAndPreview(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "cache", "redis://127.0.0.1:6379/0")
	env := writeTemp(t, ".env", "CACHE_URL=redis://127.0.0.1:6380/0\nDATABASE_URL=postgres://app@127.0.0.1:5432/app\n")
	d := mustRun(t, "import", "env", env, "--overwrite")
	if d["next"] != "komando test cache,database" {
		t.Errorf("next: %v", d["next"])
	}
	if fmt.Sprint(d["replaced"]) != "[cache]" {
		t.Errorf("replaced: %v", d["replaced"])
	}
	d = mustRun(t, "import", "env", env, "--overwrite", "-g", "shop", "--dry-run")
	if d["next"] != "komando test @shop" {
		t.Errorf("next with a group: %v", d["next"])
	}
	if got := importNext([]string{"a", "b", "c", "d", "e", "f"}, nil); got != "komando test all" {
		t.Errorf("many: %s", got)
	}
	g.dryRun = true
	defer func() { g.dryRun = false }()
	e := toErr(importIncomplete(1))
	if strings.Contains(e.Hint, "the rest is in") || !strings.Contains(e.Message, "would not") {
		t.Errorf("a preview says nothing is in yet: %s / %s", e.Message, e.Hint)
	}
}

// An import gets the TLS default conn add gives: verified TLS where the URL
// says nothing, and a clear-text login over the network is refused.
func TestImportAppliesConnTLSDefault(t *testing.T) {
	invHome(t)
	env := writeTemp(t, ".env", "REDIS_URL=redis://:pw@cache9.example:6379/0\nDATABASE_URL=postgres://app:pw@db.example:5432/shop\nLOCAL_REDIS_URL=redis://127.0.0.1:6379/0\n")
	d := mustRun(t, "import", "env", env)
	if got := fmt.Sprint(d["conns"]); got != "[database local-redis]" {
		t.Errorf("conns: %s", got)
	}
	if !strings.Contains(fmt.Sprint(d["skipped"]), "INSECURE") && !strings.Contains(fmt.Sprint(d["skipped"]), "without TLS") {
		t.Errorf("clear-text redis must be skipped: %v", d["skipped"])
	}
	c := mustRun(t, "conn", "show", "database")
	if !strings.Contains(fmt.Sprint(c["url"]), "sslmode=verify-full") {
		t.Errorf("postgres over the network gets verified TLS: %v", c["url"])
	}
	if !strings.Contains(fmt.Sprint(d["notes"]), "sslmode=verify-full") {
		t.Errorf("the note says so: %v", d["notes"])
	}
	// importing the same file again changes nothing (the stored URL has the default)
	d = mustRun(t, "import", "env", env)
	if fmt.Sprint(d["conns"]) != "[]" {
		t.Errorf("second import added %v", d["conns"])
	}
}

// group add and group rm take several targets, like host rm and host edit.
func TestGroupAddRmSeveralTargets(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "a", "u@10.0.0.1")
	mustRun(t, "host", "add", "b", "u@10.0.0.2")
	mustRun(t, "group", "add", "web", "a", "b")
	if d := mustRun(t, "list", "@web"); d["count"] != float64(2) {
		t.Errorf("@web: %v", d)
	}
	mustRun(t, "group", "rm", "web", "a", "b")
	wantCode(t, "TARGET_EMPTY", "list", "@web")
}

// An address that starts with - would be an option in the ssh line host
// ssh-command prints: it is refused, and one saved before is never printed.
func TestHostAddressNeverAnOption(t *testing.T) {
	invHome(t)
	wantCode(t, "USAGE", "host", "add", "e1", "u@-oProxyCommand=x")
	wantCode(t, "USAGE", "host", "add", "e2", "--address=-oProxyCommand=x")
	st := &store.State{Hosts: map[string]*store.Host{"old": {Name: "old", Address: "-oproxycommand=x"}}}
	if _, err := sshCommandFor(st, st.Hosts["old"]); err == nil || !strings.Contains(err.Error(), "option") {
		t.Errorf("want a refusal, got %v", err)
	}
}

// export names a key komando made as sealed (no file to copy), not by its
// sealed: path as a "key file".
func TestExportSealedKey(t *testing.T) {
	invHome(t)
	mustRun(t, "key", "gen", "k1")
	mustRun(t, "host", "add", "a", "u@10.0.0.1", "--key", "k1")
	d := mustRun(t, "export", "--to", filepath.Join(t.TempDir(), "e.json"))
	if fmt.Sprint(d["keys_sealed"]) != "[k1]" || d["key_files"] != nil {
		t.Errorf("keys_sealed %v key_files %v", d["keys_sealed"], d["key_files"])
	}
}
