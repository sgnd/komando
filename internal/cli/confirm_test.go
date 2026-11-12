package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// What a person types is the name of what goes, the count of several, or
// the target for a whole-target step; never the bare word yes (S-7.3,
// OD-8).
func TestTypedAnswer(t *testing.T) {
	for _, c := range []struct {
		items       []string
		want, shown string
	}{
		{[]string{"session:42"}, "session:42", "the name session:42"},
		{[]string{"a", "b", "c"}, "3", "3 (keys in c1)"},
		{[]string{strings.Repeat("x", 61)}, "1", "1 (keys in c1)"},
		{[]string{"bad\x1bname"}, "1", "1 (keys in c1)"},
		{nil, "", ""},
	} {
		if w, s := typedAnswer(c.items, "keys in c1"); w != c.want || s != c.shown {
			t.Errorf("%q: %q %q", c.items, w, s)
		}
	}
}

// A step that cannot be undone on a protected server asks one typed
// question that covers the protection too (S-7.4, C-C04): the answer typed
// once lets both checks through, with no [y/N] after it.
func TestDangerOnProtectedAsksOnce(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "prod1", "u@127.0.0.1:1", "--protected")
	personTypes(t, "prod1") // one line: a second question would read no answer
	_, e := invRun(t, "reboot", "prod1")
	if e == nil || e.Code == "POLICY_BLOCKED" || e.Code == "PROTECTED_HOST" {
		t.Fatalf("the typed name must cover both stops: %+v", e)
	}
}

// A dry run lists every flag the real run needs (meta.would_need), and the
// first real stop's hint names them all (S-7.5, C-C04).
func TestWouldNeedEveryFlag(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "prod1", "u@127.0.0.1:1", "--protected")
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:2")
	_, text := runMain(t, "--dry-run", "reboot", "prod1")
	if !strings.Contains(text, `"would_need":["--allow-dangerous","--yes"]`) {
		t.Errorf("dry run: %s", text)
	}
	_, text = runMain(t, "--dry-run", "reboot", "web1")
	if !strings.Contains(text, `"would_need":["--allow-dangerous"]`) {
		t.Errorf("dry run, not protected: %s", text)
	}
	if e := wantCode(t, "POLICY_BLOCKED", "reboot", "prod1"); !strings.Contains(e.Hint, "--allow-dangerous and --yes") {
		t.Errorf("hint: %q", e.Hint)
	}
	if e := wantCode(t, "POLICY_BLOCKED", "reboot", "web1"); strings.Contains(e.Hint, "--yes") {
		t.Errorf("hint, not protected: %q", e.Hint)
	}
	// fs rm of one file is dangerous (OD-7); on a protected server the dry
	// run still names --yes, and so does the first stop's hint
	_, text = runMain(t, "--dry-run", "fs", "rm", "prod1", "/tmp/x")
	if !strings.Contains(text, `"would_need":["--allow-dangerous","--yes"]`) {
		t.Errorf("fs rm dry run: %s", text)
	}
	if e := wantCode(t, "POLICY_BLOCKED", "fs", "rm", "prod1", "/tmp/x"); !strings.Contains(e.Hint, "--allow-dangerous and --yes") {
		t.Errorf("fs rm hint: %q", e.Hint)
	}
	_, text = runMain(t, "--dry-run", "secret", "rm", "nothing-here")
	if strings.Contains(text, "would_need") {
		t.Errorf("a missing secret stops before the gate: %s", text)
	}
}

// A dry run that cannot try a step says so in meta.not_simulated (C-C12):
// sqlite's VACUUM runs outside a transaction, so the preview leaves it out.
// DRY_RUN_UNSUPPORTED is the fallback for a write that reaches the store in
// a dry run, which should not happen: it is a usage error, exit 2.
func TestDryRunNotSimulated(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(t.TempDir(), "app.db"))
	mustRun(t, "db", "query", "lite", "--write", "CREATE TABLE a (x int)") // the file is there
	_, text := runMain(t, "--dry-run", "db", "query", "lite", "--write", "VACUUM")
	if !strings.Contains(text, `"not_simulated":["VACUUM statement: this statement cannot be rolled back, so it was not executed"]`) {
		t.Errorf("dry run of VACUUM: %s", text)
	}
	if _, text = runMain(t, "--dry-run", "db", "query", "lite", "--write", "CREATE TABLE t (x int)"); strings.Contains(text, "not_simulated") {
		t.Errorf("a statement the dry run tried: %s", text)
	}
	if e := toErr(fmt.Errorf("vault: %w", store.ErrDryRun)); e.Code != "DRY_RUN_UNSUPPORTED" || e.Exit != out.ExitUsage {
		t.Errorf("fallback: %+v", e)
	}
}
