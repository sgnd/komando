package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// withStdin runs fn with s piped on stdin.
func withStdin(t *testing.T, s string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	defer func() { os.Stdin = saved; r.Close() }()
	os.Stdin = r
	w.WriteString(s)
	w.Close()
	fn()
}

func setSecret(t *testing.T, name, value string) {
	t.Helper()
	t.Setenv("SECRET_TEST_VALUE", value)
	mustRun(t, "secret", "set", name, "--from-env", "SECRET_TEST_VALUE")
}

// refsTo points one of every kind of reference at secret:name.
func refsTo(t *testing.T, name string) {
	t.Helper()
	ref := "secret:" + name
	err := store.Update(func(s *store.State) error {
		s.Hosts["h1"] = &store.Host{Name: "h1", Address: "10.0.0.1", PasswordRef: ref}
		s.Hosts["h2"] = &store.Host{Name: "h2", Address: "10.0.0.2", SudoRef: ref, Env: map[string]string{"TOKEN": ref, "OTHER": "secret:other"}}
		s.Conns = map[string]*store.Conn{"db": {Name: "db", Kind: "postgres", URL: "postgres://u@db/x", PasswordRef: ref}}
		s.Keys["k"] = &store.Key{Name: "k", Path: "/x", PassphraseRef: ref}
		s.Vpns = map[string]*store.Vpn{"office": {Name: "office", Kind: "wireguard", KeyRef: ref, PSKRef: ref}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecretMvUpdatesEveryReference(t *testing.T) {
	invHome(t)
	setSecret(t, "old", "the-value")
	setSecret(t, "other", "x")
	refsTo(t, "old")
	want := "conn db,host h1,host h2,key k,vpn office"
	st, _ := loadState()
	if got := strings.Join(secretUsers(st, "old"), ","); got != want {
		t.Fatalf("users %s, want %s (a server's env counts too)", got, want)
	}
	wantCode(t, "SECRET_IN_USE", "secret", "rm", "old")

	// the preview changes nothing
	d := mustRun(t, "secret", "mv", "old", "new", "--dry-run")
	if d["would_move"] != true || len(d["would_update"].([]any)) != 5 {
		t.Errorf("dry run: %v", d)
	}
	if _, err := vault.Get("old"); err != nil {
		t.Fatal("the dry run renamed it")
	}

	d = mustRun(t, "secret", "mv", "old", "new")
	if len(d["updated"].([]any)) != 5 || d["ref"] != "secret:new" {
		t.Errorf("result: %v", d)
	}
	if _, ok := d["value"]; ok {
		t.Error("mv prints the value")
	}
	if v, err := vault.Get("new"); err != nil || v != "the-value" {
		t.Errorf("new = %q, %v", v, err)
	}
	if _, err := vault.Get("old"); err != vault.ErrNotFound {
		t.Errorf("old is still there: %v", err)
	}
	st, _ = loadState()
	h2 := st.Hosts["h2"]
	for what, got := range map[string]string{
		"host password": st.Hosts["h1"].PasswordRef, "sudo": h2.SudoRef, "env": h2.Env["TOKEN"],
		"conn": st.Conns["db"].PasswordRef, "key": st.Keys["k"].PassphraseRef,
		"vpn key": st.Vpns["office"].KeyRef, "vpn psk": st.Vpns["office"].PSKRef,
	} {
		if got != "secret:new" {
			t.Errorf("%s still says %s", what, got)
		}
	}
	if h2.Env["OTHER"] != "secret:other" {
		t.Errorf("an unrelated ref changed: %s", h2.Env["OTHER"])
	}
	if len(secretUsers(st, "old")) != 0 {
		t.Error("something still uses old")
	}

	// the audit names the secrets, never the value
	b := []byte(auditText(t))
	if !strings.Contains(string(b), `"secret.mv"`) || strings.Contains(string(b), "the-value") {
		t.Errorf("audit: %s", b)
	}

	// NEW is taken: --overwrite, and --yes when a protected server uses it
	e := wantCode(t, "SECRET_EXISTS", "secret", "mv", "new", "other")
	if e.Exit != out.ExitConflict || !strings.Contains(e.Hint, "--overwrite") {
		t.Errorf("exists: %+v", e)
	}
	mustRun(t, "host", "add", "prod", "u@10.0.0.9", "--protected", "--password-ref", "secret:other")
	wantCode(t, "PROTECTED_TARGET", "secret", "mv", "new", "other", "--overwrite")
	mustRun(t, "host", "rm", "prod", "--yes")
	mustRun(t, "secret", "mv", "new", "other", "--overwrite")
	if v, _ := vault.Get("other"); v != "the-value" {
		t.Errorf("overwrite: %q", v)
	}
	st, _ = loadState()
	if st.Hosts["h1"].PasswordRef != "secret:other" {
		t.Errorf("refs follow an overwrite too: %s", st.Hosts["h1"].PasswordRef)
	}

	wantCode(t, "SECRET_NOT_FOUND", "secret", "mv", "nope", "x")
	wantCode(t, "USAGE", "secret", "mv", "other", "other")
	wantCode(t, "USAGE", "secret", "mv", "other", "bad name")
}

func TestSecretCp(t *testing.T) {
	invHome(t)
	setSecret(t, "a", "v1")
	refsTo(t, "a")
	d := mustRun(t, "secret", "cp", "a", "b", "--dry-run")
	if d["would_copy"] != true {
		t.Errorf("dry run: %v", d)
	}
	if _, err := vault.Get("b"); err != vault.ErrNotFound {
		t.Fatal("the dry run copied it")
	}
	mustRun(t, "secret", "cp", "a", "b")
	for _, n := range []string{"a", "b"} {
		if v, _ := vault.Get(n); v != "v1" {
			t.Errorf("%s = %q", n, v)
		}
	}
	st, _ := loadState()
	if st.Hosts["h1"].PasswordRef != "secret:a" {
		t.Error("cp moved a reference")
	}
	wantCode(t, "SECRET_EXISTS", "secret", "cp", "a", "b")
}

// The approval code's key is a person's, set up by `config approval-code`:
// an agent must not replace, move, copy or remove it.
func TestSecretReservedName(t *testing.T) {
	invHome(t)
	_ = vault.Set(approvalSecret, "SEED")
	setSecret(t, "x", "v")
	t.Setenv("SECRET_TEST_VALUE", "MYSEED")
	wantCode(t, "RESERVED_SECRET", "secret", "set", approvalSecret, "--from-env", "SECRET_TEST_VALUE")
	wantCode(t, "RESERVED_SECRET", "secret", "rm", approvalSecret)
	wantCode(t, "RESERVED_SECRET", "secret", "mv", approvalSecret, "y")
	wantCode(t, "RESERVED_SECRET", "secret", "cp", "x", approvalSecret)
	if v, _ := vault.Get(approvalSecret); v != "SEED" {
		t.Errorf("changed: %q", v)
	}
}

func TestSecretSetFromPipe(t *testing.T) {
	invHome(t)
	// pbpaste and echo add a line break: it is not part of the value
	withStdin(t, "pass word\r\n", func() { mustRun(t, "secret", "set", "p1") })
	if v, _ := vault.Get("p1"); v != "pass word" {
		t.Errorf("p1 = %q", v)
	}
	// a space at the end is kept (a password can hold one), with a warning
	var d map[string]any
	withStdin(t, "copied-with-space \n", func() { d = mustRun(t, "secret", "set", "p2") })
	if v, _ := vault.Get("p2"); v != "copied-with-space " {
		t.Errorf("p2 = %q", v)
	}
	w, _ := d["warning"].(string)
	if !strings.Contains(w, "space") || strings.Contains(w, "copied") {
		t.Errorf("warning %q", w)
	}
	// secret get says so too, for an agent, without the value or its length
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	d = mustRun(t, "secret", "get", "p2")
	if w, _ := d["warning"].(string); !strings.Contains(w, "space") {
		t.Errorf("get: %v", d)
	}
	if _, ok := d["length"]; ok {
		t.Error("get shows the length")
	}
	if d = mustRun(t, "secret", "get", "p1"); d["warning"] != nil {
		t.Errorf("no warning for a clean value: %v", d)
	}
	withStdin(t, "\n\n", func() { wantCode(t, "USAGE", "secret", "set", "p3") })
}

func TestSecretCheck(t *testing.T) {
	invHome(t)
	setSecret(t, "vpn-pass", "Hunter2 ")
	withStdin(t, "Hunter2 \n", func() {
		if d := mustRun(t, "secret", "check", "vpn-pass"); d["match"] != true {
			t.Errorf("match: %v", d)
		}
	})
	var d map[string]any
	var e *out.Error
	withStdin(t, "Hunter2\n", func() { d, e = invRun(t, "secret", "check", "vpn-pass") })
	if e == nil || e.Code != "SECRET_MISMATCH" || e.Exit != out.ExitError || d["match"] != false {
		t.Fatalf("mismatch: %v %+v", d, e)
	}
	if diff := d["difference"].(string); !strings.Contains(diff, "spaces") || strings.Contains(diff, "Hunter") {
		t.Errorf("difference %q", diff)
	}
	b := []byte(auditText(t))
	if !strings.Contains(string(b), `"secret.check"`) || strings.Contains(string(b), "Hunter") {
		t.Errorf("audit: %s", b)
	}

	// an agent could guess with it one try at a time
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	withStdin(t, "Hunter2 \n", func() {
		if e := wantCode(t, "NEEDS_PERSON", "secret", "check", "vpn-pass"); e.Exit != out.ExitPolicy || strings.Contains(e.Hint, "add the flag") {
			t.Errorf("no flag allows it: %+v", e)
		}
	})
}

func TestSecretDiffAndWarning(t *testing.T) {
	for _, c := range []struct{ stored, given, want string }{
		{"abc ", "abc", "the stored value ends"},
		{"abc", " abc", "the value you entered starts"},
		{"Secret", "secret", "upper and lower case"},
		{"abcd", "abce", "both have 4 characters"},
		{"abcd", "ab", "has 4 characters, the one you entered 2"},
	} {
		if got := secretDiff(c.stored, c.given); !strings.Contains(got, c.want) {
			t.Errorf("%q vs %q: %s", c.stored, c.given, got)
		}
	}
	for v, want := range map[string]string{
		"ok": "", "multi\nline\n": "", "x\n": "line break", " x": "space", "x\t": "tab",
		"\x1b[200~x": "control characters",
	} {
		got := valueWarning("n", v)
		if want == "" && got != "" || !strings.Contains(got, want) {
			t.Errorf("%q: %q", v, got)
		}
	}
	if got := stripPasteMarks("\x1b[200~pw\x1b[201~"); got != "pw" {
		t.Errorf("paste marks: %q", got)
	}
}

// With no value, a script is told how to give one, but an AI agent is
// sent to the user: a password the user knows is typed by the user, not
// pasted into the chat for the agent to pipe in.
func TestSecretSetWithoutValueSendsAgentToUser(t *testing.T) {
	invHome(t)
	devnull, err := os.Open(os.DevNull) // not a terminal, not a pipe
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	os.Stdin = devnull
	t.Cleanup(func() { os.Stdin = saved; devnull.Close() })

	if e := wantCode(t, "USAGE", "secret", "set", "web1-pass"); !strings.Contains(e.Message, "--from-env") {
		t.Errorf("script: %+v", e)
	}
	windows := asAgent(t, true, true)
	e := wantCode(t, "NEEDS_PERSON", "secret", "set", "web1-pass")
	if !strings.Contains(e.Hint, "ask the user to run `komando secret set web1-pass` in their own terminal") ||
		!strings.Contains(e.Hint, "Never ask for a password in the chat") || e.Exit != out.ExitPolicy {
		t.Errorf("agent: %+v", e)
	}
	if strings.Contains(e.Hint, "window") || *windows != 0 {
		t.Errorf("no flag lets an agent type the user's password; hint %q, %d windows", e.Hint, *windows)
	}
	// a value a program makes still works for an agent
	withStdin(t, "generated-token-123\n", func() { mustRun(t, "secret", "set", "ci-token") })
}

// --from-env with an empty variable stores nothing, as an empty pipe does.
func TestSecretSetFromEmptyEnv(t *testing.T) {
	invHome(t)
	t.Setenv("EMPTY_PASS", "")
	if e := wantCode(t, "USAGE", "secret", "set", "x", "--from-env", "EMPTY_PASS"); e.Message != "env EMPTY_PASS is empty" {
		t.Errorf("message %q", e.Message)
	}
	t.Setenv("EMPTY_PASS", " \n")
	wantCode(t, "USAGE", "secret", "set", "x", "--from-env", "EMPTY_PASS")
	if names := secretNames(); len(names) != 0 {
		t.Errorf("stored %v", names)
	}
}
