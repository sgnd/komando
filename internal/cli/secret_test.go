package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	kitterm "github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/inventory"
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
	saved := tcl.stdin
	defer func() { tcl.stdin = saved; r.Close() }()
	tcl.stdin = r
	w.WriteString(s)
	w.Close()
	fn()
}

func setSecret(t *testing.T, name, value string) {
	t.Helper()
	t.Setenv("SECRET_TEST_VALUE", value)
	mustRun(t, "credential", "password", "add", name, "--from-env", "SECRET_TEST_VALUE")
}

// refsTo points one of every kind of reference at secret:name.
func refsTo(t *testing.T, name string) {
	t.Helper()
	ref := "secret:" + name
	err := store.Update(store.Save(), func(s *store.State) error {
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
	if got := strings.Join(inventory.SecretUsers(st, "old"), ","); got != want {
		t.Fatalf("users %s, want %s (a server's env counts too)", got, want)
	}
	wantCode(t, "SECRET_IN_USE", "credential", "password", "remove", "old")

	// the preview changes nothing
	d := mustRun(t, "credential", "password", "rename", "old", "new", "--dry-run")
	if d["would_move"] != true || len(d["would_update"].([]any)) != 5 {
		t.Errorf("dry run: %v", d)
	}
	if _, err := vault.Get("old"); err != nil {
		t.Fatal("the dry run renamed it")
	}

	d = mustRun(t, "credential", "password", "rename", "old", "new")
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
	if len(inventory.SecretUsers(st, "old")) != 0 {
		t.Error("something still uses old")
	}

	// the audit names the secrets, never the value
	b := []byte(auditText(t))
	if !strings.Contains(string(b), `"credential.password.rename"`) || strings.Contains(string(b), "the-value") {
		t.Errorf("audit: %s", b)
	}

	// NEW is taken: --overwrite, and --yes when a protected server uses it
	e := wantCode(t, "SECRET_EXISTS", "credential", "password", "rename", "new", "other")
	if e.Exit != out.ExitConflict || !strings.Contains(e.Hint, "--overwrite") {
		t.Errorf("exists: %+v", e)
	}
	mustRun(t, "host", "ssh", "add", "prod", "u@10.0.0.9", "--protected", "--credential", "other")
	wantCode(t, "PROTECTED_TARGET", "credential", "password", "rename", "new", "other", "--overwrite")
	mustRun(t, "host", "ssh", "remove", "prod", "--yes")
	mustRun(t, "credential", "password", "rename", "new", "other", "--overwrite")
	if v, _ := vault.Get("other"); v != "the-value" {
		t.Errorf("overwrite: %q", v)
	}
	st, _ = loadState()
	if st.Hosts["h1"].PasswordRef != "secret:other" {
		t.Errorf("refs follow an overwrite too: %s", st.Hosts["h1"].PasswordRef)
	}

	wantCode(t, "SECRET_NOT_FOUND", "credential", "password", "rename", "nope", "x")
	wantCode(t, "USAGE", "credential", "password", "rename", "other", "other")
	wantCode(t, "USAGE", "credential", "password", "rename", "other", "bad name")
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
	_ = vault.Set(store.Save(), approvalSecret, "SEED")
	setSecret(t, "x", "v")
	t.Setenv("SECRET_TEST_VALUE", "MYSEED")
	wantCode(t, "RESERVED_SECRET", "credential", "password", "add", approvalSecret, "--from-env", "SECRET_TEST_VALUE")
	wantCode(t, "RESERVED_SECRET", "credential", "password", "remove", approvalSecret)
	wantCode(t, "RESERVED_SECRET", "credential", "password", "rename", approvalSecret, "y")
	wantCode(t, "RESERVED_SECRET", "secret", "cp", "x", approvalSecret)
	if v, _ := vault.Get(approvalSecret); v != "SEED" {
		t.Errorf("changed: %q", v)
	}
}

func TestSecretSetFromPipe(t *testing.T) {
	invHome(t)
	// pbpaste and echo add a line break: it is not part of the value
	withStdin(t, "pass word\r\n", func() { mustRun(t, "credential", "password", "add", "p1") })
	if v, _ := vault.Get("p1"); v != "pass word" {
		t.Errorf("p1 = %q", v)
	}
	// a space at the end is kept (a password can hold one), with a warning
	var d map[string]any
	withStdin(t, "copied-with-space \n", func() { d = mustRun(t, "credential", "password", "add", "p2") })
	if v, _ := vault.Get("p2"); v != "copied-with-space " {
		t.Errorf("p2 = %q", v)
	}
	w, _ := d["warning"].(string)
	if !strings.Contains(w, "space") || strings.Contains(w, "copied") {
		t.Errorf("warning %q", w)
	}
	// secret get says so too, for an agent, without the value or its length
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	d = mustRun(t, "credential", "password", "show", "p2")
	if w, _ := d["warning"].(string); !strings.Contains(w, "space") {
		t.Errorf("get: %v", d)
	}
	if _, ok := d["length"]; ok {
		t.Error("get shows the length")
	}
	if d = mustRun(t, "credential", "password", "show", "p1"); d["warning"] != nil {
		t.Errorf("no warning for a clean value: %v", d)
	}
	withStdin(t, "\n\n", func() { wantCode(t, "USAGE", "credential", "password", "add", "p3") })
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
	setCallerEnv(t, "KOMANDO_AGENT", "1")
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
	if got := kitterm.StripPasteMarks("\x1b[200~pw\x1b[201~"); got != "pw" {
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
	saved := tcl.stdin
	tcl.stdin = devnull
	t.Cleanup(func() { tcl.stdin = saved; devnull.Close() })

	if e := wantCode(t, "USAGE", "credential", "password", "add", "web1-pass"); !strings.Contains(e.Message, "--from-env") {
		t.Errorf("script: %+v", e)
	}
	windows := asAgent(t, true, true)
	e := wantCode(t, "NEEDS_PERSON", "credential", "password", "add", "web1-pass")
	if !strings.Contains(e.Hint, "ask the user to run `komando credential password add web1-pass` in their own terminal") ||
		!strings.Contains(e.Hint, "Never ask for a password in the chat") || e.Exit != out.ExitPolicy {
		t.Errorf("agent: %+v", e)
	}
	if strings.Contains(e.Hint, "window") || *windows != 0 {
		t.Errorf("no flag lets an agent type the user's password; hint %q, %d windows", e.Hint, *windows)
	}
	// a value a program makes still works for an agent
	withStdin(t, "generated-token-123\n", func() { mustRun(t, "credential", "token", "add", "ci-token") })
}

// --from-env with an empty variable stores nothing, as an empty pipe does.
func TestSecretSetFromEmptyEnv(t *testing.T) {
	invHome(t)
	t.Setenv("EMPTY_PASS", "")
	if e := wantCode(t, "USAGE", "credential", "password", "add", "x", "--from-env", "EMPTY_PASS"); e.Message != "env EMPTY_PASS is empty" {
		t.Errorf("message %q", e.Message)
	}
	t.Setenv("EMPTY_PASS", " \n")
	wantCode(t, "USAGE", "credential", "password", "add", "x", "--from-env", "EMPTY_PASS")
	if names := secretNames(); len(names) != 0 {
		t.Errorf("stored %v", names)
	}
}

// C186: a value that is a common word is easy to guess, and komando hides
// that word everywhere in its output, so storing one gets a warning.
func TestCommonWordValue(t *testing.T) {
	tests := []struct {
		name, v string
		want    bool
	}{
		{"short lowercase word", "shared", true},
		{"short capitalised word", "Sunshine", true},
		{"listed password with digits", "password1", true},
		{"listed digits", "123456", true},
		{"listed, any case", "QWERTY123", true},
		{"ten letters", "correcthor", false},
		{"word with a digit", "shar3d", false},
		{"word with a symbol", "shared!", false},
		{"long passphrase", "correct horse battery", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commonWord(tt.v); got != tt.want {
				t.Errorf("commonWord(%q) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

func metaWarnings(d map[string]any) string {
	m, _ := d["_meta"].(map[string]any)
	return fmt.Sprint(m["warnings"])
}

// secret set, import and doctor warn about a common-word value by name,
// never printing the value.
func TestCommonWordWarnings(t *testing.T) {
	invHome(t)
	t.Setenv("SECRET_TEST_VALUE", "sunshine")
	d := mustRun(t, "credential", "password", "add", "web-pass", "--from-env", "SECRET_TEST_VALUE")
	w := metaWarnings(d)
	if !strings.Contains(w, "secret web-pass: this value is a common word") || strings.Contains(w, "sunshine") {
		t.Errorf("secret set: %s", w)
	}
	t.Setenv("SECRET_TEST_VALUE", "Xk3-long-enough-9")
	if w := metaWarnings(mustRun(t, "credential", "password", "add", "ok-pass", "--from-env", "SECRET_TEST_VALUE")); strings.Contains(w, "common word") {
		t.Errorf("a strong value: %s", w)
	}
	env := writeTemp(t, ".env", "DATABASE_URL=postgres://app:letmein@127.0.0.1:5432/shop\n")
	d = mustRun(t, "import", "env", env)
	if w := metaWarnings(d); !strings.Contains(w, "this value is a common word") || strings.Contains(w, "letmein") {
		t.Errorf("import: %s", w)
	}
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range securityChecks(tcl, st) {
		if c.Name == "security:common_secrets" {
			found = true
			if !c.Warning || !strings.Contains(c.Detail, "web-pass") || strings.Contains(c.Detail, "ok-pass") || strings.Contains(c.Detail, "sunshine") {
				t.Errorf("doctor: %+v", c)
			}
		}
	}
	if !found {
		t.Error("doctor does not list the common-word secrets")
	}
}
