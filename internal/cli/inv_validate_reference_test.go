package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
)

// Owner O-09: a reference is spelled credential:NAME. The spelling of
// format 2 (secret:NAME) given on a command is refused with a hint that
// names credential:NAME: it is never read, stored or sent as plain text.
func TestOldReferenceSpellingRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"host password", []string{"host", "add", "web1", "u@10.0.0.5", "--password-ref", "secret:web1-pass"}},
		{"host env", []string{"host", "add", "web1", "u@10.0.0.5", "--env", "PG=secret:web1-pass"}},
		{"secret run env", append([]string{"secret", "run", "--env", "PG=secret:web1-pass"}, childArgs()...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invHome(t)
			e := wantCode(t, "REFERENCE_UNSUPPORTED", tc.args...)
			if !strings.Contains(e.Hint, "credential:web1-pass") {
				t.Fatalf("hint %q does not name credential:web1-pass", e.Hint)
			}
			if d := mustRun(t, "host", "list"); strings.Contains(strings.ToLower(jsonOf(d)), "web1") {
				t.Fatalf("the host was saved: %s", jsonOf(d))
			}
		})
	}
}

// CLI-5, 2026-11-26: a flag that names a credential takes credential:NAME;
// an outside store (env:VAR, op://...) stops before anything is asked or
// planned, so --dry-run stops too.
func TestOutsideStoreOnCredentialFlagRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"host password", []string{"host", "add", "web1", "u@10.0.0.5", "--password-ref", "env:WEB_PW", "--dry-run"}},
		{"host sudo", []string{"host", "add", "web1", "u@10.0.0.5", "--sudo-ref", "file:/tmp/pw", "--dry-run"}},
		{"service password", []string{"conn", "add", "web1-db", "postgres://app@10.0.0.5/shop", "--password-ref", "op://ops/db/password", "--dry-run"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invHome(t)
			e := wantCode(t, "REFERENCE_UNSUPPORTED", tc.args...)
			// condition 2 of C547: the fix in one line
			if e.Hint != "save the secret as a credential with `komando secret set NAME`, then use credential:NAME" {
				t.Fatalf("hint %q is not the one-line fix", e.Hint)
			}
		})
	}
	if err := checkPassphraseRef("env:KEY_PASS"); err == nil || !strings.Contains(err.Error(), "outside store") {
		t.Fatalf("--passphrase-ref env:KEY_PASS: %v", err)
	}
}

// The forms ask for a saved secret where a command stores a reference to
// a credential: an outside store is not offered and not taken.
func TestFormsTakeSavedSecretOnly(t *testing.T) {
	invHome(t)
	for _, v := range []string{"env:PW", "op://ops/db/password", "file:/tmp/pw", "secret:db-pw"} {
		if cacheSecretProblem(nil, nil, v) == "" {
			t.Errorf("cache and database forms take %q", v)
		}
		if vpnRefQ("ref", "pass").check(nil, nil, v) == "" {
			t.Errorf("the VPN form takes %q", v)
		}
	}
	for _, v := range []string{"credential:db-pw"} {
		if p := cacheSecretProblem(nil, nil, v); p != "" {
			t.Errorf("cache form refuses %q: %s", v, p)
		}
		if p := vpnRefQ("ref", "pass").check(nil, nil, v); p != "" {
			t.Errorf("VPN form refuses %q: %s", v, p)
		}
	}
	for _, q := range []formQ{vpnPassQ("save", true), vpnPskQ("Shared secret", "shared secret", "")} {
		for _, r := range q.choices(nil, formAnswers{}) {
			if strings.Contains(r.label+r.detail, "password manager") || strings.Contains(r.detail, "1Password") {
				t.Errorf("%s offers %q", q.key, r.label)
			}
		}
	}
	if got := vpnPassArgs(nil, formAnswers{"user": "alice", "pass": "ref", "ref": "office-pw"}); strings.Join(got, " ") != "--credential office-pw" {
		t.Errorf("vpnPassArgs: %v", got)
	}
	if got := vpnPskArgs(nil, formAnswers{"psk": "ref", "pskref": "office-psk"}); strings.Join(got, " ") != "--psk-credential office-psk" {
		t.Errorf("vpnPskArgs: %v", got)
	}
}

// A word on --credential or --psk-credential that names no saved secret
// may be the password itself (chief, 2026-11-27): the command stops with
// USAGE, and the word is in no output, warning, audit record or entry. The
// options take a saved secret's name and nothing else (chief rule R2): a
// reference form (credential:, env:, op://, the old secret:) stops the
// same way, and a saved name passes.
func TestCredentialWordNotSavedRefused(t *testing.T) {
	const word = "Hunter2x"
	with := func(args []string, v string) []string {
		a := slices.Clone(args)
		a[slices.Index(a, "CRED")] = v
		return a
	}
	for _, tc := range []struct {
		name        string
		setup, args []string // CRED in args is the word under test
		show        []string
	}{
		{"conn add", nil, []string{"queue", "kafka", "add", "q1", "kafka://10.0.0.8:9093?tls=true", "--credential", "CRED"}, []string{"queue", "kafka", "show", "q1"}},
		{"conn edit", []string{"queue", "kafka", "add", "q1", "kafka://10.0.0.8:9093?tls=true"}, []string{"queue", "kafka", "edit", "q1", "--credential", "CRED"}, []string{"queue", "kafka", "show", "q1"}},
		{"storage add", nil, []string{"storage", "s3", "add", "b1", "s3://AKIAEXAMPLE@media/db?region=eu-west-1", "--credential", "CRED"}, []string{"storage", "s3", "show", "b1"}},
		{"vpn add", nil, []string{"vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080", "--user", "u", "--credential", "CRED"}, []string{"vpn", "socks", "show", "lab"}},
		{"vpn edit", []string{"vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080"}, []string{"vpn", "socks", "edit", "lab", "--user", "u", "--credential", "CRED"}, []string{"vpn", "socks", "show", "lab"}},
		{"vpn psk", nil, []string{"vpn", "l2tp", "add", "office", "--server", "vpn.example.com", "--user", "u", "--psk-credential", "CRED"}, []string{"vpn", "l2tp", "show", "office"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invHome(t)
			noAgent(t)
			setSecret(t, "ok-pass", "Saved-Value-9")
			if tc.setup != nil {
				mustRun(t, tc.setup...)
			}
			var stderr bytes.Buffer
			saved := tcl.out.Err
			tcl.out.Err = &stderr
			t.Cleanup(func() { tcl.out.Err = saved })
			for _, v := range []string{word, "Hunter:2x", "credential:ok-pass", "secret:ok-pass", "env:WEB_PW", "op://ops/db/password", ""} {
				e := wantCode(t, "USAGE", with(tc.args, v)...)
				if !strings.Contains(e.Message, "takes the name of a saved secret") {
					t.Fatalf("%q: refused for another reason: %s", v, e.Message)
				}
				if seen := fmt.Sprintf("%+v %s", *e, stderr.String()); v != "" && strings.Contains(seen, v) || strings.Contains(seen, "Hunter") {
					t.Errorf("%s is repeated: %s", v, seen)
				}
			}
			if strings.Contains(auditText(t), "Hunter") {
				t.Errorf("the word is in the audit log")
			}
			if d, _ := invRun(t, tc.show...); strings.Contains(fmtAny(d), "Hunter") {
				t.Errorf("the word is in the entry: %v", d)
			}
			d := mustRun(t, with(tc.args, "ok-pass")...)
			if strings.Contains(fmtAny(d), "Saved-Value-9") || strings.Contains(fmtAny(d["warnings"]), "vault") {
				t.Errorf("a saved name: %v", d)
			}
		})
	}
	if w := missingSecretWarnings("credential:" + word); len(w) != 1 || strings.Contains(w[0], word) {
		t.Errorf("the warning for a missing secret: %q", w)
	}
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.5", "--password-ref", "credential:"+word)
	if d, _ := invRun(t, "doctor"); !strings.Contains(fmtAny(d), "not in the vault") || strings.Contains(fmtAny(d), word) {
		t.Errorf("doctor on a missing secret: %v", d)
	}
}

// Chief rule R2 names four credential options. Each one in the table is a
// name that credentialRef checks before the body runs, so no option can
// reach a body with a typed password.
func TestEveryCredentialOptionIsASavedName(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range capability.All() {
		for _, o := range l.Options {
			if o.Kind != capability.Credential {
				continue
			}
			seen[o.Name] = true
			if _, ok := credentialFlags[o.Name]; !ok {
				t.Errorf("%s --%s does not go through credentialRef", l.Key, o.Name)
			}
		}
	}
	for _, name := range []string{"credential", "sudo-credential", "psk-credential", "passphrase-credential"} {
		if !seen[name] {
			t.Errorf("no leaf of the table has --%s", name)
		}
	}
	for _, verb := range []string{"add", "edit"} {
		l, _ := capability.Find(capability.Key{Type: "credential", Area: "key", Verb: verb})
		if !slices.ContainsFunc(l.Options, func(o capability.Option) bool { return o.Name == "passphrase-credential" }) {
			t.Errorf("credential key %s has no --passphrase-credential", verb)
		}
	}
}

// A vault komando cannot read proves no name: the value is refused (fail
// closed) and not repeated.
func TestCredentialRefRefusesWhenTheVaultCannotBeRead(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.WriteFile(home, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setHome(t, home)
	ref, err := credentialRef("credential", "Hunter2x")
	if err == nil {
		t.Fatalf("passed as %q", ref)
	}
	if strings.Contains(fmt.Sprintf("%+v", err), "Hunter2x") {
		t.Errorf("the value is repeated: %+v", err)
	}
}

// Host and credential key still take today's reference flags until the
// cut moves them: a typed password stops with USAGE and is repeated
// nowhere.
func TestTypedPasswordOnHostAndKeyRefused(t *testing.T) {
	const word = "Hunter2x"
	invHome(t)
	noAgent(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.5")
	mustRun(t, "key", "gen", "k")
	var stderr bytes.Buffer
	saved := tcl.out.Err
	tcl.out.Err = &stderr
	t.Cleanup(func() { tcl.out.Err = saved })
	for _, args := range [][]string{
		{"host", "add", "web2", "u@10.0.0.6", "--password-ref", word},
		{"host", "add", "web2", "u@10.0.0.6", "--sudo-ref", word},
		{"host", "edit", "web1", "--password-ref", word},
		{"host", "edit", "web1", "--sudo-ref", word},
		{"key", "edit", "k", "--passphrase-ref", word},
	} {
		e := wantCode(t, "USAGE", args...)
		if seen := fmt.Sprintf("%+v %s", *e, stderr.String()); strings.Contains(seen, word) {
			t.Errorf("%v: the word is repeated: %s", args, seen)
		}
	}
	if strings.Contains(auditText(t), word) {
		t.Errorf("the word is in the audit log")
	}
	for _, show := range [][]string{{"host", "show", "web1"}, {"key", "show", "k"}} {
		if d := mustRun(t, show...); strings.Contains(fmtAny(d), word) {
			t.Errorf("the word is in the entry: %v", d)
		}
	}
}
