package cli

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
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
