package cli

import (
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
		{"vpn psk", []string{"vpn", "add", "web1-vpn", "l2tp", "--server", "vpn.example.com", "--psk-ref", "vault:kv/vpn#psk", "--user", "alice", "--dry-run"}},
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
	if got := vpnPassArgs(nil, formAnswers{"user": "alice", "pass": "ref", "ref": "office-pw"}); strings.Join(got, " ") != "--password-ref credential:office-pw" {
		t.Errorf("vpnPassArgs: %v", got)
	}
	if got := vpnPskArgs(nil, formAnswers{"psk": "ref", "pskref": "office-psk"}); strings.Join(got, " ") != "--psk-ref credential:office-psk" {
		t.Errorf("vpnPskArgs: %v", got)
	}
}
