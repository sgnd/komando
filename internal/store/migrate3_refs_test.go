package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestParseRef(t *testing.T) {
	tests := []struct{ name, in, provider, item string }{
		{"komando secret", "secret:db-pass", "secret", "db-pass"},
		{"environment", "env:PGPASSWORD", "env", "PGPASSWORD"},
		{"file", "file:/etc/pw", "file", "/etc/pw"},
		{"1Password", "op://vault/item/field", "onepassword", "vault/item/field"},
		{"Bitwarden", "bw://item/field", "bitwarden", "item/field"},
		{"KeePass", "kdbx:/k.kdbx#g/e", "keepass", "/k.kdbx#g/e"},
		{"HashiCorp Vault", "vault:kv/app#pw", "vault", "kv/app#pw"},
		{"AWS", "aws-sm:prod/db#password", "aws-sm", "prod/db#password"},
		{"Google", "gcp-sm:db@proj", "gcp-sm", "db@proj"},
		{"Azure", "azure-kv:kv/db", "azure-kv", "kv/db"},
		{"empty", "", "", ""},
		{"plain text", "hunter2", "", ""},
		{"a prefix alone", "secret:", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, item := parseRef(tt.in)
			if p != tt.provider || item != tt.item {
				t.Errorf("parseRef(%q) = %q, %q; want %q, %q", tt.in, p, item, tt.provider, tt.item)
			}
		})
	}
}

func TestMapURLRefs(t *testing.T) {
	in := "redis://default@10.0.0.7:6379/0?ca=secret:redis-ca&tls=on&creds=secret%3Anats#frag"
	var seen []string
	got := mapURLRefs(in, func(opt, ref string) string {
		seen = append(seen, opt+"="+ref)
		if name, ok := strings.CutPrefix(ref, "secret:"); ok {
			return "credential:" + name
		}
		return ref
	})
	want := "redis://default@10.0.0.7:6379/0?ca=credential:redis-ca&tls=on&creds=credential:nats#frag"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if strings.Join(seen, " ") != "ca=secret:redis-ca tls=on creds=secret:nats" {
		t.Errorf("seen %v", seen)
	}
	if u := mapURLRefs("s3://bucket", func(_, r string) string { return "x" }); u != "s3://bucket" {
		t.Errorf("no query: %s", u)
	}
}

func TestURLUser(t *testing.T) {
	tests := []struct{ name, in, user, rest string }{
		{"user", "postgres://app@10.0.0.5:5432/app?sslmode=require", "app", "postgres://10.0.0.5:5432/app?sslmode=require"},
		{"escaped user", "postgres://a%40b@h/db", "a@b", "postgres://h/db"},
		{"no user", "redis://10.0.0.7:6379", "", "redis://10.0.0.7:6379"},
		{"no scheme", "10.0.0.7", "", "10.0.0.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, rest := urlUser(tt.in)
			if u != tt.user || rest != tt.rest {
				t.Errorf("urlUser(%q) = %q, %q; want %q, %q", tt.in, u, rest, tt.user, tt.rest)
			}
		})
	}
}

// The F10 check looks only at fields that hold a reference, so free text
// that starts with secret: never stops a store (Audit M8).
func TestCheckOldRefs3(t *testing.T) {
	ok := []record3{
		{typ: KindRecipe, name: "r", data: &Snippet{Name: "r", Command: "secret:abc", Description: "secret:x"}},
		{typ: KindHost, name: "web1", data: &HostV3{Name: "web1", Labels: map[string]string{"k": "secret:x"}, Notes: "secret:y", ProxyCommand: "secret:z"}},
		{typ: KindHost, name: "web2", data: &HostV3{Name: "web2", Env: map[string]string{"A": "credential:x", "B": "secret: not a ref"}}},
	}
	if err := checkOldRefs3(ok); err != nil {
		t.Fatalf("free text stopped the store: %v", err)
	}
	bad := []struct {
		name  string
		rec   record3
		field string
	}{
		{"sudo credential", record3{typ: KindHost, name: "web1", data: &HostV3{Name: "web1", SudoCredential: "secret:x"}}, "sudo_credential"},
		{"env value", record3{typ: KindHost, name: "web1", data: &HostV3{Name: "web1", Env: map[string]string{"PG": "secret:pg-pass"}}}, "env PG"},
		{"winrm ca", record3{typ: KindHost, name: "w", data: &HostV3{Name: "w", WinRMOpts: &WinRMOpts{CA: "secret:ca"}}}, "winrm.ca"},
		{"url option", record3{typ: KindConn, name: "c", data: &ServiceV3{Name: "c", URL: "redis://h?ca=secret:c1"}}, "url ca"},
		{"option value", record3{typ: KindConn, name: "c", data: &ServiceV3{Name: "c", Options: map[string]string{"o": "secret:o1"}}}, "option o"},
		{"vpn psk", record3{typ: KindVpn, name: "v", data: &VpnV3{Name: "v", PSKCredential: "secret:psk"}}, "psk_credential"},
		{"key passphrase", record3{typ: KindCredential, name: "k", data: &Credential{Name: "k", Kind: CredKey, Key: &CredentialKey{Passphrase: "secret:pp"}}}, "key.passphrase"},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			err := checkOldRefs3([]record3{tt.rec})
			var e *out.Error
			if !errors.As(err, &e) || e.Code != "STORE_REFERENCE_UNSUPPORTED" || e.Exit != out.ExitUsage {
				t.Fatalf("want STORE_REFERENCE_UNSUPPORTED (exit 2), got %v", err)
			}
			if !strings.Contains(e.Message, tt.rec.name) || !strings.Contains(e.Message, tt.field) {
				t.Errorf("the error names no entry or field: %s", e.Message)
			}
			if strings.Contains(e.Message, "secret:") {
				t.Errorf("the error shows the value: %s", e.Message)
			}
		})
	}
}

func TestURLPassword(t *testing.T) {
	tests := []struct {
		name, in string
		has, bad bool
	}{
		{"a password", "postgres://app:pw@10.0.0.5/db", true, false},
		{"an empty password", "postgres://app:@10.0.0.5/db", true, false},
		{"a user only", "postgres://app@10.0.0.5/db", false, false},
		{"no user", "redis://10.0.0.7:6379", false, false},
		{"no scheme", "10.0.0.7", false, false},
		{"an escape that does not parse", "postgres://app@10.0.0.5/%zz", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, err := urlPassword(tt.in)
			if has != tt.has || (err != nil) != tt.bad {
				t.Errorf("urlPassword(%q) = %v, %v; want %v, error %v", tt.in, has, err, tt.has, tt.bad)
			}
		})
	}
}

// Condition 1 of C547: a format-2 store with a login that names an outside
// store (a host on vault: and on env:, a conn on bw://, a sudo password, a
// VPN shared key and a key passphrase) does not move. The move stops before
// it changes the store (store.db byte for byte, still format 2), names each
// entry by kind, name and field with the fix and never the reference, and
// `komando doctor --dry-run` (PreviewMigration) lists the same entries in
// the same words, by kind and field.
func TestMigrate3StopsOnOutsideLogin(t *testing.T) {
	format2Store(t)
	format2Edit(t, func(s *State) {
		s.Hosts["hv"] = &Host{Name: "hv", Address: "10.0.2.1", User: "root", PasswordRef: "vault:kv/hv#pw"}
		s.Hosts["he"] = &Host{Name: "he", Address: "10.0.2.2", User: "root", PasswordRef: "env:HE_PW"}
		s.Conns["cb"] = &Conn{Name: "cb", Kind: "postgres", URL: "postgres://app@10.0.2.3/app", PasswordRef: "bw://cb-item/password"}
		s.Hosts["web1"].SudoRef = "aws-sm:prod/web1-sudo"
		s.Vpns["wg"].PSKRef = "azure-kv:kv/wg-psk"
		s.Keys["deploy"].PassphraseRef = "file:/home/me/deploy-pp"
	})
	Close()
	before := fileSum(t)
	_, err := migrateFormat3(context.Background(), personOpts())
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "STORE_MIGRATION_FAILED" || e.Exit != out.ExitError {
		t.Fatalf("want STORE_MIGRATION_FAILED, got %v", err)
	}
	if after := fileSum(t); after != before {
		t.Fatal("the stopped move changed store.db")
	}
	if f := formatNow(t); f != "2" {
		t.Fatalf("format %s after the stopped move", f)
	}
	fix := "which a login no longer reads: with komando v0.17.0 save the secret as a credential with `komando secret set NAME` and point the field at secret:NAME, and the move makes it credential:NAME"
	want := []struct{ kind, name, field, provider string }{
		{"host", "he", "password_ref", "env"},
		{"host", "hv", "password_ref", "vault"},
		{"host", "web1", "sudo_ref", "aws-sm"},
		{"conn", "cb", "password_ref", "bitwarden"},
		{"vpn", "wg", "psk_ref", "azure-kv"},
		{"key", "deploy", "passphrase", "file"},
	}
	for _, w := range want {
		line := w.kind + " " + w.name + ": field " + w.field + " names an outside store (" + w.provider + "), " + fix
		if !strings.Contains(e.Message, line) {
			t.Errorf("the move does not name %s %s %s with the fix:\n%s", w.kind, w.name, w.field, e.Message)
		}
	}
	values := []string{"kv/hv#pw", "HE_PW", "cb-item", "prod/web1-sudo", "kv/wg-psk", "/home/me/deploy-pp"}
	for _, v := range values {
		if strings.Contains(e.Message+e.Hint, v) {
			t.Errorf("the move repeats the reference %q: %v", v, err)
		}
	}
	// the dry run: the same entries, the same words, kind and field only
	pv, err := PreviewMigration(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, w := range want {
		lines = append(lines, w.kind+": field "+w.field+" names an outside store ("+w.provider+"), "+fix)
	}
	got := slices.Clone(pv.WouldRefuse)
	slices.Sort(got)
	slices.Sort(lines)
	if pv.WouldMove || !slices.Equal(got, lines) {
		t.Fatalf("the dry run lists\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(lines, "\n"))
	}
	for _, r := range pv.WouldRefuse {
		for _, v := range values {
			if strings.Contains(r, v) {
				t.Errorf("the dry run repeats the reference %q: %s", v, r)
			}
		}
	}
	if after := fileSum(t); after != before {
		t.Fatal("the dry run changed store.db")
	}
}
