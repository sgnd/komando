package cli

import "testing"

// Row C624: outside secret stores come after v0.18.0 as `credential store`
// (C332). Until then the noun and its options are refused with one
// message, never taken as a typo of something else.
func TestCredentialStoreNotInThisVersion(t *testing.T) {
	const says = "outside stores are not in this version; they come as credential store"
	for _, args := range [][]string{
		{"credential", "store"},
		{"credential", "store", "vault", "add", "corp"},
		{"credential", "password", "add", "db-pass", "--store", "vault"},
		{"credential", "password", "add", "db-pass", "--item=secret/db"},
		{"credential", "token", "add", "gh-token", "--store", "onepassword", "--item", "gh"},
	} {
		e := usageFor(t, args...)
		if e.Code != "USAGE" || e.Message != says {
			t.Errorf("%v: %s %q", args, e.Code, e.Message)
		}
		if e.Hint != "save the value in komando: `komando credential password add NAME`" {
			t.Errorf("%v: hint %q", args, e.Hint)
		}
	}
	// another unknown word or flag keeps its own message
	if e := usageFor(t, "credential", "stor"); e.Message == says {
		t.Errorf("a typo was told about outside stores: %q", e.Message)
	}
	if e := usageFor(t, "host", "ssh", "list", "--store", "x"); e.Message == says {
		t.Errorf("--store outside credential was told about outside stores: %q", e.Message)
	}
}
