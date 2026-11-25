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
			e := wantCode(t, "BAD_REFERENCE", tc.args...)
			if !strings.Contains(e.Hint, "credential:web1-pass") {
				t.Fatalf("hint %q does not name credential:web1-pass", e.Hint)
			}
			if d := mustRun(t, "host", "list"); strings.Contains(strings.ToLower(jsonOf(d)), "web1") {
				t.Fatalf("the host was saved: %s", jsonOf(d))
			}
		})
	}
}
