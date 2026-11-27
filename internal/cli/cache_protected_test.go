package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// guardCode is the code of a stop of the safety checks (the danger stop or
// the protected stop), or "" when e is nil or any other error: a command
// that got past both stops fails later with its own code (no server here).
func guardCode(e *out.Error) string {
	if e != nil && (e.Code == "POLICY_BLOCKED" || e.Code == "PROTECTED_TARGET") {
		return e.Code
	}
	return ""
}

// C363 (issue 490): a change on a protected cache conn needs --yes through
// GuardConns, and a destructive one needs --allow-dangerous as well, one
// stop after the other. This pins the stops of `cache P raw` for every
// provider before the typed-name confirm of cluster rm goes (cut step D4).
func TestProtectedCacheRawNeedsYes(t *testing.T) {
	for _, c := range []struct {
		provider, url      string
		write, destructive []string // the words after --
	}{
		{"redis", "redis://127.0.0.1:1/0", []string{"SET", "k", "v"}, []string{"FLUSHALL"}},
		{"memcached", "", []string{"set", "k", "0", "0", "1"}, []string{"flush_all"}},
	} {
		t.Run(c.provider, func(t *testing.T) {
			invHome(t)
			noAgent(t)
			url := c.url
			if c.provider == "memcached" {
				addr, _ := fakeMemcached(t)
				url = "memcached://" + addr
			}
			mustRun(t, "conn", "add", "pc", url, "--protected")
			raw := func(flags []string, words []string) *out.Error {
				args := append([]string{"cache", c.provider, "raw", "pc"}, flags...)
				_, e := cliRun(t, append(append(args, "--"), words...)...)
				return e
			}
			// a change: --write is not enough on a protected conn
			if got := guardCode(raw([]string{"--write"}, c.write)); got != "PROTECTED_TARGET" {
				t.Errorf("%s change without --yes: stop %q, want PROTECTED_TARGET", c.provider, got)
			}
			if got := guardCode(raw([]string{"--write", "--yes"}, c.write)); got != "" {
				t.Errorf("%s change with --yes was stopped: %q", c.provider, got)
			}
			// the same change on a conn that is not protected is not stopped
			mustRun(t, "conn", "edit", "pc", "--protected=false")
			if got := guardCode(raw([]string{"--write"}, c.write)); got != "" {
				t.Errorf("%s change on an unprotected conn was stopped: %q", c.provider, got)
			}
			mustRun(t, "conn", "edit", "pc", "--protected")
			// a destructive change: the danger stop first, then the protected stop
			for _, s := range []struct {
				flags []string
				want  string
			}{
				{[]string{"--write"}, "POLICY_BLOCKED"},
				{[]string{"--write", "--allow-dangerous"}, "PROTECTED_TARGET"},
				{[]string{"--write", "--yes"}, "POLICY_BLOCKED"},
				{[]string{"--write", "--allow-dangerous", "--yes"}, ""},
			} {
				if got := guardCode(raw(s.flags, c.destructive)); got != s.want {
					t.Errorf("%s %v %v: stop %q, want %q", c.provider, c.destructive, s.flags, got, s.want)
				}
			}
		})
	}
}
