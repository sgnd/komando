package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// Row C488 (step D): a hint written where the entry is not known names
// `komando TYPE PROVIDER VERB NAME`; fillHint fills the type and provider
// from a saved entry, and only in a command of that entry's own type.
func TestFillHintTypeAndProvider(t *testing.T) {
	invHome(t)
	mustRun(t, "database", "postgres", "add", "pg", "postgres://u@127.0.0.1:5/db")
	mustRun(t, "host", "ssh", "add", "web1", "u@192.0.2.10")
	for _, tc := range []struct{ target, hint, want string }{
		{"pg", "check it with `komando database PROVIDER show NAME`",
			"check it with `komando database postgres show pg`"},
		{"pg", "`komando TYPE PROVIDER edit NAME --url URL`",
			"`komando database postgres edit pg --url URL`"},
		{"pg", "`komando TYPE PROVIDER show NAME`; `komando test NAME`",
			"`komando database postgres show pg`; `komando test pg`"},
		// another type's command keeps its words: pg is no cache
		{"pg", "`komando cache PROVIDER show NAME`", "`komando cache PROVIDER show NAME`"},
		// a server or an unknown name fills nothing of an entry's path
		{"web1", "`komando TYPE PROVIDER show NAME`", "`komando TYPE PROVIDER show NAME`"},
		{"nosuch", "`komando database PROVIDER show NAME`", "`komando database PROVIDER show NAME`"},
		// PROVIDER outside a command is prose
		{"pg", "the PROVIDER word is the provider", "the PROVIDER word is the provider"},
	} {
		e := out.Errf(out.ExitUsage, "X", tc.hint, "x")
		fillHint(e, tc.target)
		if e.Hint != tc.want {
			t.Errorf("fillHint(%q, %q) = %q, want %q", tc.hint, tc.target, e.Hint, tc.want)
		}
	}
}

// G10: the selector takes the type word (kind:database) as it takes the
// family word (kind:db); kind:conn, the old noun, is gone.
func TestKindSelectorTakesTheTypeWord(t *testing.T) {
	invHome(t)
	mustRun(t, "database", "postgres", "add", "pg", "postgres://u@127.0.0.1:5/db")
	mustRun(t, "cache", "redis", "add", "r1", "redis://127.0.0.1:6379/0")
	mustRun(t, "registry", "oci", "add", "o1", "registry://ghcr.io")
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	for sel, want := range map[string]string{
		"kind:database": "pg", "kind:db": "pg", "kind:cache": "r1",
		"kind:registry": "o1",
	} {
		got, err := resolveSelection(tcl, st, sel)
		if err != nil || len(got.Conns) != 1 || got.Conns[0].Name != want || len(got.Hosts)+len(got.Vpns) != 0 {
			t.Errorf("%s picked %v, %v; want %s", sel, got.Conns, err, want)
		}
	}
	_, err = resolveSelection(tcl, st, "kind:conn")
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "USAGE" {
		t.Fatalf("kind:conn: want USAGE, got %v", err)
	}
	if msg := e.Error() + " " + e.Hint; strings.Contains(msg, "komando conn") || !strings.Contains(msg, "database") {
		t.Errorf("kind:conn: the message names the old noun or not the types: %q", msg)
	}
}
