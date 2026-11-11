package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// usageFor runs komando the way Execute does and returns the usage error
// people see: one line, a suggestion, and a hint for the command meant.
func usageFor(t *testing.T, args ...string) *out.Error {
	t.Helper()
	root := newRoot()
	root.SetArgs(args)
	root.SetOut(&bytes.Buffer{})
	cmd, err := root.ExecuteC()
	if err == nil {
		t.Fatalf("%v: want an error", args)
	}
	if isUsageErr(err) {
		err = usageErr(cmd, err)
	}
	var e *out.Error
	if !errors.As(err, &e) {
		t.Fatalf("%v: %v", args, err)
	}
	return e
}

func TestTypoSuggestions(t *testing.T) {
	e := usageFor(t, "exce", "web1")
	if e.Message != `unknown command "exce"; did you mean exec?` || e.Hint != "see `komando exec --help`" {
		t.Errorf("command typo: %q / %q", e.Message, e.Hint)
	}
	if strings.Contains(e.Message, "\n") {
		t.Errorf("one line: %q", e.Message)
	}
	// add alone points at the add commands, which ask step by step; the
	// first-run menu has no Add something row to send a person to
	if e := usageFor(t, "add"); strings.Contains(e.Message, "did you mean") || !strings.Contains(e.Hint, "komando host add") ||
		!strings.Contains(e.Hint, "step by step") || strings.Contains(e.Hint, "Add something") || e.Code != "USAGE" {
		t.Errorf("add: %q / %q", e.Message, e.Hint)
	}
	if e := usageFor(t, "zzzz"); strings.Contains(e.Message, "did you mean") {
		t.Errorf("no suggestion for nonsense: %q", e.Message)
	}
	if e := usageFor(t, "exec", "--tiemout", "3s", "web1", "--", "uptime"); !strings.HasSuffix(e.Message, "did you mean --timeout?") {
		t.Errorf("flag typo: %q", e.Message)
	}
	if e := usageFor(t, "exec", "--xyzabc", "web1"); strings.Contains(e.Message, "did you mean") {
		t.Errorf("no suggestion for nonsense flag: %q", e.Message)
	}
}

func TestFirstSteps(t *testing.T) {
	root := newRoot()
	root.SetArgs([]string{"-o", "text"})
	var buf bytes.Buffer
	root.SetOut(&buf)
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "\n"); n > 15 || !strings.Contains(buf.String(), "First steps") {
		t.Errorf("komando alone: the first steps in a few lines, got %d lines:\n%s", n, buf.String())
	}
}

func TestCountWords(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{countOf(1, "server"), "1 server"},
		{countOf(0, "server"), "0 servers"},
		{countOf(3, "server"), "3 servers"},
		{failedOf(1, 3), "1 of 3 failed"},
		{failedOf(2, 2), "both failed"},
		{failedOf(5, 5), "all 5 failed"},
		{failedOf(1, 1), "1 of 1 failed"},
	} {
		if c.got != c.want {
			t.Errorf("%q, want %q", c.got, c.want)
		}
	}
}
