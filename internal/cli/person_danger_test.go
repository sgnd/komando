package cli

import (
	"os"
	"testing"
)

// personTypes runs the rest of a test as a person at the terminal who types
// answer at the first question (stderr is kept out of the test's output).
func personTypes(t *testing.T, answer string) {
	t.Helper()
	noAgent(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(answer + "\n")
	w.Close()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	savedIn, savedErr, savedInteractive := os.Stdin, os.Stderr, interactive
	os.Stdin, os.Stderr, interactive = r, devnull, func() bool { return true }
	t.Cleanup(func() {
		os.Stdin, os.Stderr, interactive = savedIn, savedErr, savedInteractive
		r.Close()
		devnull.Close()
		personSaidNo = false
	})
}

// A dangerous command a person runs at the terminal asks them to type the
// target's name, as exec and db query do, instead of sending them back to
// add --allow-dangerous. A wrong name stops it.
func TestDangerousAsksAPerson(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"fs rm --recursive", []string{"fs", "rm", "web1", "/srv/app/old", "-r"}},
		{"fs rm of a top-level path", []string{"fs", "rm", "web1", "/srv"}},
		{"pkg rm of an essential package", []string{"pkg", "rm", "web1", "openssh-server"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invHome(t)
			mustRun(t, "host", "add", "web1", "u@127.0.0.1:1") // nothing listens: the command fails after the question
			personTypes(t, "nope")
			_, e := invRun(t, tc.args...)
			if e == nil || e.Code != "POLICY_BLOCKED" || !personSaidNo {
				t.Fatalf("a wrong name stops it: %+v", e)
			}
			personTypes(t, "web1")
			if _, e = invRun(t, tc.args...); e == nil || e.Code == "POLICY_BLOCKED" {
				t.Fatalf("the typed name lets it through to the server: %+v", e)
			}
		})
	}
}
