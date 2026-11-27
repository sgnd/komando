package gatehere

import (
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/testhome"
)

// No test of this package sees the real home folder (internal/testhome).
func TestMain(m *testing.M) {
	homeDone := testhome.Use()
	code := m.Run()
	homeDone()
	os.Exit(code)
}

// TestRunsOnlyTheTypedCommands pins rule d: in server mode exec and every
// other shell is refused, and only readings and the typed service,
// package and file-read commands run. Mutant: Runs answering true for an
// unknown key, or dropping host exec from shells, turns a line red.
func TestRunsOnlyTheTypedCommands(t *testing.T) {
	for _, k := range [][3]string{
		{"host", "", "info"}, {"host", "", "logs"},
		{"host", "file", "cat"}, {"host", "file", "list"}, {"host", "file", "stat"},
		{"host", "service", "list"}, {"host", "service", "status"}, {"host", "service", "logs"}, {"host", "service", "restart"},
		{"host", "package", "installed"}, {"host", "package", "upgradable"}, {"host", "package", "install"},
		{"ssh-gate", "", "status"}, {"", "", "version"},
	} {
		if ok, why := Runs(k[0], k[1], k[2]); !ok {
			t.Errorf("%v: refused (%s), want it to run in server mode", k, why)
		}
	}
	for k, word := range map[[3]string]string{
		{"host", "", "exec"}:          "shell",
		{"host", "job", "start"}:      "shell",
		{"host", "docker", "exec"}:    "shell",
		{"host", "docker", "raw"}:     "shell",
		{"snippet", "", "exec"}:       "shell",
		{"host", "", "shell"}:         "shell",
		{"host", "file", "write"}:     "only",
		{"host", "file", "mv"}:        "only",
		{"host", "file", "chmod"}:     "only",
		{"", "upload", "copy"}:        "only",
		{"", "cp", "copy"}:            "only",
		{"", "download", "copy"}:      "only",
		{"host", "user", "add"}:       "only",
		{"host", "cron", "set"}:       "only",
		{"credential", "key", "list"}: "only",
		{"database", "", "query"}:     "only",
		{"", "", "list"}:              "only",
		{"made", "up", "later"}:       "only", // a command added later is refused until someone decides
	} {
		ok, why := Runs(k[0], k[1], k[2])
		if ok || !strings.Contains(why, word) {
			t.Errorf("%v: %v %q, want it refused with %q", k, ok, why, word)
		}
	}
}

// TestTargetIsThisServer pins the target rule: in server mode the only
// target is this server, written localhost. Mutant: Target accepting any
// word turns it red.
func TestTargetIsThisServer(t *testing.T) {
	if why := Target(ThisServer); why != "" {
		t.Errorf("%s: %s", ThisServer, why)
	}
	for _, w := range []string{"web1", "@web", "all", "u@localhost", "127.0.0.1", "localhost:22", "LOCALHOST", ""} {
		if Target(w) == "" {
			t.Errorf("%q: accepted as this server", w)
		}
	}
}
