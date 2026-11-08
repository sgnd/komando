package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// An AI agent's komando keeps the person's data folder, ~/.komando
// (docs/features/safety.md). KOMANDO_HOME moves it: pointed at a new,
// empty folder, komando would know none of the person's protected servers,
// deny rules or pinned host keys, and would write its audit log there,
// while SSH still logs in with the person's ssh-agent and keys. So for an
// agent a KOMANDO_HOME that is another folder needs a person's yes (--yes,
// then the window), on every command. A person who keeps komando's data
// elsewhere can make ~/.komando a link to it: a link to the same folder
// counts as ~/.komando.

// defaultHome is ~/.komando, where komando keeps its data without
// KOMANDO_HOME (tests, which keep theirs in a fresh folder each, replace it).
var defaultHome = func() string {
	d, err := os.UserHomeDir()
	if err != nil {
		return ".komando"
	}
	return filepath.Join(d, ".komando")
}

// otherHome is $KOMANDO_HOME when it names another folder than
// ~/.komando, or "".
func otherHome() string {
	h := os.Getenv("KOMANDO_HOME")
	if h == "" || sameDir(h, defaultHome()) {
		return ""
	}
	return h
}

// sameDir reports whether a and b are one folder: the same path, or, when
// both exist, the same folder through a link (or other upper and lower
// case on macOS).
func sameDir(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

// homeFree are the commands that never read komando's data, so they run in
// any folder: help, version and the playbooks.
var homeFree = map[string]bool{"komando": true, "help": true, "completion": true, "version": true, "schema": true, "guide": true}

// guardHome stops an AI agent's command that would use another data folder
// than ~/.komando, unless a person allows it. Hidden commands go on: the
// background processes a checked command starts (tunnel serve, vpn serve)
// and the agent guard, which the agent's tool runs before every call.
func guardHome(cmd *cobra.Command) error {
	top, _, _ := strings.Cut(commandName(cmd), ".")
	if !isAgent() || cmd.Hidden || homeFree[top] {
		return nil
	}
	h := otherHome()
	if h == "" {
		return nil
	}
	what := "KOMANDO_HOME=" + h + ": komando's data from this folder, not from " + defaultHome()
	return agentYes("SAFETY_SETTING", "KOMANDO_HOME points komando at "+h+", not at "+defaultHome()+
		": its servers, protection, deny rules, host keys and audit log are not the usual ones, so an AI agent needs a person's yes to use it",
		what, "that folder's servers, protection, deny rules, pinned host keys and audit log are not the usual ones")
}
