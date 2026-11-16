package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/store"
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
// counts as ~/.komando. HOME does not move it for an agent: komando takes
// an agent's home folder from the system's user database (store.UserHome),
// so HOME=/x with KOMANDO_HOME=/x/.komando is another folder too.

// defaultHome is ~/.komando, where komando keeps an agent's data without
// KOMANDO_HOME, in the account's home folder from the user database
// (tests, which keep theirs in a fresh folder each, replace it).
var defaultHome = func() string {
	d, err := accountHome()
	if err != nil {
		return ".komando"
	}
	return filepath.Join(d, ".komando")
}

// accountHome is the account's home folder from the system's user
// database, else $HOME when the database has no entry for it.
func accountHome() (string, error) {
	if d, err := store.AccountHome(); err == nil {
		return d, nil
	}
	return os.UserHomeDir()
}

// guardHomes are the home folders the agent guard protects: $HOME, and
// the account's home from the user database when that is another folder.
// An agent's HOME=/tmp/x moves the one, never the other, and komando
// keeps an agent's data in the account's (store.UserHome).
func guardHomes() []string {
	var homes []string
	if d, err := os.UserHomeDir(); err == nil && d != "" {
		homes = append(homes, d)
	}
	if d, err := store.AccountHome(); err == nil && !slices.ContainsFunc(homes, func(h string) bool { return sameDir(h, d) }) {
		homes = append(homes, d)
	}
	return homes
}

// otherHome is $KOMANDO_HOME when it names another folder than the
// account's ~/.komando, or "". $HOME has no say: an agent sets it.
func otherHome(cl *call) string {
	h := cl.getenv("KOMANDO_HOME")
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
// than ~/.komando, unless a person allows it. The background commands
// (vpn serve, tunnel serve, login-holder) too: in a home of its own an
// agent holds the store key their tickets are made with. The agent guard
// (guide guard), which the agent's tool runs before every call, goes on.
func guardHome(cmd *cobra.Command) error {
	cl := callOf(cmd)
	top, _, _ := strings.Cut(commandName(cmd), ".")
	if !cl.isAgent() || homeFree[top] {
		return nil
	}
	if _, err := store.AccountHome(); err != nil {
		what := "HOME=" + cl.getenv("HOME") + ": komando's data from " + store.Home() + ", unchecked"
		return agentYes(cl, "SAFETY_SETTING", "komando cannot find this account's home folder in the user database ("+err.Error()+
			"), so it cannot tell whether HOME was moved to another folder: an AI agent needs a person's yes to use "+store.Home(),
			what, "if HOME was moved, that folder's servers, protection, deny rules, pinned host keys and audit log are not the usual ones")
	}
	h := otherHome(cl)
	if h == "" {
		return nil
	}
	what := "KOMANDO_HOME=" + h + ": komando's data from this folder, not from " + defaultHome()
	return agentYes(cl, "SAFETY_SETTING", "KOMANDO_HOME points komando at "+h+", not at "+defaultHome()+
		": its servers, protection, deny rules, host keys and audit log are not the usual ones, so an AI agent needs a person's yes to use it",
		what, "that folder's servers, protection, deny rules, pinned host keys and audit log are not the usual ones")
}
