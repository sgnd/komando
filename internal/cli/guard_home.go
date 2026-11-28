package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/spf13/cobra"
)

// An AI agent's komando keeps the person's data folder, ~/.komando
// (docs/features/safety.md). KOMANDO_HOME moves it: pointed at a new,
// empty folder, komando would know none of the person's protected servers,
// deny rules or pinned host keys, and would write its audit log there,
// while SSH still logs in with the person's ssh-agent and keys. So for an
// agent a KOMANDO_HOME that is another folder stops every command, a dry
// run too, and no flag or window lets it through (homeStop). A person who
// keeps komando's data elsewhere can make ~/.komando a link to it: a link
// to the same folder counts as ~/.komando. HOME does not move it for an agent: komando takes
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
// any folder: version and the playbooks.
var homeFree = map[string]bool{"komando": true, "completion": true, "version": true, "schema": true, "guide": true}

// homeFreeOne are single commands of a noun that is not free as a whole:
// the playbook install reads no data; agent skill uninstall takes the agent
// guard out, and the rest of the agent noun (agent mcp) is no playbook.
var homeFreeOne = map[string]bool{"agent.skill.install": true}

// homeFreeCommand says whether the command with this ID runs in any folder.
func homeFreeCommand(name string) bool {
	top, _, _ := strings.Cut(name, ".")
	return homeFree[top] || homeFreeOne[name]
}

// guardHome stops an AI agent's command that would use another data folder
// than ~/.komando. The stop is final (homeStop). Only the commands that
// read no data go on (homeFree); hidden background commands are checked
// like any other.
func guardHome(cmd *cobra.Command) error {
	cl := callOf(cmd)
	if !cl.isAgent() || homeFreeCommand(commandName(cmd)) {
		return nil
	}
	// first: with no account in the user database either, a KOMANDO_HOME
	// that is not ~/.komando of $HOME is still another folder
	if h := otherHome(cl); h != "" {
		return homeStop(cl, "KOMANDO_HOME points komando at "+h+", not at "+defaultHome()+
			": its servers, protection, deny rules, host keys and audit log are not the usual ones, so an AI agent cannot use it",
			"take KOMANDO_HOME out of the command's environment and run it again: komando then uses the user's own data folder. No flag lets an AI agent use another one")
	}
	if _, err := store.AccountHome(); err != nil {
		what := "HOME=" + cl.getenv("HOME") + ": komando's data from " + store.Home() + ", unchecked"
		msg := "komando cannot find this account's home folder in the user database (" + err.Error() +
			"), so it cannot tell whether HOME was moved to another folder: an AI agent needs a person's yes to use " + store.Home()
		if cl.dryRun() {
			// a dry run opens no window, and reads servers all the same
			return homeStop(cl, msg, "a dry run cannot ask the user: run it without --dry-run and with --yes (komando then asks them in a window on their screen), or ask them to run it in their own terminal")
		}
		return agentYes(cl, "SAFETY_SETTING", msg,
			what, "if HOME was moved, that folder's servers, protection, deny rules, pinned host keys and audit log are not the usual ones")
	}
	// KOMANDO_HOME that names the usual folder another way (a link, other
	// case) is replaced by the folder's own path, for this komando and the
	// ones it starts: a link repointed after this check must not move the
	// data. Only the process's own variable is replaced, never one that a
	// call brought along for itself (RunCall).
	if k := cl.getenv("KOMANDO_HOME"); k != "" && k == os.Getenv("KOMANDO_HOME") && filepath.Clean(k) != filepath.Clean(defaultHome()) {
		if err := os.Setenv("KOMANDO_HOME", defaultHome()); err != nil {
			return homeStop(cl, "komando cannot keep its data folder at "+defaultHome()+": "+err.Error(), "ask the user to run it in their own terminal")
		}
	}
	return nil
}

// homeStop refuses an AI agent's command in another data folder. It is
// final: no flag and no window lets it through, and a dry run stops too.
// The approval code a person switched on is kept in the usual folder, not
// in the one KOMANDO_HOME names, so a window here would be a plain click;
// and a dry run in a folder without the person's pinned host keys,
// protection and deny rules still connects, and previews nothing real.
// The stop is not written to an audit log: the only one at hand is the
// other folder's, and komando makes nothing there.
func homeStop(cl *call, msg, hint string) error {
	cl.blockAudited = true
	return out.Errf(out.ExitPolicy, "NEEDS_PERSON", hint, "%s", msg).NoFlag()
}
