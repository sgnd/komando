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
// any folder: help, version and the playbooks.
var homeFree = map[string]bool{"komando": true, "help": true, "completion": true, "version": true, "schema": true, "guide": true}

// guardHome stops an AI agent's command that would use another data folder
// than ~/.komando. The stop is final (homeStop). Only the commands that
// read no data go on (homeFree); hidden background commands are checked
// like any other.
func guardHome(cmd *cobra.Command) error {
	cl := callOf(cmd)
	top, _, _ := strings.Cut(commandName(cmd), ".")
	// guide uninstall takes the agent guard out: it is no playbook
	free := homeFree[top] && commandName(cmd) != "guide.uninstall"
	if !cl.isAgent() || free {
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
		if cl.flags.dryRun {
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

// checkAgentVars stops a command that changes the variables komando knows
// an AI agent by (agentVars), or KOMANDO_HOME (homeVar): `CLAUDECODE=0
// komando ...`, `KOMANDO_HOME=/tmp/x komando ...`, `unset`, `export`,
// `read`, `env -u`, `env -i` and `exec -c` would make komando treat the
// agent as a script and skip the person's window, masking and the
// secret-file stops. So would `sudo komando`, which starts komando with a
// clean environment. A name komando cannot read (`unset $V`, `${!CLAUDE*}`)
// or a pattern (`CLAUDE*`, `CLAUDE{CODE,_CODE_ENTRYPOINT}`) that could be
// one counts as that name.
func checkAgentVars(words []string, depth int) guardDecision {
	why := varChangeDenied
	cleared := func(how string) guardDecision {
		return deny("%s clears the variables komando knows an AI agent by, which would switch off komando's safety stops for agents", how)
	}
	// the words up to the program: shell keywords, NAME=value words and
	// wrappers (sudo, env, ...) with their flags; and the arguments of the
	// shell's own commands that set or remove variables
	wrapper, pos := "", 0
	sudo, keepsEnv := "", false
	for i := 0; i < len(words); i++ {
		w := words[i]
		base := filepath.Base(w)
		switch {
		case wrapper == "" && shellKeyword[w]:
			if w == "function" {
				i++
			}
		case envAssign.MatchString(w):
			if name, ok := agentVarIn(assignName(w)); ok {
				return why(name)
			}
		case w == "unset" || w == "export" || w == "declare" || w == "typeset" || w == "local" || w == "readonly" || w == "integer" || w == "float":
			for _, a := range words[i+1:] {
				if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
					continue // -n, -x, +x, -m: the names are what count
				}
				if name, ok := agentVarIn(assignName(a)); ok {
					return why(name)
				}
			}
			return allow()
		case w == "read" || w == "mapfile" || w == "readarray" || w == "printf" || w == "print" || w == "getopts" || w == "for" || w == "select":
			for _, n := range setNames(w, words[i+1:]) {
				if name, ok := agentVarIn(n); ok {
					return why(name)
				}
			}
			return allow()
		case wrapper == "env" && strings.HasPrefix(w, "--") && w != "--":
			opt, val, hasVal := envLongOption(w)
			switch opt {
			case "--ignore-environment":
				return cleared("`env " + w + "`")
			case "--unset", "--chdir", "--split-string", "--argv0":
				if !hasVal && i+1 < len(words) {
					i++
					val = words[i]
				}
			}
			switch opt {
			case "--unset":
				if name, ok := agentVarIn(val); ok {
					return why(name)
				}
			case "--split-string":
				return checkEnvSplit(val, words[i+1:], depth)
			}
		case wrapper == "env" && w == "-":
			return cleared("`env -`")
		case wrapper == "env" && len(w) > 1 && w[0] == '-' && w[1] != '-':
			// a cluster of short flags: -i, -vu NAME, -uNAME, -S 'words'
			for j := 1; j < len(w); j++ {
				c := w[j]
				if c == 'i' {
					return cleared("`env " + w + "`")
				}
				if c != 'u' && c != 'C' && c != 'S' && c != 'a' {
					continue
				}
				val := w[j+1:]
				if val == "" && i+1 < len(words) {
					i++
					val = words[i]
				}
				if c == 'u' {
					if name, ok := agentVarIn(val); ok {
						return why(name)
					}
				}
				if c == 'S' {
					return checkEnvSplit(val, words[i+1:], depth)
				}
				break
			}
		case wrapper == "exec" && len(w) > 1 && w[0] == '-' && w[1] != '-' && strings.ContainsRune(w, 'c'):
			return cleared("`exec -c`")
		case isWrapper(base):
			wrapper, pos = base, 0
			if base == "sudo" || base == "doas" {
				sudo = base
			}
		case strings.HasPrefix(w, "-") && wrapper != "":
			if wrapper == "sudo" && (strings.HasPrefix(w, "--preserve-env") || len(w) > 1 && w[1] != '-' && strings.ContainsRune(w, 'E')) {
				keepsEnv = true
			}
			if wrapperValue[wrapper][w] {
				i++
			}
		case pos < wrapperPositional[wrapper]:
			pos++ // timeout 10, taskset 0x1
		default:
			// the program: its arguments are its own
			if base == "komando" && (sudo == "doas" || sudo == "sudo" && !keepsEnv) {
				return deny("%s starts komando with a clean environment, so komando would not know that an AI agent runs it; run komando without %s (it does not need root on this computer)", sudo, sudo)
			}
			return allow()
		}
	}
	return allow()
}

// checkEnvSplit is checkAgentVars for env -S WORDS REST: env runs WORDS as
// its own words.
func checkEnvSplit(words string, rest []string, depth int) guardDecision {
	if depth >= guardDepth {
		return tooDeep()
	}
	return checkAgentVars(append(append([]string{"env"}, shellWords(words)...), rest...), depth+1)
}

// homeVar moves komando's data folder. An agent's shell line must not
// change it either: komando would then use another inventory, without the
// person's protected servers, deny rules, host keys and audit log
// (guardHome stops the command when it happens anyway).
const homeVar = "KOMANDO_HOME"

// homeVars are the home folder's variables. Setting them in front of
// komando is refused; elsewhere they are the agent's own business (a test
// run with its own HOME).
var homeVars = map[string]bool{"HOME": true, "USERPROFILE": true}

// checkShellVars is checkAgentVars, and refuses HOME= or USERPROFILE= among
// the words in front of komando (its NAME=value words and wrappers).
func checkShellVars(words []string, depth int) guardDecision {
	if d := checkAgentVars(words, depth); d.Deny {
		return d
	}
	prog, args := program(words)
	if filepath.Base(prog) != "komando" {
		return allow()
	}
	for _, w := range words[:len(words)-len(args)-1] {
		if envAssign.MatchString(w) && homeVars[assignName(w)] {
			return deny("%s=... in front of komando would move its data folder away from the user's protected servers, deny rules, host keys and audit log (komando keeps an agent's data in the account's own home folder all the same). Run komando without it", assignName(w))
		}
	}
	return allow()
}

// watchedVars are the variables the guard keeps an agent's shell lines
// from changing: the agent variables and homeVar.
func watchedVars() []string {
	names := []string{homeVar}
	for _, a := range agentVars {
		names = append(names, a.env)
	}
	return names
}

// varChangeDenied is the guard's answer to a line that changes name.
func varChangeDenied(name string) guardDecision {
	if name == homeVar {
		return deny("%s moves komando's data folder: komando would use another list of servers, without the user's protected servers, deny rules, host keys and audit log. Leave it as it is; ask the user if komando should use another folder", name)
	}
	return deny("%s tells komando that an AI agent is running it; changing or clearing it would switch off komando's safety stops for agents. Leave it as it is", name)
}

// shellKeyword are words that can start a simple command before the
// command itself: `{ unset X; }`, `! unset X`, `if unset X`, `builtin unset X`.
var shellKeyword = map[string]bool{"{": true, "}": true, "!": true, "if": true, "then": true, "else": true, "elif": true, "fi": true,
	"do": true, "done": true, "while": true, "until": true, "builtin": true, "coproc": true, "noglob": true, "nocorrect": true, "function": true}

// assignName is the variable name of NAME=value or NAME+=value.
func assignName(w string) string {
	n, _, _ := strings.Cut(w, "=")
	return strings.TrimSuffix(n, "+")
}

// agentVarIn reports the watched variable (watchedVars) a name word sets
// or removes: the name itself, one of a {a,b} list, one a pattern matches
// (zsh `unset -m`), or any when the name is not known until the shell runs
// ($V, ${!P*}, `...`).
func agentVarIn(w string) (string, bool) {
	if strings.ContainsAny(w, "$`") {
		for _, env := range watchedVars() {
			if strings.Contains(w, env) {
				return env, true
			}
		}
		return agentVars[0].env + " (or another agent variable)", true
	}
	for _, x := range expandBraces(w, 0) {
		elem := x
		if i := strings.IndexByte(x, '['); i > 0 && strings.HasSuffix(x, "]") {
			elem = x[:i] // NAME[i]: an element of the variable NAME
		}
		for _, env := range watchedVars() {
			if x == env || elem == env {
				return env, true
			}
			if strings.ContainsAny(x, "*?[") {
				if ok, _ := filepath.Match(x, env); ok {
					return env, true
				}
			}
		}
	}
	return "", false
}

// setNames are the variable names a shell builtin that sets variables is
// given: read's and mapfile's names (not their flags' values), printf -v
// NAME and zsh's print -v NAME, getopts' NAME, and for's and select's loop
// variable.
func setNames(builtin string, args []string) []string {
	var names []string
	switch builtin {
	case "for", "select":
		if len(args) > 0 {
			names = append(names, args[0])
		}
	case "getopts":
		if len(args) > 1 {
			names = append(names, args[1])
		}
	case "printf", "print": // -v NAME, also in a cluster (-rv NAME)
		for i := 0; i < len(args) && strings.HasPrefix(args[i], "-") && args[i] != "--"; i++ {
			if k := strings.IndexByte(args[i], 'v'); k > 0 {
				if n := args[i][k+1:]; n != "" {
					names = append(names, n)
				} else if i+1 < len(args) {
					names = append(names, args[i+1])
				}
				break
			}
		}
	case "read", "mapfile", "readarray":
		values := "dnOsuCc" // flags whose value is not a name
		if builtin == "read" {
			values = "dinNptu"
		}
		for i := 0; i < len(args); i++ {
			a := args[i]
			if a == "--" {
				names = append(names, args[i+1:]...)
				break
			}
			if len(a) < 2 || a[0] != '-' {
				n, _, _ := strings.Cut(a, "?") // zsh: read NAME?prompt
				names = append(names, n)
				continue
			}
			for j := 1; j < len(a); j++ {
				if c := a[j]; strings.IndexByte(values, c) >= 0 || c == 'a' || c == 'A' {
					v := a[j+1:]
					if v == "" && i+1 < len(args) {
						i++
						v = args[i]
					}
					if c == 'a' || c == 'A' {
						names = append(names, v) // read -a NAME: an array
					}
					break
				}
			}
		}
	}
	return names
}

// envLongOption is the GNU env option w names: GNU takes any unambiguous
// start of a long option (--uns, --ignore-env). An ambiguous start that
// could clear or remove variables is taken as that, to be safe.
func envLongOption(w string) (opt, val string, hasVal bool) {
	name, val, hasVal := strings.Cut(w, "=")
	var match []string
	for _, o := range []string{"--ignore-environment", "--null", "--unset", "--chdir", "--split-string", "--block-signal",
		"--default-signal", "--ignore-signal", "--list-signal-handling", "--debug", "--argv0", "--help", "--version"} {
		if o == name {
			return o, val, hasVal
		}
		if len(name) > 2 && strings.HasPrefix(o, name) {
			match = append(match, o)
		}
	}
	for _, o := range match {
		if o == "--ignore-environment" || o == "--unset" || o == "--split-string" {
			return o, val, hasVal
		}
	}
	if len(match) == 1 {
		return match[0], val, hasVal
	}
	return name, val, hasVal
}
