package cli

import (
	"path/filepath"
	"regexp"
	"strings"
)

// splitShell cuts a shell line into simple commands at ; | & && || newlines
// and parentheses, but not inside quotes: `grep 'a|ssh' f` is one command.
// $( and ` start a command even inside double quotes, because they run.
func splitShell(line string) []string {
	var segs []string
	var cur strings.Builder
	cut := func() {
		segs = append(segs, cur.String())
		cur.Reset()
	}
	var q byte
	subst := 0 // open $( inside double quotes
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
			cur.WriteByte(c)
		case c == '\\' && i+1 < len(line):
			cur.WriteByte(c)
			cur.WriteByte(line[i+1])
			i++
		case q == '"' && c == '"':
			q = 0
			cur.WriteByte(c)
		case c == '`' || c == '$' && i+1 < len(line) && line[i+1] == '(':
			cut() // a command substitution: its own command, quoted or not
			if c == '$' {
				i++
				if q == '"' {
					subst++
				}
			}
		case q == '"' && c == ')' && subst > 0:
			cut()
			subst--
		case q == '"':
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			q = c
			cur.WriteByte(c)
		case c == ';' || c == '|' || c == '&' || c == '\n' || c == '(' || c == ')':
			cut()
		default:
			cur.WriteByte(c)
		}
	}
	cut()
	if q != 0 {
		// an unclosed quote: the shell refuses the line, but be strict and
		// look at every part of it
		return anyOperator.Split(line, -1)
	}
	return segs
}

var anyOperator = regexp.MustCompile(`[;|&\n()` + "`" + `"']`)

// stripQuotedHeredocs drops the bodies of <<'EOF' heredocs: the shell does
// not expand them, so they are data (a file's content, a script for python),
// not commands. Unquoted heredocs stay: $(...) in them runs. So does the
// body a shell reads as its script (`bash <<'EOF'`).
func stripQuotedHeredocs(line string) string {
	lines := strings.Split(line, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		out = append(out, lines[i])
		m := heredocStart.FindStringSubmatchIndex(lines[i])
		if m == nil {
			continue
		}
		segs := splitShell(lines[i][:m[0]])
		if prog, _ := program(shellWords(segs[len(segs)-1])); isShell(filepath.Base(prog)) {
			continue // the body is a script: it runs
		}
		end := lines[i][m[4]:m[5]]
		for i++; i < len(lines) && strings.TrimLeft(lines[i], "\t") != end; i++ {
		}
		if i < len(lines) {
			out = append(out, lines[i])
		}
	}
	return strings.Join(out, "\n")
}

var (
	// reading the passphrase's value; setting it (KOMANDO_VAULT_PASS=...) is fine
	procEnviron    = regexp.MustCompile(`/proc/[^\s'"]*environ\b`)
	readsVaultPass = regexp.MustCompile(`\$\{?KOMANDO_VAULT_PASS\b|printenv\s+KOMANDO_VAULT_PASS\b`)
	heredocStart   = regexp.MustCompile(`<<-?[ \t]*(['"])([A-Za-z_][A-Za-z0-9_]*)['"]`)
	envAssign      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=`)
	remoteSpec     = regexp.MustCompile(`^([A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+:`)
	// $(echo X), `printf X`, $(ls X): their output is the words X, which
	// become the outer command's arguments
	nameSubst = regexp.MustCompile(`\$\(\s*(echo|printf|ls|realpath|readlink|dirname)\b([^()` + "`" + `]*)\)|` + "`" + `\s*(echo|printf|ls|realpath|readlink|dirname)\b([^` + "`" + `]*)` + "`")
)

// inlineNames puts the words of $(echo X) and `echo X` in place of the
// substitution, as the shell does: `cat $(echo ~)/.komando/state.json`
// reads ~/.komando/state.json.
func inlineNames(line string) string {
	return nameSubst.ReplaceAllStringFunc(line, func(m string) string {
		g := nameSubst.FindStringSubmatch(m)
		args := strings.TrimSpace(g[2] + g[4])
		if g[1]+g[3] == "printf" {
			if f, rest, ok := strings.Cut(args, " "); ok && strings.Contains(f, "%") {
				args = strings.TrimSpace(rest) // the format: the rest is what it prints
			}
		}
		return args
	})
}

// checkShell looks at each simple command of a shell line, keeping track of
// `cd` so relative paths are read from the right folder. Arguments of
// komando itself pass: komando checks the local files it reads itself
// (readLocalFile), and the rest are paths on servers, which it masks.
func checkShell(line, home, cwd string) guardDecision {
	return checkShellDepth(line, home, cwd, 0)
}

func checkShellDepth(line, home, cwd string, depth int) guardDecision {
	line = stripQuotedHeredocs(line)
	if readsVaultPass.MatchString(line) {
		return deny("KOMANDO_VAULT_PASS opens komando's vault; it is for the user only")
	}
	if procEnviron.MatchString(line) { // /proc/PID/environ, not words like "environments"
		return deny("process environments hold secrets; ask the user for the one value you need")
	}
	if in := inlineNames(line); in != line && depth < 3 {
		if d := checkShellDepth(in, home, cwd, depth+1); d.Deny {
			return d
		}
	}
	for _, seg := range splitShell(line) {
		words, globs := shellWordsGlob(seg)
		if d := checkAgentVars(words, depth); d.Deny {
			return d
		}
		prog, args := program(words)
		base := filepath.Base(prog)
		switch {
		case prog == "":
			continue
		case base == "komando":
			continue
		case base == "cd" || base == "pushd":
			cwd = nextDir(args, home, cwd)
			if why := secretPath(cwd, home); cwd != "" && why != "" {
				return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", cwd, why, viaKomando(why))
			}
		case isShell(base) || base == "eval":
			// the script of `bash -c '...'`, `bash -lc '...'` and `eval '...'`
			// is a shell line too
			script := shellScript(args)
			if base == "eval" {
				script = strings.Join(args, " ")
			}
			if script != "" && depth < 3 {
				if d := checkShellDepth(script, home, cwd, depth+1); d.Deny {
					return d
				}
			}
		case base == "ssh" || base == "scp" || base == "sftp" || base == "mosh" || base == "sshpass":
			return deny("use komando for servers (`komando exec`, `komando fs`, `komando cp`), not %s: komando checks every command, hides secrets and keeps an audit log", base)
		case base == "rsync":
			for _, a := range args {
				if !strings.HasPrefix(a, "-") && !strings.Contains(a, "://") && remoteSpec.MatchString(a) {
					return deny("use `komando sync` or `komando cp` for servers, not rsync")
				}
			}
		case base == "printenv" || base == "env" || base == "set" || base == "export" || base == "declare" || base == "typeset":
			// only the forms that list every variable: `set -e` is fine
			dump := len(args) == 0
			if (base == "export" || base == "declare" || base == "typeset") && len(args) == 1 && (args[0] == "-p" || args[0] == "-x" || args[0] == "-px") {
				dump = true
			}
			if dump {
				return deny("listing every environment variable shows tokens and passwords; read only the variable you need (`echo \"$NAME\"`)")
			}
		case base == "security":
			for _, a := range args {
				if a == "-w" || a == "-g" || a == "dump-keychain" || a == "export" {
					return deny("reading passwords from the keychain is for the user only")
				}
			}
		}
		switch base {
		case "echo", "printf", "touch", "mkdir", "ls", "test", "[":
			continue // they name files without reading them
		}
		recursive := recursiveReader(base, args)
		first := len(words) - len(args) // where the arguments start
		wcwd := cwd
		for j := 0; j < len(words); j++ {
			w := words[j]
			if j >= first {
				switch {
				case (base == "tar" || base == "git" || base == "make") && (w == "-C" || w == "--directory") && j+1 < len(words):
					// tar -C DIR and git -C DIR: the words after it are read from DIR
					j++
					if wcwd = nextDir(words[j:j+1], home, wcwd); wcwd != "" {
						if why := secretPath(wcwd, home); why != "" {
							return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", wcwd, why, viaKomando(why))
						}
					}
					continue
				case (base == "tar" || base == "git" || base == "make") && strings.HasPrefix(w, "--directory="):
					if wcwd = nextDir([]string{strings.TrimPrefix(w, "--directory=")}, home, wcwd); wcwd != "" {
						if why := secretPath(wcwd, home); why != "" {
							return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", wcwd, why, viaKomando(why))
						}
					}
					continue
				case base == "find" && findPattern[w]:
					j++ // a name pattern: find lists names; -exec, which reads, is checked
					continue
				}
			}
			glob := globs[j] && !strings.HasPrefix(w, "-")
			if !looksLikePath(w) && !glob {
				continue
			}
			if why := secretWord(w, home, wcwd, glob); why != "" {
				return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", w, why, viaKomando(why))
			}
			if recursive && j >= first && !glob && !strings.HasPrefix(w, "-") && holdsProtected(guardPathAt(w, home, wcwd), home) {
				return deny("%s holds komando's data and private keys, and %s reads all of it; work on a project folder instead", w, base)
			}
		}
	}
	return allow()
}

// findPattern are find's tests that take a name pattern.
var findPattern = map[string]bool{"-name": true, "-iname": true, "-path": true, "-ipath": true, "-wholename": true, "-iwholename": true, "-regex": true, "-iregex": true, "-lname": true, "-ilname": true}

func isShell(base string) bool {
	switch base {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish":
		return true
	}
	return false
}

// shellScript is the script a shell's arguments give with -c, or "": -c can
// come in a cluster (`bash -lc`, `sh -ec`), and options and their values
// (`-o pipefail`, `--`) can come between it and the script.
func shellScript(args []string) string {
	c := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if c && i+1 < len(args) {
				return args[i+1]
			}
			return ""
		case a == "--rcfile" || a == "--init-file":
			i++
		case strings.HasPrefix(a, "--"):
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			if a[0] == '-' && strings.ContainsRune(a[1:], 'c') {
				c = true
			}
			if strings.ContainsAny(a[1:], "oO") {
				i++ // -o pipefail
			}
		default:
			if c {
				return a
			}
			return "" // a script file
		}
	}
	return ""
}

// recursiveReader reports whether a command reads every file under the
// folders it is given (grep -r, rg, tar c, zip -r, cp -r, find -exec, ...):
// given the home folder, it reads komando's data and the private keys too.
func recursiveReader(base string, args []string) bool {
	cluster := func(letters string) bool {
		for _, a := range args {
			if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], letters) {
				return true
			}
		}
		return false
	}
	has := func(long ...string) bool {
		for _, a := range args {
			for _, l := range long {
				if a == l || strings.HasPrefix(a, l+"=") {
					return true
				}
			}
		}
		return false
	}
	switch base {
	case "rg", "ag", "ack", "ack-grep", "rclone", "restic", "borg", "7z", "7za", "7zz":
		return true
	case "grep", "egrep", "fgrep", "zgrep", "ugrep":
		return cluster("rR") || has("--recursive", "--dereference-recursive", "--directories=recurse")
	case "zip", "diff":
		return cluster("rR") || has("--recurse-paths", "--recursive")
	case "cp", "rsync":
		return cluster("rRa") || has("--recursive", "--archive")
	case "tar", "bsdtar", "gtar":
		if has("--extract", "--list", "--get", "--diff", "--compare") || cluster("xtd") {
			return false
		}
		return len(args) == 0 || strings.HasPrefix(args[0], "-") || !strings.ContainsAny(args[0], "xtd")
	case "find":
		return has("-exec", "-execdir", "-ok", "-okdir")
	}
	return false
}

// nextDir is the folder `cd ARGS` moves to from cwd, or "" when the guard
// cannot know it (`cd -`, `cd "$DIR"`).
func nextDir(args []string, home, cwd string) string {
	for _, a := range args {
		if a == "--" || a == "-L" || a == "-P" || a == "-e" || a == "-@" {
			continue
		}
		if a == "-" || strings.ContainsAny(strings.NewReplacer("$HOME", "", "${HOME}", "", "$KOMANDO_HOME", "", "${KOMANDO_HOME}", "").Replace(a), "$`") {
			return ""
		}
		if wordHasGlob(a) {
			return "" // checked as a glob with the other words
		}
		p := guardPath(a, home)
		if filepath.IsAbs(p) {
			return p
		}
		if cwd == "" {
			return ""
		}
		return filepath.Join(cwd, p)
	}
	return home
}

// checkAgentVars stops a command that changes the variables komando knows
// an AI agent by (agentVars): `CLAUDECODE=0 komando ...`, `unset`, `export`,
// `read`, `env -u`, `env -i` and `exec -c` would make komando treat the
// agent as a script and skip the person's window, masking and the
// secret-file stops. So would `sudo komando`, which starts komando with a
// clean environment. A name komando cannot read (`unset $V`, `${!CLAUDE*}`)
// or a pattern (`CLAUDE*`, `CLAUDE{CODE,_CODE_ENTRYPOINT}`) that could be
// one counts as that name.
func checkAgentVars(words []string, depth int) guardDecision {
	why := func(name string) guardDecision {
		return deny("%s tells komando that an AI agent is running it; changing or clearing it would switch off komando's safety stops for agents. Leave it as it is", name)
	}
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
		case w == "read" || w == "mapfile" || w == "readarray" || w == "printf" || w == "getopts" || w == "for" || w == "select":
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
				if depth < 3 {
					return checkAgentVars(append(append([]string{"env"}, shellWords(val)...), words[i+1:]...), depth+1)
				}
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
				if c == 'S' && depth < 3 {
					return checkAgentVars(append(append([]string{"env"}, shellWords(val)...), words[i+1:]...), depth+1)
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

// shellKeyword are words that can start a simple command before the
// command itself: `{ unset X; }`, `! unset X`, `if unset X`, `builtin unset X`.
var shellKeyword = map[string]bool{"{": true, "}": true, "!": true, "if": true, "then": true, "else": true, "elif": true, "fi": true,
	"do": true, "done": true, "while": true, "until": true, "builtin": true, "coproc": true, "noglob": true, "nocorrect": true, "function": true}

// assignName is the variable name of NAME=value or NAME+=value.
func assignName(w string) string {
	n, _, _ := strings.Cut(w, "=")
	return strings.TrimSuffix(n, "+")
}

// agentVarIn reports the agent variable a name word sets or removes: the
// name itself, one of a {a,b} list, one a pattern matches (zsh `unset -m`),
// or any when the name is not known until the shell runs ($V, ${!P*}, `...`).
func agentVarIn(w string) (string, bool) {
	if strings.ContainsAny(w, "$`") {
		for _, a := range agentVars {
			if strings.Contains(w, a.env) {
				return a.env, true
			}
		}
		return agentVars[0].env + " (or another agent variable)", true
	}
	for _, x := range expandBraces(w, 0) {
		elem := x
		if i := strings.IndexByte(x, '['); i > 0 && strings.HasSuffix(x, "]") {
			elem = x[:i] // NAME[i]: an element of the variable NAME
		}
		for _, a := range agentVars {
			if x == a.env || elem == a.env {
				return a.env, true
			}
			if strings.ContainsAny(x, "*?[") {
				if ok, _ := filepath.Match(x, a.env); ok {
					return a.env, true
				}
			}
		}
	}
	return "", false
}

// setNames are the variable names a shell builtin that sets variables is
// given: read's and mapfile's names (not their flags' values), printf -v
// NAME, getopts' NAME, and for's and select's loop variable.
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
	case "printf":
		for i, a := range args {
			if a == "-v" && i+1 < len(args) {
				names = append(names, args[i+1])
			} else if strings.HasPrefix(a, "-v") {
				names = append(names, a[2:])
			}
			if !strings.HasPrefix(a, "-") {
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

// program is the command a simple command runs, after shell keywords,
// VAR=value words and wrappers such as sudo, env, time, timeout and nohup.
func program(words []string) (string, []string) {
	wrapper, pos := "", 0
	for i := 0; i < len(words); i++ {
		w := words[i]
		base := filepath.Base(w)
		switch {
		case wrapper == "" && shellKeyword[w]:
			if w == "function" {
				i++
			}
			continue
		case envAssign.MatchString(w):
			continue
		case isWrapper(base) && base != "env":
			wrapper, pos = base, 0
			continue
		case base == "env" && i+1 < len(words) && (envAssign.MatchString(words[i+1]) || strings.HasPrefix(words[i+1], "-")):
			wrapper, pos = "env", 0
			continue
		case strings.HasPrefix(w, "-") && i > 0:
			// a wrapper's flag, e.g. sudo -u app: skip its value too
			if wrapperValue[wrapper][w] {
				i++
			}
			continue
		case pos < wrapperPositional[wrapper]:
			pos++
			continue
		}
		return w, words[i+1:]
	}
	return "", nil
}

func isWrapper(w string) bool {
	switch w {
	case "env", "sudo", "doas", "time", "nohup", "exec", "command", "nice", "xargs",
		"timeout", "setsid", "stdbuf", "chrt", "ionice", "taskset", "caffeinate", "busybox", "toybox", "unbuffer":
		return true
	}
	return false
}

// wrapperValue are the wrappers' flags that take the next word as a value.
var wrapperValue = map[string]map[string]bool{
	"env":        {"-u": true, "--unset": true, "-C": true, "--chdir": true, "-S": true, "--split-string": true},
	"sudo":       {"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true, "-r": true, "-t": true, "-U": true, "-T": true},
	"doas":       {"-u": true, "-C": true},
	"nice":       {"-n": true},
	"exec":       {"-a": true},
	"time":       {"-f": true, "-o": true},
	"xargs":      {"-I": true, "-n": true, "-P": true, "-L": true, "-d": true, "-E": true, "-s": true, "-a": true},
	"timeout":    {"-s": true, "--signal": true, "-k": true, "--kill-after": true},
	"stdbuf":     {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"ionice":     {"-c": true, "-n": true, "--class": true, "--classdata": true},
	"chrt":       {"-T": true, "-P": true, "-D": true},
	"caffeinate": {"-t": true, "-w": true},
}

// wrapperPositional are the wrappers that take words before the program:
// timeout DURATION, chrt PRIORITY, taskset MASK.
var wrapperPositional = map[string]int{"timeout": 1, "chrt": 1, "taskset": 1}

// looksLikePath: a word that names a file, not a flag or a plain word
// (e.g. `grep password` is fine, `cat .env` is not).
func looksLikePath(w string) bool {
	w = strings.Trim(w, `"'`)
	if strings.ContainsAny(w, " \t") {
		return false // a sentence, e.g. a commit message
	}
	if i := strings.Index(w, "="); i >= 0 && strings.HasPrefix(w, "-") {
		w = w[i+1:]
	}
	for _, v := range []string{"$HOME", "${HOME}", "$KOMANDO_HOME", "${KOMANDO_HOME}"} {
		if strings.HasPrefix(w, v) {
			return true
		}
	}
	return strings.ContainsAny(w, "/~.") || w == "credentials" || strings.HasPrefix(w, "id_")
}

// shellWords splits a simple command into words, removing quotes and
// redirections' operators.
func shellWords(s string) []string {
	w, _ := shellWordsGlob(s)
	return w
}

// shellWordsGlob is shellWords, and for each word whether the shell expands
// it as a glob: it has *, ?, [ or a {a,b} list outside quotes. `cat .e*`
// does, `grep -o '.*' f` and `cat ${HOME}/notes` do not.
func shellWordsGlob(s string) ([]string, []bool) {
	var words []string
	var globs []bool
	var cur strings.Builder
	var q rune
	glob, brace, inWord := false, false, false
	flush := func() {
		if cur.Len() > 0 || inWord {
			words = append(words, cur.String())
			globs = append(globs, glob || brace && strings.Contains(cur.String(), ","))
			cur.Reset()
		}
		glob, brace, inWord = false, false, false
	}
	escaped := false
	for _, r := range s {
		switch {
		case escaped: // \x is a plain x, as in the shell: \" opens no quote
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && q != '\'':
			escaped = true
			inWord = true
		case q != 0:
			if r == q {
				q = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			q = r
			inWord = true
		case r == ' ' || r == '\t' || r == '<' || r == '>':
			flush()
		default:
			if strings.ContainsRune("*?[", r) {
				glob = true
			}
			if r == '{' {
				brace = true
			}
			cur.WriteRune(r)
			inWord = true
		}
	}
	flush()
	return words, globs
}
