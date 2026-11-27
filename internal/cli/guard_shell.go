package cli

import (
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// splitShell cuts a shell line into simple commands at ; | & && || newlines
// and parentheses, but not inside quotes: `grep 'a|ssh' f` is one command.
// $( and ` start a command even inside double quotes, because they run.
func splitShell(line string) []string {
	segs, _ := shellCuts(line)
	return segs
}

// shellCuts is splitShell, and for each command the byte that ended it:
// ; | & a newline ( ) ` $ (for $(), or 0 at the end of the line. The & of
// >& and <& (2>&1, >&FILE) is part of a redirect, not a command's end.
// ends is nil when a quote is left open.
func shellCuts(line string) (segs []string, ends []byte) {
	var cur strings.Builder
	cut := func(end byte) {
		segs = append(segs, cur.String())
		ends = append(ends, end)
		cur.Reset()
	}
	var q byte
	subst := 0        // open $( inside double quotes
	redirect := false // the byte before was an unquoted, unescaped > or <
	for i := 0; i < len(line); i++ {
		c := line[i]
		after := redirect
		redirect = false
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
			cut(c) // a command substitution: its own command, quoted or not
			if c == '$' {
				i++
				if q == '"' {
					subst++
				}
			}
		case q == '"' && c == ')' && subst > 0:
			cut(c)
			subst--
		case q == '"':
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			q = c
			cur.WriteByte(c)
		case c == '&' && after:
			cur.WriteByte(c)
		case c == ';' || c == '|' || c == '&' || c == '\n' || c == '(' || c == ')':
			cut(c)
		default:
			redirect = c == '>' || c == '<'
			cur.WriteByte(c)
		}
	}
	cut(0)
	if q != 0 {
		// an unclosed quote: the shell refuses the line, but be strict and
		// look at every part of it
		return anyOperator.Split(line, -1), nil
	}
	return segs, ends
}

var anyOperator = regexp.MustCompile(`[;|&\n()` + "`" + `"']`)

// stripQuotedHeredocs drops the bodies of <<'EOF' heredocs: the shell does
// not expand them, so they are data (a file's content, a script for python),
// not commands. Unquoted heredocs stay: $(...) in them runs. So does the
// body a shell reads as its script (`bash <<'EOF'`).
func stripQuotedHeredocs(line string) string {
	return dropHeredocs(line, false)
}

// joinContinuedLines drops each \ and the line break after it, as the
// shell does before it reads words, outside '...': ~/.koma\<newline>ndo
// is ~/.komando.
func joinContinuedLines(line string) string {
	if !strings.Contains(line, "\\\n") {
		return line
	}
	var b strings.Builder
	var q byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case c == '\\' && i+1 < len(line) && line[i+1] == '\n':
			i++
			continue
		case c == '\\' && i+1 < len(line):
			b.WriteByte(c)
			i++
			c = line[i]
		case c == '\'' && q == 0, c == '"' && q == 0:
			q = c
		case c == '"' && q == '"':
			q = 0
		}
		b.WriteByte(c)
	}
	return b.String()
}

// heredoc is a here-document of a shell line: its body is line[body:end],
// quoted says its word is quoted (the shell expands nothing in it), and
// script that a shell reads the body as its script.
type heredoc struct {
	body, end      int
	quoted, script bool
}

// dropHeredocs is line without the bodies of its here-documents that are
// data: the quoted ones, or every one when all is set (the shell globs no
// body). A body a shell reads as its script stays.
func dropHeredocs(line string, all bool) string {
	var b strings.Builder
	at := 0
	for _, h := range heredocs(line) {
		if h.script || !h.quoted && !all {
			continue
		}
		b.WriteString(line[at:h.body])
		at = h.end
	}
	b.WriteString(line[at:])
	return b.String()
}

// heredocs are the here-documents of line as the shell reads them: an <<
// outside quotes, comments and arithmetic, not <<<, and its word; the body
// runs from the next line to the line that holds the word alone (tabs in
// front of it allowed), or to the end of the line. $( and ` start over
// inside "...", as the shell runs them.
func heredocs(line string) []heredoc {
	type frame struct {
		q     byte
		paren int
		tick  bool
	}
	var out, pending []heredoc
	var words []string
	var stack []frame
	var q byte
	paren, lineStart, word := 0, 0, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case c == '\\':
			i++
			word = true
		case strings.HasPrefix(line[i:], "$(("), q == 0 && !word && strings.HasPrefix(line[i:], "(("):
			i, word = arithEnd(line, i), true // arithmetic: << shifts
		case c == '$' && i+1 < len(line) && line[i+1] == '(':
			stack = append(stack, frame{q: q, paren: paren})
			q, paren, word = 0, 0, false
			i++
		case c == '`':
			if n := len(stack); n > 0 && stack[n-1].tick && q == 0 {
				q, paren, stack = stack[n-1].q, stack[n-1].paren, stack[:n-1]
				word = true
			} else {
				stack = append(stack, frame{q: q, paren: paren, tick: true})
				q, paren, word = 0, 0, false
			}
		case q == '"':
			if c == '"' {
				q = 0
			}
		case c == '\'' || c == '"':
			q, word = c, true
		case c == '#' && !word:
			for i+1 < len(line) && line[i+1] != '\n' {
				i++ // a comment
			}
		case c == '(':
			paren++
			word = false
		case c == ')':
			word = false
			if paren > 0 {
				paren--
			} else if n := len(stack); n > 0 && !stack[n-1].tick {
				q, paren, stack = stack[n-1].q, stack[n-1].paren, stack[:n-1]
				word = true
			}
		case strings.HasPrefix(line[i:], "<<<"):
			i, word = i+2, false
		case strings.HasPrefix(line[i:], "<<"):
			j := i + 2
			if j < len(line) && line[j] == '-' {
				j++
			}
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			k := j
			for k < len(line) && !strings.ContainsRune(" \t\n;&|<>()", rune(line[k])) {
				k++
			}
			w := line[j:k]
			segs := splitShell(line[lineStart:i])
			prog, _ := program(shellWords(segs[len(segs)-1]))
			pending = append(pending, heredoc{quoted: strings.ContainsAny(w, `'"\`), script: isShell(filepath.Base(prog))})
			words = append(words, strings.NewReplacer(`'`, "", `"`, "", `\`, "").Replace(w))
			i, word = k-1, false
		case c == '\n':
			pos := i + 1
			for n, h := range pending {
				h.body, h.end = pos, len(line)
				for pos < len(line) {
					lineEnd := len(line)
					if k := strings.IndexByte(line[pos:], '\n'); k >= 0 {
						lineEnd = pos + k
					}
					if strings.TrimLeft(line[pos:lineEnd], "\t") == words[n] {
						h.end = pos
						pos = lineEnd + 1
						break
					}
					pos = lineEnd + 1
				}
				pos = min(pos, len(line))
				out = append(out, h)
			}
			pending, words = nil, nil
			i, lineStart, word = pos-1, pos, false
		case strings.ContainsRune(" \t;&|<>", rune(c)):
			word = false
		default:
			word = true
		}
	}
	return out
}

var (
	// reading the passphrase's value; setting it (KOMANDO_VAULT_PASS=...) is fine
	procEnviron    = regexp.MustCompile(`/proc/[^\s'"]*environ\b`)
	readsVaultPass = regexp.MustCompile(`\$\{?KOMANDO_VAULT_PASS\b|printenv\s+KOMANDO_VAULT_PASS\b`)
	envAssign      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=`)
	remoteSpec     = regexp.MustCompile(`^([A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+:`)
)

// checkShell looks at each simple command of a shell line, keeping track of
// `cd` so relative paths are read from the right folder. Arguments of
// komando itself pass: komando checks the local files it reads itself
// (readLocalFile), and the rest are paths on servers, which it masks.
func checkShell(cl *call, line, home, cwd string) guardDecision {
	return checkShellDepth(cl, line, home, cwd, 0)
}

// guardDepth is how many shells, evals and command outputs inside each
// other the guard reads; a line that goes deeper is refused.
const guardDepth = 3

func tooDeep() guardDecision {
	return deny("the line nests shells, evals or command outputs more than %d deep, deeper than komando's guard reads; run the inner command on its own", guardDepth)
}

func checkShellDepth(cl *call, line, home, cwd string, depth int) guardDecision {
	return checkShellIn(cl, line, home, cwd, depth, nil)
}

// checkShellIn is checkShellDepth for a line run where outer's variables
// are set: a shell's -c script, or eval's.
func checkShellIn(cl *call, line, home, cwd string, depth int, outer lineVars) guardDecision {
	line = decodeDollarQuotes(joinContinuedLines(stripQuotedHeredocs(line)))
	if d := checkWholeLine(line); d.Deny {
		return d
	}
	if d := checkGlobForms(line); d.Deny {
		return d
	}
	vars := maps.Clone(outer)
	if vars == nil {
		vars = lineVars{}
	}
	vars.aliasesFrom(line, -1) // this code is read after the alias was made
	if redefines.MatchString(line) || namesTrusted(line) {
		vars[redefinedVar] = nil
	}
	// each word with a command output in it is checked whole: splitShell
	// below cuts it where the command starts
	if in := withCommandOutput(cl, line, vars); in != line {
		if depth >= guardDepth {
			return tooDeep()
		}
		if d := checkShellIn(cl, in, home, cwd, depth+1, vars); d.Deny {
			return d
		}
	}
	// the checks of reads look at the words a command output names
	rline := strings.ReplaceAll(line, unknownOutput, "")
	end := 0
	for _, seg := range splitShell(line) {
		if at := strings.Index(line[end:], seg); at >= 0 {
			end += at + len(seg)
		}
		mwords, mglobs := shellWordsGlob(seg)
		vars.aliasesFrom(line, end-len(seg))
		vars.learn(cl, line, seg, end, home, cwd, mwords)
		_, margs := program(mwords)
		rseg := strings.ReplaceAll(seg, unknownOutput, "")
		words, globs := shellWordsGlob(rseg)
		if d := checkShellVars(words, depth); d.Deny {
			return d
		}
		prog, args := program(words)
		base := filepath.Base(prog)
		if d := checkGuardFiles(cl, rline, rseg, prog, args, home, cwd); d.Deny {
			return d
		}
		if d := checkWrites(cl, seg, mwords, mglobs, vars, home, cwd); d.Deny {
			return d
		}
		switch {
		case prog == "":
			continue
		case base == "komando":
			continue
		case base == "cd" || base == "pushd":
			cwd = cdTarget(cl, margs, vars, home, cwd)
			if why := secretPath(cl, cwd, home); cwd != "" && why != "" {
				return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", cwd, why, viaKomando(why))
			}
		case base == "popd":
			cwd = lostDir
		case isShell(base) || base == "eval" || base == "trap":
			// the script of `bash -c '...'`, `bash -lc '...'`, `eval '...'`
			// and `trap '...' SIGNAL` is a shell line too
			script := shellScript(margs)
			switch base {
			case "eval":
				script = strings.Join(margs, " ")
			case "trap":
				script = trapScript(margs)
			}
			if script != "" && depth >= guardDepth {
				return tooDeep()
			}
			if script != "" {
				// $f in the script is the line's f
				if d := checkShellIn(cl, script, home, cwd, depth+1, vars); d.Deny {
					return d
				}
			}
			if base == "eval" {
				cwd = lostDir // the script may cd
			}
		case base == "source" || base == ".":
			cwd = lostDir
		case base == "alias":
			// an alias's text runs where a later command names it
			for _, a := range margs {
				if _, text, ok := strings.Cut(a, "="); ok && text != "" {
					if depth >= guardDepth {
						return tooDeep()
					}
					if d := checkShellIn(cl, text, home, cwd, depth+1, vars); d.Deny {
						return d
					}
				}
			}
		case base == "find":
			if d := checkFind(cl, margs, mglobs[len(mglobs)-len(margs):], vars, home, cwd, depth); d.Deny {
				return d
			}
		case base == "watch" || scriptOption[base]:
			// watch runs its words, and script, su, runuser and flock
			// their -c text, as a shell line
			if script := commandScript(base, margs); script != "" {
				if depth >= guardDepth {
					return tooDeep()
				}
				if d := checkShellIn(cl, script, home, cwd, depth+1, vars); d.Deny {
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
					if wcwd = nextDir(cl, words[j:j+1], home, wcwd); wcwd != "" {
						if why := secretPath(cl, wcwd, home); why != "" {
							return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", wcwd, why, viaKomando(why))
						}
					}
					continue
				case (base == "tar" || base == "git" || base == "make") && strings.HasPrefix(w, "--directory="):
					if wcwd = nextDir(cl, []string{strings.TrimPrefix(w, "--directory=")}, home, wcwd); wcwd != "" {
						if why := secretPath(cl, wcwd, home); why != "" {
							return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", wcwd, why, viaKomando(why))
						}
					}
					continue
				case base == "find" && findPattern[w]:
					j++ // a name pattern: find lists names; -exec, which reads, is checked
					continue
				}
			}
			values, _ := vars.expand(cl, w, home, wcwd)
			for _, v := range values {
				glob := globs[j] && !strings.HasPrefix(w, "-") || v != w && wordHasGlob(v)
				if !looksLikePath(v) && !glob {
					continue
				}
				if why := secretWord(cl, v, home, wcwd, glob); why != "" {
					return deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", w, why, viaKomando(why))
				}
				if recursive && j >= first && !glob && !strings.HasPrefix(v, "-") && holdsProtected(cl, guardPathAt(cl, v, home, wcwd), home) {
					return deny("%s holds komando's data and private keys, and %s reads all of it; work on a project folder instead", w, base)
				}
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

// scriptOption are programs that run the text of their -c (or --command)
// option as a shell line.
var scriptOption = map[string]bool{"script": true, "su": true, "runuser": true, "flock": true}

// commandScript is the shell line base ARGS runs: watch's words after its
// options, the -c text of a scriptOption program, or the command BSD's
// script FILE COMMAND runs; "" when there is none.
func commandScript(base string, args []string) string {
	if base == "script" && !slices.ContainsFunc(args, func(a string) bool { return a == "-c" || strings.HasPrefix(a, "--command") }) {
		for i, a := range args {
			if !strings.HasPrefix(a, "-") {
				if i+1 < len(args) {
					return findCommandLine(args[i+1:], "{}")
				}
				return ""
			}
		}
		return ""
	}
	if base == "watch" {
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "-n" || a == "--interval" || a == "-q" || a == "--equexit":
				i++
			case a == "--":
				return strings.Join(args[i+1:], " ")
			case !strings.HasPrefix(a, "-"):
				return strings.Join(args[i:], " ")
			}
		}
		return ""
	}
	for i, a := range args {
		if (a == "-c" || a == "--command") && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--command="); ok {
			return v
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

// nextDir is the folder `cd ARGS` moves to from cwd: lostDir when the guard
// cannot know it (`cd -`, `cd "$DIR"`, a glob, or a relative folder from a
// lost one), and "" for a relative folder when cwd is "".
func nextDir(cl *call, args []string, home, cwd string) string {
	for _, a := range args {
		if a == "--" || a == "-L" || a == "-P" || a == "-e" || a == "-@" {
			continue
		}
		if a == "-" || strings.ContainsAny(strings.NewReplacer("$HOME", "", "${HOME}", "", "$KOMANDO_HOME", "", "${KOMANDO_HOME}", "").Replace(a), "$`"+unknownOutput) {
			return lostDir
		}
		if wordHasGlob(a) {
			return lostDir // the word is checked as a glob with the others
		}
		p := guardPath(cl, a, home)
		if filepath.IsAbs(p) {
			return p
		}
		if cwd == "" || cwd == lostDir {
			return cwd
		}
		return lexOrKernel(cwd + string(filepath.Separator) + p)
	}
	return home
}

// cdTarget is the folder cd ARGS, words of a line with vars, moves to from
// cwd (nextDir). A word with more than one value or one the guard cannot
// read, and a relative name CDPATH can send elsewhere, give lostDir.
func cdTarget(cl *call, args []string, vars lineVars, home, cwd string) string {
	dirs := slices.Clone(args)
	_, cdpath := vars["CDPATH"]
	cdpath = cdpath || cl.getenv("CDPATH") != ""
	for k, a := range dirs {
		x, known := vars.expand(cl, a, home, cwd)
		if !known || len(x) != 1 {
			return lostDir
		}
		dirs[k] = x[0]
		if d := x[0]; cdpath && !strings.HasPrefix(d, "-") && d != "." && d != ".." && !strings.HasPrefix(d, "./") && !strings.HasPrefix(d, "../") && !filepath.IsAbs(guardPath(cl, d, home)) {
			return lostDir
		}
	}
	return nextDir(cl, dirs, home, cwd)
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
				if depth >= guardDepth {
					return tooDeep()
				}
				return checkAgentVars(append(append([]string{"env"}, shellWords(val)...), words[i+1:]...), depth+1)
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
				if c == 'S' && depth >= guardDepth {
					return tooDeep()
				}
				if c == 'S' {
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
		"timeout", "setsid", "stdbuf", "chrt", "ionice", "taskset", "caffeinate", "busybox", "toybox", "unbuffer", "rtk":
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
	escaped, redirect := false, false
	for _, r := range s {
		after := redirect
		redirect = false
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
		case r == '&' && after: // >&FILE writes FILE; 2>&1 names no file
		case r == ' ' || r == '\t' || r == '<' || r == '>':
			redirect = r != ' ' && r != '\t'
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
