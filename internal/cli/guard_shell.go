package cli

import (
	"maps"
	"path/filepath"
	"regexp"
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
// body). A body a shell reads as its script stays, and so do the command
// outputs of a body whose word is not quoted, which run.
func dropHeredocs(line string, all bool) string {
	var b strings.Builder
	at := 0
	for _, h := range heredocs(line) {
		if h.script || !h.quoted && !all {
			continue
		}
		b.WriteString(line[at:h.body])
		if !h.quoted {
			for _, s := range bodyOutputs(line[h.body:h.end]) {
				b.WriteString(s + "\n")
			}
		}
		at = h.end
	}
	b.WriteString(line[at:])
	return b.String()
}

// bodyOutputs are the command outputs ($(...) and `...`) of a here-document
// body whose word is not quoted: there \ makes the next character text, and
// quotes are text.
func bodyOutputs(body string) []string {
	var out []string
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '\\':
			i++
		case c == '`' || c == '$' && i+1 < len(body) && body[i+1] == '(':
			end, _ := outputEnd(body, i)
			out = append(out, body[i:end])
			i = end - 1
		}
	}
	return out
}

// heredocs are the here-documents of line as the shell reads them: an <<
// outside quotes, comments and arithmetic, not <<<, and its word; the body
// runs from the next line to the line that holds the word alone (tabs in
// front of it allowed), or to the end of the line. $( and ` start over
// inside "...", as the shell runs them. ${...}, $[...] and $'...' hold no
// here-document: inside the first two, quotes and command outputs are
// read, and an open brace or bracket nests, as zsh reads them.
func heredocs(line string) []heredoc {
	var out, pending []heredoc
	var words []string
	var s lineScan
	lineStart, word := 0, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case s.q == '\'':
			if c == '\'' {
				s.q = 0
			}
		case c == '\\':
			i++
			word = true
		case strings.HasPrefix(line[i:], "$(("), s.q == 0 && !word && strings.HasPrefix(line[i:], "(("):
			i, word = arithEnd(line, i), true // arithmetic: << shifts
		case c == '$' && i+1 < len(line) && line[i+1] == '(':
			s.push(scanFrame{})
			word = false
			i++
		case c == '$' && i+1 < len(line) && (line[i+1] == '{' || line[i+1] == '['):
			f := scanFrame{close: '}'}
			if line[i+1] == '[' {
				f.close = ']'
			}
			s.push(f)
			s.depth, word = 1, true
			i++
		case c == '`':
			if n := len(s.stack); n > 0 && s.stack[n-1].tick && s.q == 0 {
				s.pop()
				word = true
			} else {
				s.push(scanFrame{tick: true})
				word = false
			}
		case s.q == '"':
			if c == '"' {
				s.q = 0
			}
		case c == '$' && i+1 < len(line) && line[i+1] == '\'':
			i, word = dollarQuoteEnd(line, i), true
		case c == '\'' || c == '"':
			s.q, word = c, true
		case s.in() == '}' && c == '{', s.in() == ']' && c == '[':
			s.depth++
		case s.in() != 0 && c == s.in():
			if s.depth--; s.depth == 0 {
				s.pop()
			}
			word = true
		case s.in() != 0 && strings.HasPrefix(line[i:], "<<"):
			i++ // text in ${...} or $[...]
		case c == '#' && !word:
			for i+1 < len(line) && line[i+1] != '\n' {
				i++ // a comment
			}
		case c == '(':
			s.paren++
			word = false
		case c == ')':
			word = false
			if s.paren > 0 {
				s.paren--
			} else if n := len(s.stack); n > 0 && !s.stack[n-1].tick && s.stack[n-1].close == 0 {
				s.pop()
				word = true
			}
		case strings.HasPrefix(line[i:], "<<<"):
			i, word = i+2, false
		case strings.HasPrefix(line[i:], "<<"):
			h, w, k := heredocAt(line, i, lineStart)
			pending, words = append(pending, h), append(words, w)
			i, word = k-1, false
		case c == '\n':
			done, pos := endHeredocs(line, i+1, pending, words)
			out = append(out, done...)
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

// lineScan is where heredocs is in a line: the quote it is in, the ( open,
// the { or [ open in the ${ or $[ it is right inside, and the frames of the
// $(, `, ${ and $[ around it.
type lineScan struct {
	q            byte
	paren, depth int
	stack        []scanFrame
}

// scanFrame is a $(, `, ${ or $[ with the state outside it.
type scanFrame struct {
	q            byte
	paren, depth int
	tick         bool
	close        byte // } or ] of ${ or $[; 0 for $( and `
}

func (s *lineScan) push(f scanFrame) {
	f.q, f.paren, f.depth = s.q, s.paren, s.depth
	s.stack = append(s.stack, f)
	s.q, s.paren, s.depth = 0, 0, 0
}

func (s *lineScan) pop() {
	f := s.stack[len(s.stack)-1]
	s.q, s.paren, s.depth, s.stack = f.q, f.paren, f.depth, s.stack[:len(s.stack)-1]
}

// in is the close of the ${ or $[ the scan is right inside, or 0.
func (s *lineScan) in() byte {
	if n := len(s.stack); n > 0 {
		return s.stack[n-1].close
	}
	return 0
}

// dollarQuoteEnd is where the $'...' at i of line ends: there \ makes the
// next character text, a \' too.
func dollarQuoteEnd(line string, i int) int {
	for i += 2; i < len(line) && line[i] != '\''; i++ {
		if line[i] == '\\' {
			i++
		}
	}
	return i
}

// heredocAt reads the << at i of line, in the command that starts at
// lineStart: the here-document, its word, and where the word ends.
func heredocAt(line string, i, lineStart int) (heredoc, string, int) {
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
	h := heredoc{quoted: strings.ContainsAny(w, `'"\`), script: isShell(filepath.Base(prog))}
	return h, strings.NewReplacer(`'`, "", `"`, "", `\`, "").Replace(w), k
}

// endHeredocs gives the here-documents pending, whose words are words, with
// their bodies read from line[pos:], the text after the line break that
// ends their line; and where the line goes on after the last body.
func endHeredocs(line string, pos int, pending []heredoc, words []string) ([]heredoc, int) {
	var out []heredoc
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
	return out, pos
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
// (readLocalFile), and the rest are paths on servers, which it masks. cwd,
// before any cd of the line, is the project in use.
func checkShell(cl *call, line, home, cwd string) guardDecision {
	vars := lineVars{}
	if dirs := agentFoldersInUse(cwd); dirs != nil {
		vars[inUseVar] = dirs
	}
	return checkShellIn(cl, line, home, cwd, 0, vars)
}

// guardDepth is how many shells, evals and command outputs inside each
// other the guard reads; a line that goes deeper is refused.
const guardDepth = 3

func tooDeep() guardDecision {
	return deny("the line nests shells, evals or command outputs more than %d deep, deeper than komando's guard reads; run the inner command on its own", guardDepth)
}

// checkShellIn is checkShell for a line run depth shells, evals or command
// outputs deep, where outer's variables are set: a shell's -c script, or
// eval's.
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
		mwords, _ := shellWordsGlob(seg)
		vars.aliasesFrom(line, end-len(seg))
		vars.learn(cl, line, seg, end, home, cwd, mwords)
		segs, ok := wrapperReadings(seg)
		if !ok {
			return deny("komando's guard cannot tell which word is the program: a wrapper on the line has options it does not know (more than %d ways to read them); write each as --name=value, or run the program without the wrapper", maxReadings)
		}
		after := cwd
		for i, s := range segs {
			next, d := checkSimple(cl, rline, s, vars, home, cwd, depth)
			if d.Deny {
				return d
			}
			if i > 0 && next != after {
				next = lostDir
			}
			after = next
		}
		cwd = after
	}
	return allow()
}

// checkSimple checks the simple command seg, read one way its wrappers may
// read (wrapperReadings), and gives the working folder after it. rline is
// the line without its command outputs.
func checkSimple(cl *call, rline, seg string, vars lineVars, home, cwd string, depth int) (string, guardDecision) {
	mwords, mglobs := shellWordsGlob(seg)
	_, margs := program(mwords)
	rseg := strings.ReplaceAll(seg, unknownOutput, "")
	words, globs := shellWordsGlob(rseg)
	if d := checkShellVars(words, depth); d.Deny {
		return cwd, d
	}
	prog, args := program(words)
	base := filepath.Base(prog)
	// env -C DIR and sudo -D DIR run the program in DIR; the shell stays
	run, chdir := wrapperCwd(cl, shellWords(dropRedirects(seg)), vars, home, cwd)
	if d := checkGuardFiles(cl, rline, rseg, prog, args, home, run); d.Deny {
		return cwd, d
	}
	if d := checkWrites(cl, seg, vars, home, run); d.Deny {
		return cwd, d
	}
	if prog == "" || base == "komando" {
		return cwd, allow()
	}
	next, d := checkProgram(cl, base, args, margs, mglobs, vars, home, run, depth)
	if d.Deny {
		return cwd, d
	}
	if d := checkReadWords(cl, base, words, globs, args, vars, home, next); d.Deny {
		return cwd, d
	}
	next, d = checkValuePrograms(cl, seg, vars, home, next, depth)
	if d.Deny || chdir {
		return cwd, d
	}
	return next, allow()
}

// checkProgram checks what the program base does beyond the files it
// names: a cd, a script it runs, a command it refuses outright. args are
// its arguments with command outputs left out, margs with them in
// (mglobs are margs' globs and those before). It gives the working folder
// after it.
func checkProgram(cl *call, base string, args, margs []string, mglobs []bool, vars lineVars, home, cwd string, depth int) (string, guardDecision) {
	switch {
	case base == "cd" || base == "pushd":
		cwd = cdTarget(cl, margs, vars, home, cwd)
		if why := secretPath(cl, cwd, home); cwd != "" && why != "" {
			return cwd, deny("%s is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", cwd, why, viaKomando(why))
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
			return cwd, tooDeep()
		}
		if script != "" {
			// $f in the script is the line's f
			if d := checkShellIn(cl, script, home, cwd, depth+1, vars); d.Deny {
				return cwd, d
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
					return cwd, tooDeep()
				}
				if d := checkShellIn(cl, text, home, cwd, depth+1, vars); d.Deny {
					return cwd, d
				}
			}
		}
	case base == "find":
		if d := checkFind(cl, margs, mglobs[len(mglobs)-len(margs):], vars, home, cwd, depth); d.Deny {
			return cwd, d
		}
	case base == "watch" || scriptOption[base]:
		// watch runs its words, and script, su, runuser and flock
		// their -c text, as a shell line
		if script := commandScript(base, margs); script != "" {
			if depth >= guardDepth {
				return cwd, tooDeep()
			}
			if d := checkShellIn(cl, script, home, cwd, depth+1, vars); d.Deny {
				return cwd, d
			}
		}
	case base == "ssh" || base == "scp" || base == "sftp" || base == "mosh" || base == "sshpass":
		return cwd, deny("use komando for servers (`komando exec`, `komando fs`, `komando cp`), not %s: komando checks every command, hides secrets and keeps an audit log", base)
	case base == "rsync":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") && !strings.Contains(a, "://") && remoteSpec.MatchString(a) {
				return cwd, deny("use `komando sync` or `komando cp` for servers, not rsync")
			}
		}
	case base == "printenv" || base == "env" || base == "set" || base == "export" || base == "declare" || base == "typeset":
		// only the forms that list every variable: `set -e` is fine
		dump := len(args) == 0
		if (base == "export" || base == "declare" || base == "typeset") && len(args) == 1 && (args[0] == "-p" || args[0] == "-x" || args[0] == "-px") {
			dump = true
		}
		if dump {
			return cwd, deny("listing every environment variable shows tokens and passwords; read only the variable you need (`echo \"$NAME\"`)")
		}
	case base == "security":
		for _, a := range args {
			if a == "-w" || a == "-g" || a == "dump-keychain" || a == "export" {
				return cwd, deny("reading passwords from the keychain is for the user only")
			}
		}
	}
	return cwd, allow()
}

// checkReadWords refuses a command whose words name a secret path, or that
// reads all of a folder holding one (recursiveReader): words and globs are
// the command's, args its arguments.
func checkReadWords(cl *call, base string, words []string, globs []bool, args []string, vars lineVars, home, cwd string) guardDecision {
	switch base {
	case "echo", "printf", "touch", "mkdir", "ls", "test", "[":
		return allow() // they name files without reading them
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
	return allow()
}

// findPattern are find's tests that take a name pattern.
var findPattern = map[string]bool{"-name": true, "-iname": true, "-path": true, "-ipath": true, "-wholename": true, "-iwholename": true, "-regex": true, "-iregex": true, "-lname": true, "-ilname": true}

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
	words, globs, _ := shellWordsFlags(s)
	return words, globs
}

// shellWordsFlags is shellWordsGlob, and for each word whether it has a $,
// a backquote or a command output outside quotes: the shell splits such a
// value into more words.
func shellWordsFlags(s string) (words []string, globs, bare []bool) {
	var cur strings.Builder
	var q rune
	glob, brace, inWord, expands := false, false, false, false
	flush := func() {
		if cur.Len() > 0 || inWord {
			words = append(words, cur.String())
			globs = append(globs, glob || brace && strings.Contains(cur.String(), ","))
			bare = append(bare, expands)
			cur.Reset()
		}
		glob, brace, inWord, expands = false, false, false, false
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
			expands = expands || r == '$' || r == '`' || string(r) == unknownOutput
			cur.WriteRune(r)
			inWord = true
		}
	}
	flush()
	return words, globs, bare
}

// dropRedirects is the simple command seg without its redirects (2>/dev/null,
// >out, <in, <<<text, <<EOF): the words its program is given. A file
// descriptor written right before the operator goes with it.
func dropRedirects(seg string) string {
	var b strings.Builder
	for _, w := range rawWords(seg) {
		b.WriteString(w)
		b.WriteByte(' ')
	}
	return b.String()
}

// rawWords are the words of dropRedirects, quotes and all.
func rawWords(seg string) []string {
	var words []string
	var cur strings.Builder
	var q rune
	escaped, skip, quoted := false, false, false
	end := func() {
		if !skip && (cur.Len() > 0 || quoted) {
			words = append(words, cur.String())
		}
		cur.Reset()
		skip, quoted = false, false
	}
	rs := []rune(seg)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case escaped:
			escaped = false
			cur.WriteRune(r)
		case r == '\\' && q != '\'':
			escaped = true
			cur.WriteRune(r)
		case q != 0:
			if r == q {
				q = 0
			}
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			q, quoted = r, true
			cur.WriteRune(r)
		case r == '<' || r == '>':
			if !quoted && strings.Trim(cur.String(), "0123456789") == "" || cur.String() == "&" {
				cur.Reset() // 2>, &>: part of the operator
			} else {
				end()
			}
			for i+1 < len(rs) && strings.ContainsRune("<>&|!-", rs[i+1]) {
				i++
			}
			for i+1 < len(rs) && (rs[i+1] == ' ' || rs[i+1] == '\t') {
				i++
			}
			skip = true // the operator's word
		case r == ' ' || r == '\t':
			end()
		default:
			cur.WriteRune(r)
		}
	}
	end()
	return words
}
