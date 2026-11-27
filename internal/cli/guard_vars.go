package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The guard reads a word the way the shell will run it: $'...' and $"..."
// decoded, and a variable set earlier on the line in place of its name.

// decodeDollarQuotes writes each $'...' of a shell line as the '...' word
// bash and zsh read it as (\x2e, \056, ., \n and the other escapes
// decoded), and each $"..." as "...". Inside '...' and "..." the shell
// leaves them as they are, and so does this; a $(...) or `...` in "..."
// starts over.
func decodeDollarQuotes(line string) string {
	if !strings.Contains(line, "$'") && !strings.Contains(line, `$"`) {
		return line
	}
	type frame struct {
		q     byte
		paren int
		tick  bool
	}
	var b strings.Builder
	var stack []frame
	var q byte
	paren := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		next := byte(0)
		if i+1 < len(line) {
			next = line[i+1]
		}
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
			b.WriteByte(c)
		case c == '\\' && next != 0:
			b.WriteByte(c)
			b.WriteByte(next)
			i++
		case c == '$' && next == '(':
			stack = append(stack, frame{q: q, paren: paren})
			q, paren = 0, 0
			b.WriteString("$(")
			i++
		case c == '`':
			if n := len(stack); n > 0 && stack[n-1].tick && q == 0 {
				q, paren, stack = stack[n-1].q, stack[n-1].paren, stack[:n-1]
			} else {
				stack = append(stack, frame{q: q, paren: paren, tick: true})
				q, paren = 0, 0
			}
			b.WriteByte(c)
		case q == '"':
			if c == '"' {
				q = 0
			}
			b.WriteByte(c)
		case c == '$' && next == '\'':
			dec, end := ansiC(line, i+2)
			b.WriteString(shellQuote1(dec))
			i = end
		case c == '$' && next == '"':
			// $"..." is "..."
		default:
			switch c {
			case '\'', '"':
				q = c
			case '(':
				paren++
			case ')':
				if paren > 0 {
					paren--
				} else if n := len(stack); n > 0 && !stack[n-1].tick {
					q, paren, stack = stack[n-1].q, stack[n-1].paren, stack[:n-1]
				}
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}

// shellQuote1 is s in single quotes, always.
func shellQuote1(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ansiC decodes the body of $'...' that starts at line[i], and gives the
// index of its closing quote (or of the line's last byte). The shell ends
// the word at a NUL byte.
func ansiC(line string, i int) (string, int) {
	isHex := func(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }
	isOct := func(c byte) bool { return '0' <= c && c <= '7' }
	span := func(j, most int, ok func(byte) bool) int {
		k := j
		for k < len(line) && k-j < most && ok(line[k]) {
			k++
		}
		return k
	}
	var b strings.Builder
	for ; i < len(line) && line[i] != '\''; i++ {
		c := line[i]
		if c != '\\' || i+1 >= len(line) {
			b.WriteByte(c)
			continue
		}
		i++
		switch e := line[i]; e {
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e', 'E':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case 'c':
			if i+1 < len(line) {
				i++
				b.WriteByte(line[i] & 0x1f)
			}
		case 'x', 'u', 'U':
			k := span(i+1, map[byte]int{'x': 2, 'u': 4, 'U': 8}[e], isHex)
			if k == i+1 {
				b.WriteByte('\\')
				b.WriteByte(e)
				continue
			}
			v, _ := strconv.ParseUint(line[i+1:k], 16, 32)
			if e == 'x' {
				b.WriteByte(byte(v))
			} else if v <= utf8.MaxRune {
				b.WriteRune(rune(v))
			}
			i = k - 1
		default:
			if isOct(e) {
				k := span(i, 3, isOct)
				v, _ := strconv.ParseUint(line[i:k], 8, 32)
				b.WriteByte(byte(v))
				i = k - 1
				continue
			}
			if e != '\\' && e != '\'' && e != '"' && e != '?' {
				b.WriteByte('\\')
			}
			b.WriteByte(e)
		}
	}
	s, _, _ := strings.Cut(b.String(), "\x00")
	if i >= len(line) {
		i = len(line) - 1
	}
	return s, i
}

// A value the guard checks is known only when every part of it is literal
// or comes from a rule that proves it: a variable the line sets to a known
// value, the environment, the shell's own numbers, mktemp and date. Every
// other part is unknown, and checkWrites refuses a file named with one.

// unknownOutput stands for a command's output the guard cannot know before
// the line runs. withCommandOutput writes it where the output goes, then the
// words the command names (namedWords) for the checks of reads. It is a
// private-use character, which no shell line a person writes holds.
const unknownOutput = "\ue000"

// span is a command output of a line, line[start:end], which runs body;
// quoted says it stands in "...".
type span struct {
	start, end int
	body       string
	quoted     bool
}

// commandOutputs are the outermost $(...) and `...` of line that the shell
// runs: not in '...' and not after a \. One that is not closed runs to the
// end of the line.
func commandOutputs(line string) []span {
	var out []span
	var q byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case c == '\\':
			i++
		case c == '`' || c == '$' && i+1 < len(line) && line[i+1] == '(':
			end, bodyEnd := outputEnd(line, i)
			from := i + 2
			if c == '`' {
				from = i + 1
			}
			out = append(out, span{start: i, end: end, body: line[min(from, bodyEnd):bodyEnd], quoted: q == '"'})
			i = end - 1
		case q == '"':
			if c == '"' {
				q = 0
			}
		case c == '\'' || c == '"':
			q = c
		}
	}
	return out
}

// outputEnd is where the command output that starts at line[i] ends, and
// where its command does. Quotes and nested parentheses count; a case
// pattern's ) ends it early, and the rest is then checked as more of the line.
func outputEnd(line string, i int) (end, bodyEnd int) {
	if line[i] == '`' {
		for j := i + 1; j < len(line); j++ {
			switch line[j] {
			case '\\':
				j++
			case '`':
				return j + 1, j
			}
		}
		return len(line), len(line)
	}
	depth := 1
	var q byte
	for j := i + 2; j < len(line); j++ {
		c := line[j]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case c == '\\':
			j++
		case c == '`':
			e, _ := outputEnd(line, j)
			j = e - 1
		case q == '"':
			if c == '"' {
				q = 0
			}
		case c == '\'' || c == '"':
			q = c
		case c == '(':
			depth++
		case c == ')':
			if depth--; depth == 0 {
				return j + 1, j
			}
		}
	}
	return len(line), len(line)
}

// withCommandOutput is line with each command output in its place as the
// guard can know it before the line runs: the value a rule proves
// (outputValue), or else unknownOutput and the words the command names.
// `cat $(echo ~)/.komando/state.json` reads ~/.komando/state.json.
func withCommandOutput(cl *call, line string, vars lineVars) string {
	return outputsIn(cl, line, vars, 0)
}

func outputsIn(cl *call, line string, vars lineVars, depth int) string {
	spans := commandOutputs(line)
	if len(spans) == 0 {
		return line
	}
	var b strings.Builder
	at := 0
	for _, s := range spans {
		b.WriteString(line[at:s.start])
		at = s.end
		if depth >= 8 {
			b.WriteString(unknownOutput)
			continue
		}
		body := outputsIn(cl, s.body, vars, depth+1)
		// NAME=$(...) is one word, however many blanks the output holds
		assigned := !s.quoted && assignBefore.MatchString(line[:s.start])
		if v, ok := outputValue(cl, body, s.quoted || assigned, vars); ok {
			if assigned {
				v = `"` + v + `"`
			}
			b.WriteString(v)
			continue
		}
		b.WriteString(unknownOutput + namedWords(body))
	}
	b.WriteString(line[at:])
	return b.String()
}

// assignBefore is a line that ends in NAME=, where a command output that
// follows is assigned, not split into words.
var assignBefore = regexp.MustCompile(`(^|[\s;&|(])[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=$`)

// namePrinter is a command that prints the names it is given, or the files
// they lead to.
var namePrinter = regexp.MustCompile(`(?s)^\s*(echo|printf|ls|realpath|readlink|dirname)\b(.*)$`)

// namedWords are the words a namePrinter command names (after printf's
// format when it has a %), without quotes or \, so they keep the quotes of
// the line around them as they are; for any other command "".
func namedWords(body string) string {
	m := namePrinter.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	args := strings.TrimSpace(m[2])
	if m[1] == "printf" {
		if f, rest, ok := strings.Cut(args, " "); ok && strings.Contains(f, "%") {
			args = strings.TrimSpace(rest)
		}
	}
	return strings.NewReplacer(`'`, "", `"`, "", `\`, "", "`", "").Replace(args)
}

// provable is a command whose output ends where the guard reads it ending,
// as the shell does: one simple command without a variable, a command
// output, a redirect, a comment, a \, a glob or a line break.
var provable = regexp.MustCompile(`^[A-Za-z0-9_./~%+:=@, '"-]*$`)

// redefines finds what can make a command's output other than the one
// outputValue proves: a function, an alias, hash, enable, disable, eval,
// source and . (which can define functions), and a change of PATH or
// TMPDIR.
var redefines = regexp.MustCompile(`\b(alias|unalias|hash|enable|disable|eval|source|function|functions|autoload|PATH|path|TMPDIR)\b|[A-Za-z0-9_.:-]\s*\(\s*\)|(^|[;&|(\s])\.\s`)

// outputValue is the output of the command body when a rule proves it
// before the line runs: the file of mktemp (mktempFile), and date's numbers
// (dateOutput). quoted says the output stands in "...".
func outputValue(cl *call, body string, quoted bool, vars lineVars) (string, bool) {
	if _, ok := vars[redefinedVar]; ok || !provable.MatchString(body) ||
		strings.Count(body, "'")%2 != 0 || strings.Count(body, `"`)%2 != 0 {
		return "", false
	}
	words := shellWords(body)
	if len(words) == 0 {
		return "", false
	}
	switch words[0] {
	case "mktemp":
		return mktempFile(cl, words[1:])
	case "date":
		return dateOutput(words[1:], quoted)
	}
	return "", false
}

// plainPath is a value that keeps its meaning written into a shell line.
var plainPath = regexp.MustCompile(`^[A-Za-z0-9_./~%+:=@,-]+$`)

// mktempFile is the file mktemp ARGS makes: TEMPLATE, in -p DIR or the
// temporary folder with -t or with no template.
func mktempFile(cl *call, args []string) (string, bool) {
	dir, tmpl, inTmp := "", "", false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case (a == "-p" || a == "--tmpdir") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-"):
			dir, inTmp = args[i+1], true
			i++
		case strings.HasPrefix(a, "--tmpdir="):
			dir, inTmp = strings.TrimPrefix(a, "--tmpdir="), true
		case a == "-t":
			inTmp = true
		case strings.HasPrefix(a, "-"):
		default:
			tmpl = a
		}
	}
	if dir == "" && (inTmp || tmpl == "") {
		if dir = cl.getenv("TMPDIR"); dir == "" {
			dir = os.TempDir()
		}
	}
	if tmpl == "" {
		tmpl = "tmp.XXXXXXXXXX"
	}
	p := tmpl
	if dir != "" {
		p = filepath.Join(dir, tmpl)
	}
	return p, plainPath.MatchString(p)
}

// dateNumbers are the date conversions that print digits and - : + only.
const dateNumbers = "CdFgGHIjmMsSTuUVwWyYz"

// dateOutput is what date ARGS prints when ARGS are -u and one +FORMAT of
// dateNumbers and plain characters. Each conversion is a * outside quotes,
// so the checks try every value it may have.
func dateOutput(args []string, quoted bool) (string, bool) {
	format, seen := "", false
	for _, a := range args {
		switch {
		case a == "-u" || a == "--utc" || a == "--universal":
		case strings.HasPrefix(a, "+") && !seen:
			format, seen = a[1:], true
		default:
			return "", false
		}
	}
	if !seen {
		return "", false
	}
	star := "*"
	if quoted {
		star = `"*"`
	}
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			b.WriteByte(format[i])
			continue
		}
		if i+1 == len(format) || !strings.ContainsRune(dateNumbers, rune(format[i+1])) {
			return "", false
		}
		b.WriteString(star)
		i++
	}
	return b.String(), true
}

// lineVars are the values the variables a shell line sets may have for its
// later commands. A name whose value the guard cannot know (read NAME,
// NAME=$(command)) maps to nil. redefinedVar, anyVar and aliasVar are keys
// no variable has: the line can change what a command name runs
// (redefines), it ran code that can set any variable (eval, source, a trap,
// a name reference), and a command name may be an alias, so the program of
// a command is not known. aliasFrom holds where the line made an alias:
// the shell reads a line whole before it runs it, so the alias counts from
// the next line on.
type lineVars map[string][]string

const (
	redefinedVar = "\x00redefined"
	anyVar       = "\x00any"
	aliasVar     = "\x00alias"
	aliasFrom    = "\x00alias-from"
)

// aliasAt notes that the command of a line that ends at end can make a
// command name an alias.
func (v lineVars) aliasAt(end int) {
	_, on := v[aliasVar]
	if _, noted := v[aliasFrom]; !on && !noted {
		v[aliasFrom] = []string{strconv.Itoa(end)}
	}
}

// aliasesFrom turns a noted alias on for a command of line that starts at
// start on a later line, or for code read later (start < 0: an eval's or a
// shell's script).
func (v lineVars) aliasesFrom(line string, start int) {
	at, ok := v[aliasFrom]
	if !ok || len(at) != 1 {
		return
	}
	n, _ := strconv.Atoi(at[0])
	if start < 0 || n <= start && strings.Contains(line[n:start], "\n") {
		v[aliasVar] = nil
		delete(v, aliasFrom)
	}
}

// lostDir is the working folder after a cd the guard cannot follow
// (cd -, cd "$DIR" with an unknown DIR): a path relative to it is unknown.
const lostDir = "\x00"

// varRef is a variable's value in a word: $NAME, ${...}, $1, $@ and the like.
var varRef = regexp.MustCompile(`\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])`)

var varName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// zshDollar finds the forms zsh gives a value other than the variable's
// own: $=NAME, $~NAME, $^NAME and $+NAME (split, used as a glob, spread,
// set or not), and $NAME[...] and $NAME:MOD (a part of it, or a change
// such as :h, :r or :s/a/b/).
var zshDollar = regexp.MustCompile(`\$[=~^+]+[A-Za-z_{(]|\$[A-Za-z_][A-Za-z0-9_]*[\[:]|\$\{[A-Za-z_][A-Za-z0-9_]*\}[\[:]`)

// shellNumbers are the parameters the shell sets to a number; [0-9]* stands
// for every value they may have.
var shellNumbers = map[string]bool{"$": true, "?": true, "#": true, "!": true, "RANDOM": true, "SRANDOM": true,
	"SECONDS": true, "EPOCHSECONDS": true, "EPOCHREALTIME": true, "LINENO": true, "BASHPID": true, "PPID": true,
	"UID": true, "EUID": true, "HISTCMD": true}

// shellOwn are variables the shell sets itself, whatever the environment
// the guard sees holds ($_ is the last word of the command before).
var shellOwn = map[string]bool{"_": true, "OLDPWD": true, "SHLVL": true, "REPLY": true, "OPTARG": true, "OPTIND": true,
	"BASH_COMMAND": true, "BASH_SOURCE": true, "BASH_ARGV0": true, "FUNCNAME": true, "MATCH": true, "MAPFILE": true,
	"PIPESTATUS": true}

// maxValues is the most values the guard follows for one word; past it the
// word is unknown.
const maxValues = 64

// expand gives the values the word w, run in cwd, may have when the line
// runs, and whether the guard knows them all. A command output it cannot
// know, a variable no rule gives a value and a ${...} with more than a name
// in it are unknown; for the checks of reads such a part is tried as itself
// and as empty. A variable's value also gives the fields the shell may
// split it into.
func (v lineVars) expand(cl *call, w, home, cwd string) (words []string, known bool) {
	known = !strings.Contains(w, unknownOutput)
	w = strings.ReplaceAll(w, unknownOutput, "")
	for rest := w; known; {
		j := strings.Index(rest, "${")
		if j < 0 {
			break
		}
		if loc := varRef.FindStringIndex(rest[j:]); loc == nil || loc[0] != 0 {
			known = false // a ${ the guard does not read to its }
		}
		rest = rest[j+2:]
	}
	known = known && !zshDollar.MatchString(w)
	split := false
	var walk func(s string, from, n int)
	walk = func(s string, from, n int) {
		loc := varRef.FindStringSubmatchIndex(s[from:])
		if loc == nil || n == 8 || len(words) >= maxValues {
			known = known && loc == nil
			words = append(words, s)
			return
		}
		start, end := from+loc[0], from+loc[1]
		name := strings.TrimSuffix(strings.TrimPrefix(s[from+loc[2]:from+loc[3]], "{"), "}")
		split = true
		vals, ok := v.values(cl, name, home, cwd)
		if !ok {
			known = false
			walk(s, end, n+1)
			vals = []string{""}
		}
		for _, val := range vals {
			walk(s[:start]+val+s[end:], start+len(val), n+1)
		}
	}
	walk(w, 0, 0)
	if split {
		var ok bool
		words, ok = v.fields(words)
		known = known && ok
	}
	if len(words) > maxValues {
		words, known = words[:maxValues], false
	}
	return words, known
}

// fields adds to vals the fields the shell may split them into: at blanks,
// and at each character of an IFS value the line sets. An IFS the guard
// cannot know leaves them unknown.
func (v lineVars) fields(vals []string) ([]string, bool) {
	seps := " \t\n"
	if ifs, ok := v["IFS"]; ok {
		if ifs == nil {
			return vals, false
		}
		seps += strings.Join(ifs, "")
	}
	out := vals
	for _, val := range vals {
		if f := strings.FieldsFunc(val, func(r rune) bool { return strings.ContainsRune(seps, r) }); len(f) > 1 {
			out = append(out, f...)
		}
	}
	return out, true
}

// values are the values name may have when the line uses it, and whether
// the guard knows them: what the line set it to, the shell's own numbers,
// $PWD, the home folders and the environment.
func (v lineVars) values(cl *call, name, home, cwd string) ([]string, bool) {
	if vals, ok := v[name]; ok {
		return vals, vals != nil
	}
	if _, ok := v[anyVar]; ok && !shellNumbers[name] {
		return nil, false
	}
	switch {
	case shellNumbers[name]:
		return []string{"[0-9]*"}, true
	case name == "PWD":
		return []string{cwd}, cwd != "" && cwd != lostDir
	case name == "HOME":
		return []string{home}, true
	case name == homeVar:
		if h := cl.getenv(homeVar); h != "" {
			return []string{h}, true
		}
		return []string{filepath.Join(home, ".komando")}, true
	case shellOwn[name] || !varName.MatchString(name):
		return nil, false
	}
	if val := cl.getenv(name); val != "" {
		return []string{val}, true
	}
	return nil, false
}

// set adds vals to name's values, or makes them unknown: an assignment may
// not run (false && f=x, (f=x), x | f=x), so it never replaces a value the
// line set. A name the line has not set yet starts from its value before
// the line, or from "" when the environment does not hold it, unless sure
// says the assignment runs (surelyRuns) and no code the guard does not read
// ran before it.
func (v lineVars) set(cl *call, name string, vals []string, known, sure bool, home, cwd string) {
	old, ok := v[name]
	if _, any := v[anyVar]; !ok && sure && !any {
		old, ok = []string{}, true
	}
	if !ok {
		var had bool
		old, had = v.values(cl, name, home, cwd)
		_, any := v[anyVar]
		switch {
		case had:
		case !any && varName.MatchString(name) && !shellOwn[name]:
			old = []string{""}
		default:
			old = nil
		}
	}
	if old == nil || !known {
		v[name] = nil
		return
	}
	all := slices.Clone(old)
	for _, x := range vals {
		if !slices.Contains(all, x) {
			all = append(all, x)
		}
	}
	if len(all) > maxValues {
		all = nil
	}
	v[name] = all
}

// mayNotRun finds, before a command of a line, what can skip it, run it in
// a subshell or make it data: && || | & ( ) { } < > # ` and the words of
// compound commands.
var mayNotRun = regexp.MustCompile("[&|(){}<>#`]|\\b(if|then|else|elif|while|until|do|case|for|select|function)\\b")

// surelyRuns says whether the command line[start:end] runs in this shell
// before the commands after it: nothing before it can skip it or put it in
// a subshell, and it is not piped or put in the background.
func surelyRuns(line string, start, end int) bool {
	after := strings.TrimLeft(line[min(end, len(line)):], " \t")
	return !mayNotRun.MatchString(line[:max(0, start)]) && !strings.HasPrefix(after, "|") && !strings.HasPrefix(after, ")") &&
		(!strings.HasPrefix(after, "&") || strings.HasPrefix(after, "&&"))
}

// forget: the line ran code that can set any variable, so the guard knows
// none from here on.
func (v lineVars) forget() {
	for k := range v {
		if k != redefinedVar && k != aliasVar && k != aliasFrom {
			v[k] = nil
		}
	}
	v[anyVar] = nil
}

// assignExpansion is ${NAME:=VALUE}, ${NAME=VALUE} or zsh's ${NAME::=VALUE}:
// it sets NAME wherever it stands. zsh's flags, as in ${(A)NAME::=...}, and
// an element NAME[i] leave the value unknown.
var assignExpansion = regexp.MustCompile(`\$\{(\([^)]*\))?([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?:{0,2}=([^}]*)`)

// learn notes what the command seg of line sets for the commands after it.
// seg ends at line[end:]; words are its words. In NAME=$(mktemp) the shell
// line is cut where the command output starts: seg ends at NAME=.
func (v lineVars) learn(cl *call, line, seg string, end int, home, cwd string, words []string) {
	prog, args := program(words)
	after := line[min(end, len(line)):]
	cut := strings.HasPrefix(after, "$(") || strings.HasPrefix(after, "`")
	sure := surelyRuns(line, end-len(seg), end)
	for _, m := range assignExpansion.FindAllStringSubmatch(seg, -1) {
		vals, known := v.expand(cl, m[4], home, cwd)
		v.set(cl, m[2], vals, known && m[1] == "" && m[3] == "", false, home, cwd)
	}
	assign := func(w string, last bool) {
		name, val, _ := strings.Cut(w, "=")
		if !varName.MatchString(name) {
			if i := strings.IndexAny(name, "+["); i > 0 {
				v.set(cl, name[:i], nil, false, false, home, cwd) // NAME+=value, NAME[i]=value
			}
			return
		}
		// NAME="$(...)" ends the segment at NAME=" as NAME=$(...) does at NAME=
		quoted := strings.HasSuffix(seg, `"`)
		if last && val == "" && strings.HasSuffix(strings.TrimSuffix(seg, `"`), "=") {
			switch {
			case strings.HasPrefix(after, "("): // NAME=(...): an array
				v.set(cl, name, nil, false, sure, home, cwd)
				return
			case cut:
				out, ok := "", false
				if o := commandOutputs(after); len(o) > 0 && o[0].start == 0 {
					out, ok = outputValue(cl, o[0].body, false, v)
					rest := after[o[0].end:]
					if quoted {
						ok = ok && strings.HasPrefix(rest, `"`)
						rest = strings.TrimPrefix(rest, `"`)
					}
					ok = ok && (rest == "" || strings.ContainsRune(" \t\n;&|)", rune(rest[0])))
				}
				v.set(cl, name, []string{out}, ok, sure, home, cwd)
				return
			}
		}
		vals, known := v.expand(cl, val, home, cwd)
		v.set(cl, name, vals, known && !(last && cut), sure, home, cwd)
	}
	switch {
	case prog == "":
		for i, w := range words {
			if envAssign.MatchString(w) {
				assign(w, i == len(words)-1)
			}
		}
	case prog == "export" || prog == "local" || prog == "declare" || prog == "readonly" || prog == "typeset" || prog == "nameref":
		if prog == "nameref" || (prog == "local" || prog == "declare" || prog == "typeset") && slices.ContainsFunc(args, nameRefFlag) {
			v.forget() // NAME is another variable's name: a value set through it is not followed
		}
		for i, a := range args {
			if envAssign.MatchString(a) {
				assign(a, i == len(args)-1)
			}
		}
	case (prog == "for" || prog == "select") && len(args) > 2 && args[1] == "in":
		var vals []string
		known := !cut
		for _, a := range args[2:] {
			x, k := v.expand(cl, a, home, cwd)
			vals, known = append(vals, x...), known && k
		}
		v.set(cl, args[0], vals, known, false, home, cwd)
	case prog == "eval" || prog == "source" || prog == ".":
		v.forget()
		v.aliasAt(end) // the code can make aliases too
	case prog == "trap" && trapRunsAnyTime(args):
		v.forget()
	case prog == "alias" && slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, "=") }):
		v.aliasAt(end)
	default:
		for _, n := range setNames(prog, args) {
			v.set(cl, n, nil, false, false, home, cwd)
		}
	}
}

// nameRefFlag is declare's, typeset's or local's -n: NAME=OTHER makes NAME
// another name of OTHER.
func nameRefFlag(a string) bool {
	return len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a, 'n')
}

// trapScript is the command trap ARGS runs, or "": trap -p, trap -l and
// trap - SIGNAL run none.
func trapScript(args []string) string {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) < 2 || args[0] == "-" || strings.HasPrefix(args[0], "-") && len(args[0]) == 2 {
		return ""
	}
	return args[0]
}

// trapRunsAnyTime says whether trap ARGS sets a command that can run before
// a later command of the line: on any signal but EXIT.
func trapRunsAnyTime(args []string) bool {
	if trapScript(args) == "" {
		return false
	}
	start := 1
	if args[0] == "--" {
		start = 2
	}
	for _, s := range args[start:] {
		if s != "EXIT" && s != "0" && s != "SIGEXIT" {
			return true
		}
	}
	return false
}
