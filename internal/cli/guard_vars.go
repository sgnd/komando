package cli

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/store"
)

// The guard reads a word the way the shell will run it: $'...' and $"..."
// decoded, brace lists expanded, and a variable set earlier on the line in
// place of its name.

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
// outputValue proves: alias, unalias, hash, enable, disable, eval, source,
// . and the like as a command (after a separator, a keyword or a command
// word such as command or builtin), a function, and PATH, path or TMPDIR
// set, unset or declared. The same words as text or as a value read
// ($TMPDIR, find ., source-parser.ts) change nothing.
var redefines = regexp.MustCompile(`(^|[;&|\n(){}\x60!]|\b(then|do|else|elif|if|while|until|time|command|builtin|exec|coproc|nocorrect|noglob)\s)\s*(alias|unalias|hash|rehash|enable|disable|eval|source|function|functions|autoload|zmodload)(\s|$)` +
	`|(^|[;&|\n({]|\b(then|do|else|elif|if|while|until|time|command|builtin|exec)\s)[ \t]*\.(\s|$)` +
	`|(^|[;&|\n{(])\s*[A-Za-z0-9_.:-]+\s*\(\s*\)` +
	`|(^|[\s;&|(])(PATH|path|TMPDIR)\+?=` +
	`|\b(unset|export|readonly|declare|typeset|local)\b[^;&|\n]*\b(PATH|path|TMPDIR)\b`)

// outputValue is the output of the command body when a rule proves it
// before the line runs: the file of mktemp (mktempFile), and date's numbers
// (dateOutput). quoted says the output stands in "...".
func outputValue(cl *call, body string, quoted bool, vars lineVars) (string, bool) {
	if _, ok := vars[redefinedVar]; ok || !provable.MatchString(body) ||
		strings.Count(body, "'")%2 != 0 || strings.Count(body, `"`)%2 != 0 {
		return "", false
	}
	words := shellWords(body)
	if len(words) == 0 || !runsTrusted(cl, words[0]) {
		return "", false
	}
	switch filepath.Base(words[0]) {
	case "mktemp":
		return mktempFile(cl, words[1:])
	case "date":
		return dateOutput(words[1:], quoted)
	}
	return "", false
}

// trustedPrograms are where mktemp and date live on macOS, one path each.
// Their output is proven only when the name runs that program, links
// followed (where /bin leads to /usr/bin, both names run it): a program of
// the same name earlier in PATH, or at another path, is another program.
var trustedPrograms = map[string][]string{"mktemp": {"/usr/bin/mktemp"}, "date": {"/bin/date"}}

// runsTrusted says whether the word name, a command's first word, runs one
// of the trustedPrograms: looked up in the call's PATH as the shell does,
// links followed.
func runsTrusted(cl *call, name string) bool {
	want, ok := trustedPrograms[filepath.Base(name)]
	if !ok {
		return false
	}
	p := name
	if !strings.Contains(name, "/") {
		p = ""
		for _, d := range filepath.SplitList(cl.getenv("PATH")) {
			if !filepath.IsAbs(d) {
				return false // a relative folder: the line can put a program there
			}
			if fi, err := os.Stat(filepath.Join(d, name)); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
				p = filepath.Join(d, name)
				break
			}
		}
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return false
	}
	for _, w := range want {
		if r, err := filepath.EvalSymlinks(w); err == nil && r == real {
			return true
		}
	}
	return false
}

// namesTrusted says whether line names mktemp or date other than as the
// program of a command: it may write a program of that name where PATH
// finds it before the line runs it.
func namesTrusted(line string) bool {
	for _, seg := range splitShell(line) {
		words := shellWords(seg)
		prog, _ := program(words)
		for _, w := range words {
			if _, ok := trustedPrograms[filepath.Base(w)]; ok && w != prog {
				return true
			}
		}
	}
	return false
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

// maxBraceNames is the most names the guard reads from the brace lists of
// one word.
const maxBraceNames = 64

// braceLimitWhy is why a word whose brace lists give more names is
// refused: the names past the limit would go unread.
var braceLimitWhy = fmt.Sprintf("a brace list of more than %d names, more than komando's guard reads", maxBraceNames)

// expandBraces turns a{b,c}d into abd and acd, as the shell does. whole is
// false when w gives more than maxBraceNames names: names then holds only
// some of them, and the caller refuses w.
func expandBraces(w string) (names []string, whole bool) {
	whole = braceNames(w, 0, &names)
	return names, whole
}

// braceNames adds the names w gives to names, list by list from the left,
// and says whether they stay within maxBraceNames. Each list on the way
// gives a name of its own, so depth lists give more than depth names.
func braceNames(w string, depth int, names *[]string) bool {
	open, end, cuts := braceList(w)
	switch {
	case open < 0 && len(*names) == maxBraceNames, open >= 0 && depth == maxBraceNames:
		return false
	case open < 0:
		*names = append(*names, w)
		return true
	}
	start := open + 1
	for _, c := range append(cuts, end) {
		if !braceNames(w[:open]+w[start:c]+w[end+1:], depth+1, names) {
			return false
		}
		start = c + 1
	}
	return true
}

// braceList finds the list the shell expands first in w: the leftmost {
// whose matching } holds a comma at its own level. cuts are those commas;
// open is -1 when w has no list. A { that pairs with no } is a letter, and
// so is a pair without a comma: {x}{a,b} gives {x}a and {x}b.
func braceList(w string) (open, end int, cuts []int) {
	type frame struct {
		open int
		cuts []int
	}
	var stack []frame
	open = -1
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case '{':
			stack = append(stack, frame{open: i})
		case ',':
			if n := len(stack); n > 0 {
				stack[n-1].cuts = append(stack[n-1].cuts, i)
			}
		case '}':
			n := len(stack)
			if n == 0 {
				continue
			}
			f := stack[n-1]
			stack = stack[:n-1]
			if len(f.cuts) > 0 && (open < 0 || f.open < open) {
				open, end, cuts = f.open, i, f.cuts
			}
		}
	}
	return open, end, cuts
}

// treeWord is one argument as the program gets it, whether the shell reads
// it as a glob, and the index of the word of the line it comes from.
type treeWord struct {
	w    string
	glob bool
	arg  int
}

// treeLines are the argument lists the program may get, so `rm {-rf,~}` and
// `f=-rf; rm $f ~` give their options: one list for each choice among the
// values the guard knows a word may have, a value both whole (quoted, or
// in zsh) and split at the line's separators, brace lists expanded. Past 64
// choices one list holds every value, and flat is set. whole is false when
// a brace list gives more names than the guard reads. A word with a part
// the guard cannot know gives its values with that part as written and as
// empty: checkWritten refused one that ends in the part, and
// checkTreeChange one whose fixed rest can name a folder that holds a
// protected path (unknownFolderReaches).
func treeLines(cl *call, args []string, globs []bool, vars lineVars, home, cwd string) (lines [][]treeWord, flat, whole bool) {
	seps, _ := vars.separators()
	lines, all := [][]treeWord{nil}, []treeWord(nil)
	for i, a := range args {
		vals, _ := vars.expand(cl, a, home, cwd)
		var alts [][]treeWord
		for _, v := range vals {
			ways := [][]string{{v}}
			if f := splitAt(v, seps); v != a && !slices.Equal(f, ways[0]) {
				ways = append(ways, f)
			}
			for _, fields := range ways {
				var seq []treeWord
				for _, f := range fields {
					glob := globs[i] || v != a && wordHasGlob(f)
					pats := []string{f}
					if glob && strings.Contains(f, "{") {
						if pats, whole = expandBraces(f); !whole {
							return nil, false, false
						}
					}
					for _, p := range pats {
						seq = append(seq, treeWord{p, glob && wordHasGlob(p), i})
					}
				}
				alts, all = append(alts, seq), append(all, seq...)
			}
		}
		if lines == nil || len(lines)*len(alts) > 64 {
			lines = nil // too many choices: all holds every value
			continue
		}
		var next [][]treeWord
		for _, l := range lines {
			for _, s := range alts {
				next = append(next, append(slices.Clone(l), s...))
			}
		}
		lines = next
	}
	if lines == nil {
		return [][]treeWord{all}, true, true
	}
	return lines, false, true
}

// unknownShapes are the shapes of the word a (vars.shapes) with a part the
// guard cannot know before the line runs: an unknown value, or a relative
// name after a cd it could not follow (lostDir).
func unknownShapes(cl *call, a string, vars lineVars, home, cwd string) []string {
	vals, known := vars.expand(cl, a, home, cwd)
	var out []string
	if !known {
		shapes, ok := vars.shapes(cl, a, home, cwd)
		if !ok {
			return []string{unknownOutput}
		}
		out = shapes
	}
	if cwd == lostDir {
		for _, v := range vals {
			if v != "" && !strings.HasPrefix(v, "-") && !filepath.IsAbs(guardPath(cl, v, home)) {
				out = append(out, unknownOutput+"/"+v)
			}
		}
	}
	return out
}

// unknownFolderReaches says whether the shape s, its unknown parts written
// as unknownOutput, can name a folder that is or holds a protected path:
// the unknown part stands for any folder, so the fixed path after the last
// one must not end the path of such a folder (holderFolders).
func unknownFolderReaches(cl *call, s, home string, vars lineVars) bool {
	k := strings.LastIndex(s, unknownOutput)
	if k < 0 {
		return false
	}
	if _, known := vars.agentFolders(); !known {
		return true // without the project in use, any folder may hold an agent's own
	}
	rest := filepath.ToSlash(s[k+len(unknownOutput):])
	if !strings.HasPrefix(rest, "/") {
		rest = "*" + rest // the unknown part ends inside the last name
	}
	tail := strings.Split(strings.Trim(path.Clean(rest), "/"), "/")
	for len(tail) > 0 && (tail[0] == ".." || tail[0] == "." || tail[0] == "") {
		tail = tail[1:]
	}
	if len(tail) == 0 {
		return true // the unknown folder itself
	}
	fold := func(s string) string {
		if caseFoldFS {
			return foldCase(s)
		}
		return s
	}
	for _, d := range holderFolders(cl, home, vars) {
		dc := strings.Split(fold(filepath.ToSlash(d)), "/")
		if len(dc) < len(tail) {
			continue
		}
		dc = dc[len(dc)-len(tail):]
		match := true
		for j, t := range tail {
			if ok, err := path.Match(fold(t), dc[j]); err == nil && !ok {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// holderFolders are the folders the folder rule refuses by what they are
// or hold (touchesProtected): the protected folders, komando's data, the
// agent's own settings folders, the komando programs the guard hook runs,
// and each folder above them, as named and as their links lead.
func holderFolders(cl *call, home string, vars lineVars) []string {
	roots := append(protectedDirs(cl, home), store.Home())
	for dir := range hookSettingFiles {
		roots = append(roots, filepath.Join(home, dir))
	}
	inUse, _ := vars.agentFolders()
	roots = append(append(roots, inUse...), guardPrograms()...)
	var out []string
	for _, r := range withReal(nil, roots...) {
		for d := r; ; d = filepath.Dir(d) {
			out = append(out, d)
			if d == filepath.Dir(d) {
				break
			}
		}
	}
	return out
}

// treeTargets are the paths the word v, its brace lists expanded
// (treeLines), names: a glob's names as they are now; past 500 of them,
// the folder the glob starts in stands for the rest.
func treeTargets(cl *call, v string, glob bool, home, cwd string) []string {
	p := guardPathAt(cl, v, home, cwd)
	out := []string{p}
	if !glob {
		return out
	}
	m, _ := filepath.Glob(p)
	for i, f := range m {
		if i == 500 {
			dir := p
			for wordHasGlob(dir) && dir != filepath.Dir(dir) {
				dir = filepath.Dir(dir)
			}
			return append(out, dir)
		}
		if shellGlobMatches(p, f) {
			out = append(out, f)
		}
	}
	return out
}
