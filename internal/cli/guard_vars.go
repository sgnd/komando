package cli

import (
	"os"
	"path/filepath"
	"regexp"
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

// commandOutput is a $(...) or `...` with no $( or ` inside it.
var commandOutput = regexp.MustCompile("\\$\\(([^()`]*)\\)|`([^`]*)`")

// withoutCommandOutput is line with each command's output in its place as
// the guard can know it: the file of $(mktemp ...), nothing for any other.
// `cat ~/.ssh/id_ed$(true)25519` reads ~/.ssh/id_ed25519.
func withoutCommandOutput(cl *call, line string) string {
	for range 8 {
		out := commandOutput.ReplaceAllStringFunc(line, func(m string) string {
			g := commandOutput.FindStringSubmatch(m)
			if p, args := program(shellWords(g[1] + g[2])); filepath.Base(p) == "mktemp" {
				return mktempFile(cl, args)
			}
			return ""
		})
		if out == line {
			break
		}
		line = out
	}
	return line
}

// mktempFile is the file mktemp ARGS makes: TEMPLATE, in -p DIR or the
// temporary folder with -t or with no template.
func mktempFile(cl *call, args []string) string {
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
	if dir == "" {
		return tmpl
	}
	return filepath.Join(dir, tmpl)
}

// lineVars are the values the variables a shell line sets have for its
// later commands: NAME=value, export, local, declare, readonly and typeset
// NAME=value, and a for or select loop's words. A name whose value the
// guard cannot know (read NAME, NAME=$(command)) maps to nil.
type lineVars map[string][]string

// varRef is a variable's value in a word: $NAME, ${...}, $1, $@ and the like.
var varRef = regexp.MustCompile(`\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])`)

var varName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// homeRefs are read by guardPath itself.
var homeRefs = map[string]bool{"HOME": true, "KOMANDO_HOME": true}

// expand gives the words w, run in cwd, can become: each variable in
// place, with each value the line or the environment gives it. A variable
// the guard cannot read stays as it is, and is also tried empty (an unset
// variable is), and known is then false.
func (v lineVars) expand(cl *call, w, cwd string) (words []string, known bool) {
	known = true
	var walk func(s string, from, n int)
	walk = func(s string, from, n int) {
		loc := varRef.FindStringSubmatchIndex(s[from:])
		if loc == nil || n == 8 || len(words) >= 16 {
			words = append(words, s)
			return
		}
		start, end := from+loc[0], from+loc[1]
		name := strings.TrimSuffix(strings.TrimPrefix(s[from+loc[2]:from+loc[3]], "{"), "}")
		vals, ok := v.values(cl, name, cwd)
		if !ok {
			if homeRefs[name] {
				walk(s, end, n+1)
				return
			}
			known = false
			walk(s, end, n+1)
			vals = []string{""}
		}
		for _, val := range vals {
			walk(s[:start]+val+s[end:], start+len(val), n+1)
		}
	}
	walk(w, 0, 0)
	return words, known
}

// values are the values name has, and whether the guard knows them. $$,
// $?, $# and $! are numbers, and $PWD is the working folder.
func (v lineVars) values(cl *call, name, cwd string) ([]string, bool) {
	if vals, ok := v[name]; ok {
		return vals, vals != nil
	}
	switch {
	case name == "$" || name == "?" || name == "#" || name == "!":
		return []string{"0"}, true
	case name == "PWD" && cwd != "":
		return []string{cwd}, true
	}
	if homeRefs[name] || !varName.MatchString(name) {
		return nil, false
	}
	if val := cl.getenv(name); val != "" {
		return []string{val}, true
	}
	return nil, false
}

// learn notes what the command seg of line, read as words, sets for the
// commands after it, run in cwd. next is the line's command after seg: in
// NAME=$(mktemp), seg ends at NAME= and next is mktemp.
func (v lineVars) learn(cl *call, line, seg, next, cwd string, words []string) {
	prog, args := program(words)
	cut := cutByCommand(line, seg)
	set := func(w string, last bool) {
		name, val, _ := strings.Cut(w, "=")
		if !varName.MatchString(name) {
			if i := strings.IndexAny(name, "+["); i > 0 {
				v[name[:i]] = nil // NAME+=value, NAME[i]=value
			}
			return
		}
		if last && cut {
			if p, a := program(shellWords(next)); val == "" && filepath.Base(p) == "mktemp" {
				v[name] = []string{mktempFile(cl, a)}
			} else {
				v[name] = nil
			}
			return
		}
		vals, known := v.expand(cl, val, cwd)
		if !known {
			vals = nil
		}
		v[name] = vals
	}
	switch {
	case prog == "":
		for i, w := range words {
			if envAssign.MatchString(w) {
				set(w, i == len(words)-1)
			}
		}
	case prog == "export" || prog == "local" || prog == "declare" || prog == "readonly" || prog == "typeset":
		for i, a := range args {
			if envAssign.MatchString(a) {
				set(a, i == len(args)-1)
			}
		}
	case (prog == "for" || prog == "select") && len(args) > 2 && args[1] == "in" && !cut:
		var vals []string
		for _, a := range args[2:] {
			x, _ := v.expand(cl, a, cwd)
			vals = append(vals, x...)
		}
		v[args[0]] = vals
	default:
		for _, n := range setNames(prog, args) {
			v[n] = nil
		}
	}
}

// cutByCommand says whether seg, a command of line, stops where a $(...)
// or `...` starts: its last word goes on with that command's output.
func cutByCommand(line, seg string) bool {
	if seg == "" {
		return false
	}
	i := strings.Index(line, seg)
	if i < 0 {
		return false
	}
	rest := line[i+len(seg):]
	return strings.HasPrefix(rest, "$(") || strings.HasPrefix(rest, "`")
}
