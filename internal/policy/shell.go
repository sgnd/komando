package policy

import (
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Token is one word of a shell command line, with its quotes removed, or an
// operator: ; | || & && ( ) or a redirect (> >> >| &> &>> <> >& < << <<< <&).
// A line break and ;; are both ";".
type Token struct {
	Text   string
	Op     bool
	Quoted bool // the word had quotes or backslashes in it
	// Expands: the word has a $ or ` the shell expands when it runs (a
	// variable, $1, a command substitution), so its value is not Text
	Expands bool
}

// Sub stands in a word for a command substitution: $( ), ` `, <( ) or >( ).
const Sub = "$(...)"

// Tokens splits a shell command line the way bash reads it, closely enough
// for the safety checks: quotes and backslashes are removed, $'...' is
// decoded, and the text of each command substitution is a command line of
// its own, returned after the first one (the word that held it shows Sub).
// Comments are left out, and so is the body of a here-document (only the
// $( ) and ` ` in an unquoted one are kept, as lines of their own).
// It never fails: text it cannot read stays words, which the checks treat
// with suspicion; Lex says what it could not read.
func Tokens(s string) [][]Token {
	lines, _ := Lex(s)
	return lines
}

// Lex is Tokens, and also says what it could not read: an unclosed quote,
// ` or $( ). Bash refuses such a line, or reads it in a way the checks may
// not, so a check that must be sure treats it as unknown.
func Lex(s string) ([][]Token, string) {
	l := &lexer{s: s}
	first := l.line(false)
	return append([][]Token{first}, l.subs...), l.bad
}

type lexer struct {
	s        string
	i        int
	subs     [][]Token
	bad      string    // the first thing it could not read
	heredocs []heredoc // started on this line; the bodies come after it
}

type heredoc struct {
	delim         string
	quoted, strip bool // <<'EOF': no substitutions; <<-: leading tabs go
}

func (l *lexer) fail(what string) {
	if l.bad == "" {
		l.bad = what
	}
}

// cmdKeywords come before a command, so the word after them is in command
// position (case is a keyword only there).
var cmdKeywords = map[string]bool{"then": true, "do": true, "else": true, "elif": true, "if": true,
	"while": true, "until": true, "{": true, "!": true, "time": true}

// line reads tokens up to the end, or in a $( ) up to its closing ).
func (l *lexer) line(inSub bool) []Token {
	var toks []Token
	var cur strings.Builder
	inWord, quoted, expands := false, false, false
	depth := 0     // ( opened in this line
	cases := 0     // case ... esac open in this line: its ) end patterns
	delim := false // the next word ends a here-document
	strip := false
	word := func() {
		if inWord {
			t := Token{Text: cur.String(), Quoted: quoted, Expands: expands}
			start := len(toks) == 0 || toks[len(toks)-1].Op || cmdKeywords[toks[len(toks)-1].Text]
			switch {
			case delim:
				l.heredocs = append(l.heredocs, heredoc{delim: t.Text, quoted: quoted, strip: strip})
				delim = false
			case !quoted && t.Text == "case" && start:
				cases++
			case !quoted && t.Text == "esac" && cases > 0:
				cases--
			}
			toks = append(toks, t)
		}
		cur.Reset()
		inWord, quoted, expands = false, false, false
	}
	op := func(o string, n int) {
		word()
		toks = append(toks, Token{Text: o, Op: true})
		l.i += n
	}
	s := l.s
	for l.i < len(s) {
		c := s[l.i]
		next := byte(0)
		if l.i+1 < len(s) {
			next = s[l.i+1]
		}
		switch {
		case c == '#' && !inWord: // a comment, to the end of the line
			for l.i < len(s) && s[l.i] != '\n' {
				l.i++
			}
		case c == '\'':
			j := strings.IndexByte(s[l.i+1:], '\'')
			if j < 0 {
				l.fail("an unclosed '")
				j = len(s) - l.i - 1
			}
			cur.WriteString(s[l.i+1 : l.i+1+j])
			inWord, quoted = true, true
			l.i += j + 2
		case c == '"':
			l.i++
			if l.dquote(&cur) {
				expands = true
			}
			inWord, quoted = true, true
		case c == '\\' && next == '\n': // a line continuation
			l.i += 2
		case c == '\\':
			if l.i+1 < len(s) {
				cur.WriteByte(next)
			}
			inWord, quoted = true, true
			l.i += 2
		case c == '$' && next == '\'':
			l.i += 2
			cur.WriteString(l.ansiC())
			inWord, quoted = true, true
		case c == '$' && next == '"':
			l.i += 2
			if l.dquote(&cur) {
				expands = true
			}
			inWord, quoted = true, true
		case c == '$' && next == '(', (c == '<' || c == '>') && next == '(':
			l.i += 2
			l.subs = append(l.subs, l.line(true))
			cur.WriteString(Sub)
			inWord, expands = true, true
		case c == '`':
			l.i++
			l.backquote()
			cur.WriteString(Sub)
			inWord, expands = true, true
		case c == ' ' || c == '\t' || c == '\r':
			word()
			l.i++
		case c == '\n':
			op(";", 1)
			l.heredocBodies()
		case c == ';':
			n := 1
			for n < 3 && l.i+n < len(s) && (s[l.i+n] == ';' || s[l.i+n] == '&') {
				n++
			}
			op(";", n)
		case c == '|':
			switch next {
			case '|':
				op("||", 2)
			case '&':
				op("|", 2)
			default:
				op("|", 1)
			}
		case c == '&':
			switch {
			case next == '&':
				op("&&", 2)
			case next == '>' && l.i+2 < len(s) && s[l.i+2] == '>':
				op("&>>", 3)
			case next == '>':
				op("&>", 2)
			default:
				op("&", 1)
			}
		case c == '(':
			depth++
			op("(", 1)
		case c == ')':
			word() // esac) closes the case first
			if inSub && depth == 0 && cases == 0 {
				l.i++
				return toks
			}
			depth = max(depth-1, 0)
			op(")", 1)
		case c == '<' || c == '>':
			// 2>file, {fd}>file: the word before is the descriptor
			if inWord && !quoted && fdWord(cur.String()) {
				cur.Reset()
				inWord = false
			}
			o := redirectOp(s[l.i:])
			n := len(o)
			doc := o == "<<" || o == "<<-"
			if doc {
				o = "<<"
			}
			op(o, n)
			if doc {
				delim, strip = true, n == 3
			}
		default:
			if c == '$' && next != 0 && strings.IndexByte(" \t\n;&|()<>", next) < 0 {
				expands = true // $NAME, ${NAME}, $1, $@ ...
			}
			cur.WriteByte(c)
			inWord = true
			l.i++
		}
	}
	word()
	if inSub {
		l.fail("an unclosed $(")
	}
	return toks
}

// heredocBodies reads the bodies of the here-documents started on the line
// that just ended. A body is data; in an unquoted one, $( ) and ` ` still
// run, so those are kept as lines of their own.
func (l *lexer) heredocBodies() {
	docs := l.heredocs
	l.heredocs = nil
	for _, d := range docs {
		start := l.i
		end := len(l.s)
		for l.i < len(l.s) {
			nl := strings.IndexByte(l.s[l.i:], '\n')
			line, next := l.s[l.i:], len(l.s)
			if nl >= 0 {
				line, next = l.s[l.i:l.i+nl], l.i+nl+1
			}
			check := strings.TrimSuffix(line, "\r")
			if d.strip {
				check = strings.TrimLeft(check, "\t")
			}
			if check == d.delim {
				end = l.i
				l.i = next
				break
			}
			l.i = next
		}
		if d.quoted {
			continue
		}
		b := &lexer{s: l.s[start:end]}
		for b.i < len(b.s) {
			switch c := b.s[b.i]; {
			case c == '\\':
				b.i += 2
			case c == '$' && b.i+1 < len(b.s) && b.s[b.i+1] == '(':
				b.i += 2
				b.subs = append(b.subs, b.line(true))
			case c == '`':
				b.i++
				b.backquote()
			default:
				b.i++
			}
		}
		l.subs = append(l.subs, b.subs...)
		if b.bad != "" {
			l.fail(b.bad)
		}
	}
}

func redirectOp(s string) string {
	for _, o := range []string{"<<<", "<<-", "<<", "<>", "<&", ">>", ">|", ">&"} {
		if strings.HasPrefix(s, o) {
			return o
		}
	}
	return s[:1]
}

// fdWord: 2 in 2>file, {fd} in {fd}>file. Only digits or a {name} are a
// descriptor: in echo hi>file the word hi is an argument.
func fdWord(w string) bool {
	if n := len(w); n > 2 && w[0] == '{' && w[n-1] == '}' {
		for i := 1; i < n-1; i++ {
			if c := w[i]; !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 1 && c >= '0' && c <= '9') {
				return false
			}
		}
		return true
	}
	return w != "-" && IsDescriptor(w)
}

// dquote reads a "..." string after its opening quote. In it, \ escapes
// only $ ` " \ and a line break, and $( ) and ` ` still run commands. It
// says whether the string has something the shell expands.
func (l *lexer) dquote(cur *strings.Builder) (expands bool) {
	s := l.s
	for l.i < len(s) {
		c := s[l.i]
		switch {
		case c == '"':
			l.i++
			return expands
		case c == '\\' && l.i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[l.i+1]) >= 0:
			if s[l.i+1] != '\n' {
				cur.WriteByte(s[l.i+1])
			}
			l.i += 2
		case c == '$' && l.i+1 < len(s) && s[l.i+1] == '(':
			l.i += 2
			l.subs = append(l.subs, l.line(true))
			cur.WriteString(Sub)
			expands = true
		case c == '`':
			l.i++
			l.backquote()
			cur.WriteString(Sub)
			expands = true
		default:
			if c == '$' && l.i+1 < len(s) && s[l.i+1] != '"' && s[l.i+1] != ' ' {
				expands = true
			}
			cur.WriteByte(c)
			l.i++
		}
	}
	l.fail(`an unclosed "`)
	return expands
}

// backquote reads a `...` substitution after its opening quote: the text up
// to the closing one, with \$ \` and \\ unescaped, is a command line.
func (l *lexer) backquote() {
	s := l.s
	var b strings.Builder
	for l.i < len(s) && s[l.i] != '`' {
		if s[l.i] == '\\' && l.i+1 < len(s) && strings.IndexByte("$`\\", s[l.i+1]) >= 0 {
			l.i++
		}
		b.WriteByte(s[l.i])
		l.i++
	}
	if l.i >= len(s) {
		l.fail("an unclosed `")
	}
	l.i++
	lines, bad := Lex(b.String())
	l.subs = append(l.subs, lines...)
	if bad != "" {
		l.fail(bad)
	}
}

// ansiC decodes a $'...' string after its opening quote: $'\x72m' is rm.
func (l *lexer) ansiC() string {
	s := l.s
	var b strings.Builder
	digits := func(base, most int) (rune, bool) {
		v, n := 0, 0
		for n < most && l.i < len(s) {
			d := strings.IndexByte("0123456789abcdef", s[l.i]|0x20)
			if d < 0 || d >= base {
				break
			}
			v = v*base + d
			l.i++
			n++
		}
		return rune(v), n > 0
	}
	for l.i < len(s) && s[l.i] != '\'' {
		c := s[l.i]
		l.i++
		if c != '\\' || l.i >= len(s) {
			b.WriteByte(c)
			continue
		}
		e := s[l.i]
		l.i++
		if r := strings.IndexByte("abtnvfr", e); r >= 0 {
			b.WriteByte(byte(7 + r)) // \a=7 \b=8 \t=9 \n=10 \v=11 \f=12 \r=13
			continue
		}
		switch e {
		case 'e', 'E':
			b.WriteByte(27)
		case 'c':
			if l.i < len(s) {
				b.WriteByte(s[l.i] & 0x1f)
				l.i++
			}
		case 'x', 'u', 'U':
			most := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
			if r, ok := digits(16, most); !ok {
				b.WriteString("\\" + string(e))
			} else if e == 'x' {
				b.WriteByte(byte(r))
			} else if utf8.ValidRune(r) {
				b.WriteRune(r)
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			l.i--
			r, _ := digits(8, 3)
			b.WriteByte(byte(r))
		case '\\', '\'', '"', '?':
			b.WriteByte(e)
		default:
			b.WriteByte('\\')
			b.WriteByte(e)
		}
	}
	if l.i >= len(s) {
		l.fail("an unclosed $'")
	}
	l.i++
	return b.String()
}

// IsShell: sh, bash, su ... run the text after -c (or a flag group with c
// in it) as commands, and otherwise a script from a file or their input.
func IsShell(name string) bool { return shells[name] }

// shells run the text after -c (or a flag group with c in it) as commands.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true,
	"mksh": true, "fish": true, "csh": true, "tcsh": true, "rbash": true, "su": true, "runuser": true}

// Plain is the command line as the shell runs it, for matching: quotes and
// backslashes removed, every redirect that writes a file shown as >,
// absolute paths cleaned (//etc, /./etc and /tmp/../etc are /etc), and the
// text of command substitutions, sh -c '...' and eval as lines of their
// own. A word with blanks or operators in it keeps quotes, so text in an
// argument (grep "rm -rf /") does not look like a command.
func Plain(cmd string) string {
	return strings.Join(plainLines(cmd, 0), " ; ")
}

func plainLines(cmd string, depth int) []string {
	var lines []string
	for _, toks := range Tokens(cmd) {
		parts := make([]string, 0, len(toks))
		for i, t := range toks {
			switch {
			case t.Op && (t.Text == ">>" || t.Text == ">|" || t.Text == "&>" || t.Text == "&>>" || t.Text == "<>"):
				parts = append(parts, ">")
			case t.Op && t.Text == ">&" && i+1 < len(toks) && !toks[i+1].Op && !IsDescriptor(toks[i+1].Text):
				parts = append(parts, ">")
			case t.Op:
				parts = append(parts, t.Text)
			default:
				parts = append(parts, plainWord(t.Text))
			}
		}
		lines = append(lines, strings.Join(parts, " "))
		if words, ok := braceWords(toks); ok {
			for i, w := range words {
				words[i] = plainWord(w)
			}
			lines = append(lines, strings.Join(words, " "))
		}
		if depth < 8 {
			for _, s := range scripts(toks) {
				lines = append(lines, plainLines(s, depth+1)...)
			}
		}
	}
	return lines
}

func plainWord(w string) string {
	if strings.HasPrefix(w, "/") && !strings.ContainsAny(w, " \t\n") {
		w = path.Clean(w)
	}
	if w == "" || strings.ContainsAny(w, " \t\n;&|()<>") {
		return "'" + w + "'"
	}
	return w
}

// IsDescriptor: the 2 in >&2, or - (close).
func IsDescriptor(w string) bool {
	if w == "-" {
		return true
	}
	if w == "" {
		return false
	}
	for i := 0; i < len(w); i++ {
		if w[i] < '0' || w[i] > '9' {
			return false
		}
	}
	return true
}

// IsCFlag is -c or a group of short flags with c in it (-ec, -lc).
func IsCFlag(w string) bool {
	if len(w) < 2 || w[0] != '-' || w[1] == '-' {
		return false
	}
	for _, r := range w[1:] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return strings.ContainsRune(w[1:], 'c')
}

// ShellScript reads the arguments of a shell (sh, bash, su ...): the text
// it runs after -c, and the words after that text, which the script gets
// as $0, $1 ... Options may come before and after -c (bash -c -e 'x',
// bash -o pipefail -c -- 'x'). ok is false when there is no -c: the shell
// runs a script from a file or its input.
func ShellScript(name string, args []string) (script string, params []string, ok bool) {
	if name == "su" || name == "runuser" {
		return suScript(args)
	}
	c, opts := false, true
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case opts && a == "--":
			opts = false
		case opts && (a == "-o" || a == "+o" || a == "-O" || a == "+O"):
			i++ // -o pipefail
		case opts && len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			c = c || IsCFlag(a)
		default:
			if !c {
				return "", nil, false // bash FILE ARGS
			}
			return a, args[i+1:], true
		}
	}
	return "", nil, c
}

// suScript: su [-] [USER] -c TEXT. The words that are not options are the
// user and, after it, arguments for the shell.
func suScript(args []string) (script string, params []string, ok bool) {
	var words []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" || a == "--command" || a == "--session-command":
			if i+1 < len(args) {
				script, ok = args[i+1], true
			}
			i++
		case strings.HasPrefix(a, "--command=") || strings.HasPrefix(a, "--session-command="):
			_, script, _ = strings.Cut(a, "=")
			ok = true
		case a == "-s" || a == "--shell" || a == "-g" || a == "--group" || a == "-G" || a == "--supp-group" ||
			a == "-w" || a == "--whitelist-environment" || a == "-u" || a == "--user":
			i++
		case IsCFlag(a) && !strings.HasPrefix(a, "--"):
			if i+1 < len(args) {
				script, ok = args[i+1], true
			}
			i++
		case len(a) > 1 && a[0] == '-':
		case a == "-":
		default:
			words = append(words, a)
		}
	}
	if len(words) > 1 {
		params = words[1:]
	}
	return script, params, ok
}

var paramRe = regexp.MustCompile(`\$(\{([0-9]+|[@*])\}|[0-9@*])`)

// FillParams puts the arguments a script gets ($0, $1, ${2}, $@, $*) into
// its text, for checking it as it runs. A missing one is empty.
func FillParams(script string, params []string) string {
	return paramRe.ReplaceAllStringFunc(script, func(m string) string {
		k := strings.Trim(m, "${}")
		if k == "@" || k == "*" {
			if len(params) < 2 {
				return ""
			}
			return strings.Join(params[1:], " ")
		}
		n := 0
		for _, d := range k {
			n = n*10 + int(d-'0')
		}
		if n < len(params) {
			return params[n]
		}
		return ""
	})
}

// scripts returns the text a line hands to a shell to run: sh -c '...',
// bash -lc "...", su -c '...' and the words after eval. A script that gets
// arguments (sh -c 'rm "$0"' /) is also returned with them filled in.
func scripts(toks []Token) []string {
	var found []string
	shell, eval := -1, -1
	var words []string // the shell's arguments
	end := func(i int) {
		if eval >= 0 && i > eval+1 {
			words := make([]string, 0, i-eval-1)
			for _, t := range toks[eval+1 : i] {
				words = append(words, t.Text)
			}
			found = append(found, strings.Join(words, " "))
		}
		if shell >= 0 {
			if s, params, ok := ShellScript(path.Base(toks[shell].Text), words); ok {
				found = append(found, s)
				if len(params) > 0 {
					found = append(found, FillParams(s, params))
				}
			}
		}
		shell, eval, words = -1, -1, nil
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.Op {
			if t.Text == "<" || t.Text == "<<" || t.Text == "<<<" || t.Text == "<&" || t.Text[0] == '>' || t.Text[0] == '&' && len(t.Text) > 1 && t.Text[1] == '>' || t.Text == "<>" {
				i++ // a redirect does not end the command; its file is not an argument
				continue
			}
			end(i)
			continue
		}
		switch b := path.Base(t.Text); {
		case shell >= 0:
			words = append(words, t.Text)
		case shells[b]:
			shell = i
		case b == "eval" && eval < 0:
			eval = i
		}
	}
	end(len(toks))
	return found
}

// braceWords expands a simple brace list in each word that has one:
// {rm,-rf,/} is rm -rf /, as bash runs it. ok is false when there is none.
func braceWords(toks []Token) (words []string, ok bool) {
	for _, t := range toks {
		open := strings.IndexByte(t.Text, '{')
		close := strings.IndexByte(t.Text, '}')
		if t.Op || t.Quoted || open < 0 || close < open || !strings.Contains(t.Text[open:close], ",") {
			words = append(words, t.Text)
			continue
		}
		ok = true
		for _, alt := range strings.Split(t.Text[open+1:close], ",") {
			words = append(words, t.Text[:open]+alt+t.Text[close+1:])
		}
	}
	return words, ok
}
