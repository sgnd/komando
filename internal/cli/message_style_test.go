package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
)

// The message style (docs/design/message-style.md): every line komando
// writes for a person. These tests read komando's own strings from the
// source with go/ast, as TestErrorCodeCatalog does, and check the [test]
// rules M-1 to M-13. Each starts from an allow-list of the strings that
// break a rule today for a reason (another program's words, a name the
// rule does not know, work left for another change). An entry that no
// longer matches anything fails too, so a list can only shrink.
//
// An allow-list entry is "file: text", the file under internal/ (or
// cmd/) and the first 60 characters of the string as the source writes it
// ({x} for a Go expression in a concatenation). KOMANDO_STYLE_LIST=1
// prints the entries a test would need.

// textRole is what a string is for a person.
type textRole string

const (
	roleMsg    textRole = "message" // error.message, a Go error's text
	roleHint   textRole = "hint"    // error.hint
	roleWarn   textRole = "warning" // cl.out.Warn
	roleStderr textRole = "stderr"  // a line komando writes on stderr for itself
	roleAsk    textRole = "ask"     // a question
	roleHelpQ  textRole = "help"    // the help under a question
	roleUsage  textRole = "usage"   // flag help, Short, Long, Example
)

// styleText is one string komando shows, with where it is.
type styleText struct {
	file  string // under internal/ or cmd/
	line  int
	role  textRole
	text  string   // the whole expression, {x} for what is not a literal
	parts []string // its literals, in order
	first bool     // the expression starts with a literal
	last  bool     // and ends with one
	// pair is the other half of an error: the hint of a message and the
	// message of a hint, when one call gives both
	pair string
	call string // the call that takes it: out.Errf, Say, ...
	// wrapped: printed through sayLine, which wraps it at a terminal only
	wrapped bool
}

func (s styleText) key() string {
	t := s.text
	if utf8.RuneCountInString(t) > 60 {
		t = string([]rune(t)[:60])
	}
	return s.file + ": " + t
}

var (
	styleOnce  []styleText
	styleFiles = map[string]bool{}
)

// styleTexts reads every non-test Go file of komando once.
func styleTexts(t *testing.T) []styleText {
	t.Helper()
	if styleOnce != nil {
		return styleOnce
	}
	for _, root := range []string{"..", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			name := d.Name()
			if d.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") ||
				strings.HasPrefix(name, "cluster_kctl") || name == "errcodes.go" { // kubectl's words (M-15); generated
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel := strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(path), "../../"), "../")
			styleFiles[rel] = true
			styleOnce = append(styleOnce, fileTexts(fset, rel, f)...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(styleOnce) < 3000 {
		t.Fatalf("only %d strings found: is the scan looking at internal/?", len(styleOnce))
	}
	return styleOnce
}

// stderrWriters are the writers that reach the person's stderr.
var stderrWriters = map[string]bool{"os.Stderr": true, "promptW()": true, "cmd.ErrOrStderr()": true, "c.ErrOrStderr()": true,
	// a call's stderr (call.go), also through the struct that keeps the call
	"cl.out.Err": true, "w.cl.out.Err": true, "r.cl.out.Err": true, "p.cl.out.Err": true, "s.cl.out.Err": true, "pr.Stderr()": true,
	// the printer's stderr (internal/out)
	"p.Stderr()": true}

var flagFunc = regexp.MustCompile(`^(String|Bool|Int|Int64|Uint|Duration|Float64|StringSlice|StringArray|StringToString|Count|Var)(Var)?P?$`)

func fileTexts(fset *token.FileSet, rel string, f *ast.File) []styleText {
	var res []styleText
	call := ""
	add := func(e ast.Expr, role textRole, pair ast.Expr) {
		s, ok := exprText(e)
		if !ok {
			return
		}
		s.file, s.line, s.role, s.call = rel, fset.Position(e.Pos()).Line, role, call
		if pair != nil {
			p, _ := exprText(pair)
			s.pair = p.text
		}
		res = append(res, s)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			name := exprName(x.Fun)
			args := x.Args
			call = name
			switch {
			case name == "out.Errf" || name == "Errf" && strings.HasPrefix(rel, "out/"):
				if len(args) >= 4 {
					add(args[2], roleHint, args[3])
					add(args[3], roleMsg, args[2])
				}
			case name == "out.Usage" || name == "fmt.Errorf" || name == "errors.New":
				if len(args) >= 1 {
					add(args[0], roleMsg, nil)
				}
			case strings.HasSuffix(name, ".WithHint"):
				if len(args) == 1 {
					add(args[0], roleHint, nil)
				}
			case strings.HasSuffix(name, ".Say"):
				if len(args) == 2 {
					add(args[0], roleMsg, args[1])
					add(args[1], roleHint, args[0])
				}
			case strings.HasSuffix(name, ".Warn") || name == "Warn":
				if len(args) == 1 {
					add(args[0], roleWarn, nil)
				}
			case name == "sayLine":
				if len(args) == 2 { // sayLine(cl, msg) writes on the call's stderr
					add(args[1], roleStderr, nil)
					if len(res) > 0 && res[len(res)-1].line == fset.Position(args[1].Pos()).Line {
						res[len(res)-1].wrapped = true
					}
				}
			case name == "fmt.Fprintf" || name == "fmt.Fprintln" || name == "fmt.Fprint" || name == "io.WriteString":
				if len(args) >= 2 && stderrWriters[exprName(args[0])] {
					add(args[1], roleStderr, nil)
				}
			case name == "spanText" || name == "durVar":
				if len(args) > 0 {
					add(args[len(args)-1], roleUsage, nil)
				}
			default:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && flagFunc.MatchString(sel.Sel.Name) && len(args) >= 2 &&
					strings.Contains(exprName(sel.X), "lags") || ok && flagFunc.MatchString(sel.Sel.Name) && (exprName(sel.X) == "fl" || exprName(sel.X) == "f") {
					add(args[len(args)-1], roleUsage, nil)
				}
			}
		case *ast.CompositeLit:
			call = "composite"
			var msg, hint ast.Expr
			for _, el := range x.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				k, _ := kv.Key.(*ast.Ident)
				if k == nil {
					continue
				}
				switch k.Name {
				case "Message":
					msg = kv.Value
				case "Hint":
					hint = kv.Value
				case "ask":
					add(kv.Value, roleAsk, nil)
				case "help":
					add(kv.Value, roleHelpQ, nil)
				case "Short", "Long", "Example":
					add(kv.Value, roleUsage, nil)
				}
			}
			if msg != nil {
				add(msg, roleMsg, hint)
			}
			if hint != nil {
				add(hint, roleHint, msg)
			}
		case *ast.AssignStmt:
			call = "="
			if len(x.Lhs) == len(x.Rhs) {
				for i, l := range x.Lhs {
					switch n := exprName(l); {
					case n == "hint" || strings.HasSuffix(n, ".Hint"):
						add(x.Rhs[i], roleHint, nil)
					case strings.HasSuffix(n, ".Message"):
						add(x.Rhs[i], roleMsg, nil)
					}
				}
			}
		}
		return true
	})
	return res
}

// exprName is an expression as the source writes it, for the few shapes the
// scan names (os.Stderr, out.Errf, cmd.ErrOrStderr()).
func exprName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprName(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		return exprName(x.Fun) + "()"
	case *ast.ParenExpr:
		return exprName(x.X)
	}
	return "?"
}

// exprText reads a string expression: a literal, or a + of literals and
// other expressions ({x}). An expression with no literal is not text.
func exprText(e ast.Expr) (styleText, bool) {
	var s styleText
	var walk func(e ast.Expr, pos int)
	var b strings.Builder
	n := 0
	walk = func(e ast.Expr, _ int) {
		if x, ok := e.(*ast.BinaryExpr); ok && x.Op == token.ADD {
			walk(x.X, 0)
			walk(x.Y, 0)
			return
		}
		if x, ok := e.(*ast.ParenExpr); ok {
			walk(x.X, 0)
			return
		}
		n++
		if l, ok := e.(*ast.BasicLit); ok && l.Kind == token.STRING {
			v, err := strconv.Unquote(l.Value)
			if err == nil {
				if n == 1 {
					s.first = true
				}
				s.last = true
				s.parts = append(s.parts, v)
				b.WriteString(v)
				return
			}
		}
		s.last = false
		b.WriteString("{x}")
	}
	walk(e, 0)
	s.text = b.String()
	return s, len(s.parts) > 0
}

// styleCheck fails for each text bad says something about, except the
// allowed ones, and for each allowed entry nothing matches any more.
func styleCheck(t *testing.T, rule string, roles []textRole, allow []string, bad func(s styleText) string) {
	t.Helper()
	allowed := map[string]bool{}
	for _, a := range allow {
		allowed[a] = false
	}
	want := map[textRole]bool{}
	for _, r := range roles {
		want[r] = true
	}
	var need []string
	for _, s := range styleTexts(t) {
		if !want[s.role] {
			continue
		}
		why := bad(s)
		if why == "" {
			continue
		}
		if _, ok := allowed[s.key()]; ok {
			allowed[s.key()] = true
			continue
		}
		need = append(need, s.key())
		t.Errorf("%s:%d: %s (%s): %s %q", s.file, s.line, rule, s.role, why, s.text)
	}
	for a, used := range allowed {
		if !used {
			t.Errorf("%s: the allow-list entry %q matches nothing any more: take it out", rule, a)
		}
	}
	if os.Getenv("KOMANDO_STYLE_LIST") != "" && len(need) > 0 {
		sort.Strings(need)
		var b strings.Builder
		for _, n := range need {
			fmt.Fprintf(&b, "\t%q,\n", n)
		}
		t.Logf("%s allow-list:\n%s", rule, b.String())
	}
}

var (
	// M-1: words that blame or plead; M-6: Latin abbreviations
	blameWords  = regexp.MustCompile(`(?i)\b(invalid|malformed|illegal|forbidden|please|simply|sorry|oops|failed to|unable to)\b|\bbad\b|\bmust\b|\be\.g\.|\bi\.e\.|(^|[^/])\betc\.`)
	closingBang = regexp.MustCompile(`[A-Za-z]!\s*$`)
)

// M-1, M-6: calm and plain words, no e.g., i.e. or etc.
func TestMessageWords(t *testing.T) {
	styleCheck(t, "M-1/M-6", []textRole{roleMsg, roleHint, roleWarn, roleStderr, roleAsk, roleHelpQ, roleUsage}, allowWords, func(s styleText) string {
		for _, p := range s.parts {
			if m := blameWords.FindString(p); m != "" {
				return "says " + strconv.Quote(m)
			}
			if closingBang.MatchString(p) && s.role != roleUsage {
				return `ends in "!"`
			}
		}
		return ""
	})
}

// properStart are the words a fragment may start with in upper case: a
// name, an acronym, a code (M-3).
var properStart = regexp.MustCompile(`^([A-Z][A-Z0-9_]+\b|[A-Z][a-z]*[A-Z]\w*|(AWS|Azure|BigQuery|ClickHouse|Claude|Cloudflare|DNS|Docker|ECR|ESP|Google|GitHub|Helm|IKE|Kafka|Kubernetes|Linux|MongoDB|MySQL|NATS|OpenBao|OpenSSH|OpenVPN|Oracle|PowerShell|PostgreSQL|Pub/Sub|RabbitMQ|Redis|Snowflake|SQL|SQLite|Swarm|Tailscale|Vault|WinRM|Windows|WireGuard)\b)`)

// M-3: a message, hint or warning is a fragment: lower case first, no
// full stop at the end.
func TestMessageCase(t *testing.T) {
	styleCheck(t, "M-3", []textRole{roleMsg, roleHint, roleWarn}, allowCase, func(s styleText) string {
		if strings.HasSuffix(s.call, ".Say") || strings.HasSuffix(s.call, ".Cancel") {
			return "" // a person's words: sentences (M-3, M-14)
		}
		if s.first {
			p := s.parts[0]
			r, _ := utf8.DecodeRuneInString(p)
			if unicode.IsUpper(r) && !properStart.MatchString(p) {
				return "starts upper case"
			}
		}
		if s.last {
			p := s.parts[len(s.parts)-1]
			if strings.HasSuffix(p, ".") && !strings.HasSuffix(p, "..") && !strings.HasSuffix(p, "...") {
				return "ends in a full stop"
			}
		}
		return ""
	})
	styleCheck(t, "M-3", []textRole{roleAsk}, allowAsk, func(s styleText) string {
		if s.last && !strings.Contains(s.text, "?") && !strings.HasSuffix(strings.TrimSpace(s.parts[len(s.parts)-1]), ":") {
			return "a question with no question mark"
		}
		return ""
	})
}

// stderrStart is how a line komando writes for itself on stderr starts
// (M-4): a label of the closed set, a capital, "komando:" where it shares
// the screen with a server, an indent, a prompt line, a line break, or a
// value komando prints as it is.
var stderrStart = regexp.MustCompile(`^(Error:|Stopped|Hint:|Warning:|Note:|Dry run:|Without --dry-run|Skipped|Next:|Next time:|Using|komando:|  |\$ komando|\n|\r|\x1b|%|[A-Z✓✗!●→·…\[(])`)

// M-4: komando's own stderr lines start with a label or a capital.
func TestStderrLabels(t *testing.T) {
	styleCheck(t, "M-4", []textRole{roleStderr}, allowLabels, func(s styleText) string {
		if !s.first || s.parts[0] == "" {
			return ""
		}
		if !stderrStart.MatchString(s.parts[0]) {
			return "starts without a label or a capital"
		}
		return ""
	})
}

var (
	// M-5: komando's words; the allowed senses of host, service and
	// directory are taken out first: a URL's host part, a database
	// account's host, a host key or name, a systemd, Swarm or Kubernetes
	// service, another program's words
	termsAllowed = regexp.MustCompile(`(?i)(komando host|host (key|name|keys|part|port|header)|hosts? file|localhost|--(from-)?host|host:|\bhost\)|:host|known_hosts|/etc/hosts|` +
		`(URL|URL's|endpoint|portal|kubeconfig's server|redirected to another|the same|after the|virtual|account|Vault|to a|a|one) hosts?\b|hosts it may|` +
		`service account|service principal|service name|systemd|unit|kubernetes|swarm|stack|cluster list|windows|Service\b|service/|services? \(|[a-z]+\.service|` +
		`system files or services|Which services|Only services|without services|lists the services|or services|deployments, services|no such file or directory)`)
	termsBanned = regexp.MustCompile(`\binventory\b|\bdirectory\b|\bdirectories\b|\bhost\b|\bhosts\b|\bservice\b|\bservices\b`)
)

// M-5: one term for one thing: server, conn, your list, folder.
func TestMessageTerms(t *testing.T) {
	styleCheck(t, "M-5", []textRole{roleMsg, roleHint, roleWarn, roleAsk, roleHelpQ}, allowTerms, func(s styleText) string {
		for _, p := range s.parts {
			if m := termsBanned.FindString(termsAllowed.ReplaceAllString(p, "")); m != "" {
				return "says " + strconv.Quote(m)
			}
		}
		return ""
	})
}

var (
	jsonPath  = regexp.MustCompile(`\b(data|meta|error)\.[a-z_]+`)
	streamWrd = regexp.MustCompile(`\b(stdin|stdout|stderr)\b`)
)

// M-7: a hint names JSON paths and streams only in parentheses after
// plain words: "(data.results in -o json)", "the error output (stderr)".
func TestHintJargon(t *testing.T) {
	styleCheck(t, "M-7", []textRole{roleHint}, allowJargon, func(s styleText) string {
		for _, p := range s.parts {
			for _, loc := range jsonPath.FindAllStringIndex(p, -1) {
				open := strings.LastIndex(p[:loc[0]], "(")
				end := strings.Index(p[loc[0]:], ")")
				if open < 0 || end < 0 || !strings.Contains(p[open:loc[0]+end], "-o json") {
					return "names " + p[loc[0]:loc[1]] + " outside (... in -o json)"
				}
			}
			for _, loc := range streamWrd.FindAllStringIndex(p, -1) {
				if loc[0] > 0 && p[loc[0]-1] == '-' {
					continue // a flag: --stdin-file
				}
				if loc[0] == 0 || p[loc[0]-1] != '(' || loc[1] >= len(p) || p[loc[1]] != ')' {
					return "names " + p[loc[0]:loc[1]] + " outside parentheses"
				}
			}
		}
		return ""
	})
}

var wayOut = regexp.MustCompile("known|`komando|\\buse\\b|takes|one of|list")

// M-8: "unknown X" only when the line or its hint gives the way out.
func TestUnknownNamesWayOut(t *testing.T) {
	styleCheck(t, "M-8", []textRole{roleMsg}, allowUnknown, func(s styleText) string {
		if !strings.Contains(strings.Join(s.parts, " "), "unknown ") {
			return ""
		}
		if wayOut.MatchString(strings.Replace(s.text, "unknown", "", 1)) || wayOut.MatchString(s.pair) {
			return ""
		}
		return "says unknown and names no known values or command"
	})
}

// M-9: a line komando lays out itself fits in 80 columns; the printer
// wraps errors, hints and warnings and keeps a backticked command whole.
// A message printed through sayLine is wrapped the same way, at a
// terminal only: it is measured unwrapped and is one line, so a pipe, a
// script or an agent reads it whole.
func TestTextWidth(t *testing.T) {
	styleCheck(t, "M-9", []textRole{roleStderr}, allowWidth, func(s styleText) string {
		if s.wrapped {
			if strings.Contains(s.text, "\n") || strings.Contains(s.text, "\r") {
				return "a line break in a message sayLine wraps: write it as one line"
			}
			return ""
		}
		for _, l := range strings.Split(s.text, "\n") {
			if n := utf8.RuneCountInString(strings.ReplaceAll(l, "{x}", "")); n > 80 {
				return fmt.Sprintf("a line of %d columns", n)
			}
		}
		return ""
	})
	cmd := "`komando conn edit prod-db --via bastion --url postgres://app@db.internal:5432/shop`"
	w := out.Wrap(strings.Repeat("check the address and the port first, ", 4)+"then run "+cmd, len("Hint: "), 80)
	for i, l := range strings.Split(w, "\n") {
		n := utf8.RuneCountInString(l)
		if i == 0 {
			n += len("Hint: ")
		}
		if n > 80 && !strings.Contains(l, "`") {
			t.Errorf("Wrap left a line of %d columns: %q", n, l)
		}
	}
	if !strings.Contains(w, cmd) {
		t.Errorf("Wrap broke the command:\n%s", w)
	}
}

var (
	marksOK   = "✓✗●→·…"
	allCapsSt = regexp.MustCompile(`\bFAILED\b|\bBROKEN\b|\bERROR\b|exit=`)
)

// M-10: marks from the table only, status words in lower case.
func TestMarks(t *testing.T) {
	styleCheck(t, "M-10", []textRole{roleMsg, roleHint, roleWarn, roleStderr, roleAsk, roleHelpQ}, allowMarks, func(s styleText) string {
		for _, p := range s.parts {
			for _, r := range p {
				if r > unicode.MaxASCII && unicode.IsSymbol(r) && !strings.ContainsRune(marksOK, r) {
					return "uses the mark " + string(r)
				}
			}
			if m := allCapsSt.FindString(p); m != "" && !codeShape.MatchString(p) {
				return "says " + m
			}
		}
		return ""
	})
}

// verbS: a reason that reads after "This" starts with a verb in -s.
func verbS(reason string) bool {
	first, _, _ := strings.Cut(reason, " ")
	return len(first) > 2 && strings.HasSuffix(first, "s") && first == strings.ToLower(first)
}

// M-11: the reason in a typed question reads after "This": the rule
// table's what and typed, the shell rules and the cache rules.
func TestRiskReasons(t *testing.T) {
	for _, r := range riskRows {
		if r.what != "" && !verbS(r.what) {
			t.Errorf("riskRows %s: what %q does not start with a verb in -s", r.id, r.what)
		}
	}
	for _, r := range policy.Rules() {
		if !verbS(r.Reason) {
			t.Errorf("policy rule %s: %q does not start with a verb in -s", r.ID, r.Reason)
		}
	}
	for _, r := range cachex.Rules() {
		if !verbS(r.Reason) {
			t.Errorf("cache rule %s: %q does not start with a verb in -s", r.ID, r.Reason)
		}
	}
	for _, s := range styleTexts(t) {
		if s.file == "cli/confirm_typed.go" && strings.Contains(s.text, "Dangerous:") {
			t.Errorf("%s:%d: the T3 line is \"This <reason>.\" (dangerLine), not %q", s.file, s.line, s.text)
		}
	}
}

// M-12, M-13: the fixed stop lines, and one note for cut output.
func TestStopLines(t *testing.T) {
	for file, line := range map[string]string{
		"prompter_fill.go": `Cancel("Cancelled. Nothing was changed.")`,
		"common.go":        `Say("Stopped (Ctrl-C) before the end; what already ran stays as it is", "check what it left, then run it again")`,
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), line) {
			t.Errorf("%s: the fixed stop line %s is gone", file, line)
		}
	}
	if b, _ := os.ReadFile("prompter_fill.go"); !strings.Contains(string(b), `Cancel("Stopped. Nothing was run.")`) {
		t.Error(`prompter_fill.go: Ctrl-C at a question reads "Stopped. Nothing was run."`)
	}
	for _, s := range styleTexts(t) {
		if s.role != roleStderr && s.role != roleMsg {
			continue
		}
		lower := strings.ToLower(s.text)
		switch {
		case strings.Contains(lower, "truncated at") || strings.Contains(lower, "of more;"):
			t.Errorf("%s:%d: a cut note reads \"Note: showing the first N; ...\": %q", s.file, s.line, s.text)
		case strings.Contains(lower, "showing the first") && s.role == roleStderr && !strings.HasPrefix(s.text, "Note: showing the first"):
			t.Errorf("%s:%d: a cut note starts \"Note: showing the first\": %q", s.file, s.line, s.text)
		case s.role == roleMsg && strings.HasPrefix(s.text, "Stopped") && !strings.HasPrefix(s.text, "Stopped (Ctrl-C)") && !strings.HasPrefix(s.text, "Stopped. Nothing was run."):
			t.Errorf("%s:%d: a stop line is one of the fixed ones (M-12): %q", s.file, s.line, s.text)
		}
	}
	// a hint is the next step, never a state (M-2)
	for _, s := range styleTexts(t) {
		if s.role == roleHint && s.first && strings.HasPrefix(strings.ToLower(s.parts[0]), "nothing was") {
			t.Errorf("%s:%d: a hint that says a state (put it in the message): %q", s.file, s.line, s.text)
		}
	}
}

// Every error gives a hint (S-8.5, M-2): out.Errf takes one, and an error
// made without one gets the printer's default (hintOrDefault). So no
// out.Errf passes an empty hint.
func TestEveryErrorHasAHint(t *testing.T) {
	styleCheck(t, "S-8.5", []textRole{roleHint}, allowNoHint, func(s styleText) string {
		if (s.call == "out.Errf" || s.call == "Errf") && len(s.parts) == 1 && s.first && s.last && strings.TrimSpace(s.parts[0]) == "" {
			return "an error with an empty hint"
		}
		return ""
	})
}

// The style guide is in the repository.
func TestMessageStyleDoc(t *testing.T) {
	b, err := os.ReadFile("../../docs/design/message-style.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"M-1 ", "M-5 ", "M-9 ", "M-12 ", "M-15 "} {
		if !strings.Contains(string(b), "**"+m) {
			t.Errorf("message-style.md has no rule %s", m)
		}
	}
}

// the allow-lists, by rule
var (
	allowWords = []string{}
	allowCase  = []string{
		"cli/windows_winrm.go: Basic login over plain HTTP sends the password unencrypted", // Basic: the auth scheme's name
		"driver/sql.go: U&\"...\" names are not allowed",                                   // SQL syntax
	}
	allowAsk = []string{
		"cli/form_cluster.go: Swarm only: the stack's name (empty on Kubernetes)", // a field label, not a question
		"cli/form_hints_files.go: Or type the content",                            // the second half of the question before it
	}
	allowLabels = []string{
		"openvpn/client.go: openvpn: {x}\n", // the OpenVPN client's log line, beside the server's (like komando:)
	}
	// M-5: the Swarm and Kubernetes Service, command words, and URL or
	// account placeholders
	allowTerms = []string{
		"cli/cluster_names.go: Swarm has no namespaces: leave out --namespace (a stack's se",
		"cli/cluster_swarm.go: Swarm lists services, tasks, nodes or stacks",
		"cli/cluster_swarm.go: a stack is its services: `komando cluster list %s services -",
		"cli/cluster_swarm.go: list services with `komando cluster list TARGET services`",
		"cli/cluster_swarm.go: list the services with `komando cluster list {x} services`",
		"cli/cluster_swarm.go: list what exists with `komando cluster list {x} services` (o",
		"cli/cluster_objects.go: service %s is global (one task per node); scale works on rep",
		"cli/docker.go: list what exists with `komando docker ps TARGET --all` or `k",
		"cli/form_cluster.go: pods, deployments, services, nodes, ingresses, configmaps ..",
		"cli/host_sshcommand.go: host ssh-command writes a copy of the pinned host keys for O",
		"cli/select.go: unknown kind %q: use host, conn, vpn, a conn kind (see `koma",
		"cli/vpn.go: --server takes a host name or address (host or host:port)",
		"cli/vpn_inv.go: --server takes a host name or address (host or host:port)",
		"dbx/users.go: host %q: a name, an address, or a pattern with %%",
		"driver/driver.go: %s URL needs a user name, for example %s://deploy@host/folde",
		"driver/storage_urls.go: add the user name, for example smb://alice@host/share; a gue",
	}
	allowJargon  = []string{}
	allowUnknown = []string{
		// the hint names the nearest commands or `komando schema`
		"cli/suggest.go: unknown command %q",
		"cli/suggest.go: unknown command %q for %q",
	}
	allowWidth = []string{}
	allowMarks = []string{
		"cli/login_ssh.go: %s ERROR %s\n", // a background program's log line
	}
	allowNoHint = []string{
		"cli/approval_hint.go: ", // approvalErr sets the hint on the next line
	}
)
