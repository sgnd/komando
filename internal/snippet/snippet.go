// Package snippet is the engine of komando's ready-made snippets: a
// built-in, named read or change with one documented JSON shape
// (docs/design/code-layout.md). It holds the Builtin type, the checks of a
// definition, the registry, the filling of a text with quoted variables, the
// parse step and the JSON contract. It runs nothing itself: the command
// layer runs a filled text through the same guard and transport as a typed
// exec line, and hands the output back to Parse.
package snippet

import (
	"context"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/capability"
)

// Family is the shell a text is written for.
type Family string

const (
	Unix    Family = "unix"    // POSIX sh: Linux, macOS
	Windows Family = "windows" // PowerShell
)

// Channel is where a variable's value goes, which decides how it is
// quoted (Audit A-C368-5).
type Channel uint8

const (
	_        Channel = iota
	Text             // into the text: quoted by the family's shell (sshx.Q, sshx.PSQ)
	SQLIdent         // a SQL identifier: quoted by dbx for its engine, in the client call
	SQLValue         // a SQL value: a bind parameter, never spliced
	RESP             // a cache argument: its own RESP argument, never a joined line
	KubeName         // a Kubernetes name: DNS-1123, passed as an API field
	SFTPPath         // a remote path: cleaned, an SFTP argument, no shell
	Number           // a count into the text: ASCII digits only, written as they are
)

// Var is one variable a snippet takes with --var NAME=VALUE.
type Var struct {
	Name    string
	Channel Channel
	Pattern *regexp.Regexp // anchored (^...$); the value must match it
	MaxLen  int            // bytes
	// Longest is a value of MaxLen bytes that matches Pattern: the filled
	// text with it must find no exec rule (Audit A-C368-4, rule 3.5)
	Longest  string
	Required bool
	Default  string // used when the variable is not given and not required
	// List takes several values, comma-separated: each is checked alone
	// and quoted as its own word, in the order given (svc-status takes
	// several units). MaxItems caps how many; MaxLen is per value.
	List     bool
	MaxItems int
	// Families narrows Pattern for one family's text, checked when that
	// text is filled: systemd unit names and Windows service names differ.
	Families map[Family]*regexp.Regexp
}

// Output is what a text printed on the server.
type Output struct {
	Stdout, Stderr string
	ExitCode       int
	Truncated      bool // stdout was cut at the output cap
}

// Values are a snippet's variables after Check, for a client call.
type Values map[string]string

// Builtin is one ready-made snippet. A text snippet has Text and Parse; a
// client snippet (SFTP, SQL, cache, Kubernetes API) has Run. Never both.
type Builtin struct {
	Name     string          // "svc-list"
	Type     string          // the entry type it runs against: host, database, cache, cluster
	Replaces string          // the command it replaces, as typed: "svc list"
	Reader   string          // the app screen or the written agent need (Audit A-C368-1)
	Tier     capability.Tier // static, never weaker than Replaces (rule 3.4)
	Shape    string          // "svc-list/1"
	Vars     []Var
	Checks   []string // the checks carried, each named by the test that pins it (Audit A-C368-4)
	// Sudo runs the Unix text with sudo, as the replaced command does;
	// --no-sudo turns it off. A Windows text never runs with sudo.
	Sudo  bool
	Text  map[Family]string
	Parse func(o Output, f Family) (any, error)
	Run   func(ctx context.Context, v Values) (any, error)
}

// types are the entry types a built-in may run against.
var types = []string{"host", "database", "cache", "cluster"}

// waitOnRule are the snippets that may not be registered until a rule is
// in place (Audit's delta read, 2026-11-25). They are open hooks, not
// built-ins: the engine refuses them by name.
var waitOnRule = map[string]string{
	// a client write has no filled text, so the exec rules never see it:
	// its target path must go through the write rules (tee PATH, > PATH,
	// with the policy-edit switches), a hit raising the tier
	"fs-write": "Q1: the target path must go through the write rules first",
	// today an upgrade turns dangerous when the simulation removes an
	// essential package: that stop is carried, or the tier is dangerous
	"pkg-upgrade-all": "Q2: the simulation stop must be carried, or the tier is dangerous",
}

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	numberRe = regexp.MustCompile(`^[0-9]{1,9}$`)
	markerRe = regexp.MustCompile(`\{\{var:([a-z][a-z0-9_]*)\}\}`)
)

// Registry is the list of built-ins, looked up by exact name.
type Registry struct {
	byName map[string]Builtin
	names  []string
}

// New checks every definition of the lists and returns the registry. The
// lists come from the type packages (hostcmd.Snippets(), ...), collected in
// one place: no init() registration.
func New(lists ...[]Builtin) (*Registry, error) {
	r := &Registry{byName: map[string]Builtin{}}
	for _, l := range lists {
		for _, b := range l {
			if err := valid(b); err != nil {
				return nil, fmt.Errorf("built-in snippet %q: %w", b.Name, err)
			}
			if _, dup := r.byName[b.Name]; dup {
				return nil, fmt.Errorf("built-in snippet %q is listed twice", b.Name)
			}
			r.byName[b.Name] = b
			r.names = append(r.names, b.Name)
		}
	}
	slices.Sort(r.names)
	return r, nil
}

// Lookup finds a built-in by its exact name.
func (r *Registry) Lookup(name string) (Builtin, bool) {
	b, ok := r.byName[name]
	return b, ok
}

// Names lists the built-ins, sorted.
func (r *Registry) Names() []string { return slices.Clone(r.names) }

// valid checks one definition.
func valid(b Builtin) error {
	if why, ok := waitOnRule[b.Name]; ok {
		return fmt.Errorf("waits on a rule, %s", why)
	}
	if !nameRe.MatchString(b.Name) {
		return fmt.Errorf("the name is not lowercase words joined by hyphens")
	}
	if !slices.Contains(types, b.Type) {
		return fmt.Errorf("unknown type %q (one of %s)", b.Type, strings.Join(types, ", "))
	}
	if name, _, err := ParseShape(b.Shape); err != nil || name != b.Name {
		return fmt.Errorf("the shape is %q; write %s/N with N from 1", b.Shape, b.Name)
	}
	if b.Replaces == "" {
		return fmt.Errorf("replaces is empty: name the command it replaces")
	}
	if b.Reader == "" {
		return fmt.Errorf("reader is empty: name the app screen or the agent need")
	}
	switch {
	case b.Run != nil && (b.Text != nil || b.Parse != nil):
		return fmt.Errorf("has both a text and a client call")
	case b.Run == nil && b.Text == nil:
		return fmt.Errorf("has neither a text nor a client call")
	case b.Text != nil && b.Parse == nil:
		return fmt.Errorf("has a text but no parse function")
	}
	if _, ok := b.Text[Unix]; b.Sudo && !ok {
		return fmt.Errorf("sudo is set but there is no Unix text to run with it")
	}
	vars := map[string]Var{}
	for _, v := range b.Vars {
		if _, dup := vars[v.Name]; dup {
			return fmt.Errorf("variable %q is declared twice", v.Name)
		}
		if err := validVar(v); err != nil {
			return fmt.Errorf("variable %q: %w", v.Name, err)
		}
		vars[v.Name] = v
	}
	for f, text := range b.Text {
		if f != Unix && f != Windows {
			return fmt.Errorf("unknown family %q (one of %s, %s)", f, Unix, Windows)
		}
		if err := validText(text, vars); err != nil {
			return fmt.Errorf("%s text: %w", f, err)
		}
	}
	return nil
}

func validVar(v Var) error {
	if v.Channel < Text || v.Channel > Number {
		return fmt.Errorf("no channel")
	}
	if v.Pattern == nil {
		return fmt.Errorf("no pattern")
	}
	if !anchored(v.Pattern) {
		return fmt.Errorf("the pattern is not anchored with ^ and $")
	}
	if v.MaxLen <= 0 {
		return fmt.Errorf("no max length")
	}
	if len(v.Longest) != v.MaxLen || !v.Pattern.MatchString(v.Longest) {
		return fmt.Errorf("the longest value does not have the max length or does not match the pattern")
	}
	switch {
	case v.List && v.MaxItems <= 0:
		return fmt.Errorf("a list needs max items")
	case !v.List && v.MaxItems != 0:
		return fmt.Errorf("max items is set but it is not a list")
	case v.List && v.Channel != Text:
		return fmt.Errorf("a list goes only into a text, as text values: a client call or a number takes one value")
	case v.Channel == Number && !numberRe.MatchString(v.Longest):
		return fmt.Errorf("the longest value of a number is not 1 to 9 digits")
	case v.Channel == Number && !v.Required && v.Default == "":
		return fmt.Errorf("a number that is not required needs a default: an empty number would leave a gap in the text")
	}
	for f, p := range v.Families {
		switch {
		case f != Unix && f != Windows:
			return fmt.Errorf("a family pattern for the unknown family %q (one of %s, %s)", f, Unix, Windows)
		case v.Channel != Text:
			return fmt.Errorf("a family pattern is for a text variable only")
		case p == nil || !anchored(p):
			return fmt.Errorf("the %s pattern is not anchored with ^ and $", f)
		case !p.MatchString(v.Longest):
			return fmt.Errorf("the longest value does not match the %s pattern", f)
		}
	}
	if !v.Required && v.Default != "" && checkVar(v, v.Default) != nil {
		return fmt.Errorf("the default does not pass the variable's checks")
	}
	return nil
}

// anchored reports whether the whole pattern sits between ^ and $: its
// parsed tree begins with the start of the text and ends with its end, so
// `^a|b$` (a at the start, or b at the end) is not anchored and
// `^(?:a|b)$` is (Audit A-453-2).
func anchored(p *regexp.Regexp) bool {
	re, err := syntax.Parse(p.String(), syntax.Perl)
	if err != nil || re.Op != syntax.OpConcat || len(re.Sub) < 2 {
		return false
	}
	return re.Sub[0].Op == syntax.OpBeginText && re.Sub[len(re.Sub)-1].Op == syntax.OpEndText
}

// validText checks that every marker names a declared text variable.
func validText(text string, vars map[string]Var) error {
	if n := strings.Count(text, "{{var:"); n != len(markerRe.FindAllString(text, -1)) {
		return fmt.Errorf("a broken {{var:NAME}} marker")
	}
	for _, m := range markerRe.FindAllStringSubmatch(text, -1) {
		v, ok := vars[m[1]]
		if !ok {
			return fmt.Errorf("{{var:%s}} is not a declared variable", m[1])
		}
		if v.Channel != Text && v.Channel != Number {
			return fmt.Errorf("{{var:%s}} is not a text variable: only text variables and numbers go into a text", m[1])
		}
	}
	return nil
}

// Mutating reports whether the snippet changes something: the guard then
// asks on a protected entry, as the replaced command does.
func Mutating(b Builtin) bool { return b.Tier >= capability.Change }
