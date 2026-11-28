package snippet

import (
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// dns1123 is a Kubernetes object name: a DNS-1123 subdomain.
var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// Check checks the given variables against b's and returns the values to
// use: defaults filled in, a path cleaned. It refuses a variable b does not
// declare, a missing required one, and a value that fails its checks.
func Check(b Builtin, given map[string]string) (Values, error) {
	declared := map[string]Var{}
	for _, v := range b.Vars {
		declared[v.Name] = v
	}
	for _, name := range slices.Sorted(maps.Keys(given)) {
		if _, ok := declared[name]; !ok {
			has := "it takes no variables"
			if len(b.Vars) > 0 {
				has = "its variables: " + strings.Join(varNames(b), ", ")
			}
			return nil, out.Errf(out.ExitUsage, "UNKNOWN_VAR", "give only the variables the snippet names, as `komando snippet exec "+b.Name+" TARGET --var NAME=VALUE`",
				"snippet %s has no variable named %q (%s)", b.Name, name, has)
		}
	}
	vals := Values{}
	for _, v := range b.Vars {
		val, ok := given[v.Name]
		if !ok {
			if v.Required {
				return nil, out.Usage("snippet %s needs --var %s=VALUE", b.Name, v.Name)
			}
			val = v.Default
		}
		if val == "" && !v.Required {
			vals[v.Name] = ""
			continue
		}
		if err := checkVar(v, val); err != nil {
			return nil, err
		}
		if v.Channel == SFTPPath {
			val = path.Clean(val)
		}
		vals[v.Name] = val
	}
	return vals, nil
}

func varNames(b Builtin) []string {
	names := make([]string, len(b.Vars))
	for i, v := range b.Vars {
		names[i] = v.Name
	}
	return names
}

// checkVar checks a variable's value: each value of a list alone.
func checkVar(v Var, val string) error {
	if !v.List {
		return checkValue(v, val)
	}
	items := strings.Split(val, ",")
	if len(items) > v.MaxItems {
		return out.Usage("%s takes at most %d values, comma-separated", v.Name, v.MaxItems)
	}
	for _, item := range items {
		if item == "" {
			return out.Usage("the value of %s has an empty item: join the values with single commas", v.Name)
		}
		if err := checkValue(v, item); err != nil {
			return err
		}
	}
	return nil
}

// checkValue checks one value against its variable and channel.
func checkValue(v Var, val string) error {
	if !utf8.ValidString(val) || strings.ContainsFunc(val, unicode.IsControl) {
		return out.Usage("the value of %s holds a control character or is not UTF-8", v.Name)
	}
	if len(val) > v.MaxLen {
		return out.Usage("the value of %s is longer than %d bytes", v.Name, v.MaxLen)
	}
	if !v.Pattern.MatchString(val) {
		return out.Usage("the value of %s does not match %s", v.Name, v.Pattern)
	}
	switch v.Channel {
	case Text:
		// quotes do not stop a program from reading an operand as an
		// option; a negative number or a relative time (-5, -2h) is fine
		if strings.HasPrefix(val, "-") && !(len(val) > 1 && val[1] >= '0' && val[1] <= '9') {
			return out.Errf(out.ExitUsage, "OPTION_LIKE_VAR", "for a path that starts with -, write ./"+val,
				"the value of %s may not start with '-' (%q would be read as an option)", v.Name, val)
		}
	case Number:
		if !numberRe.MatchString(val) {
			return out.Usage("the value of %s is not a number: give 1 to 9 digits 0-9", v.Name)
		}
	case KubeName:
		if len(val) > 253 || !dns1123.MatchString(val) {
			return out.Usage("the value of %s is not a Kubernetes name (DNS-1123: lowercase letters, digits, - and .)", v.Name)
		}
	}
	return nil
}

// Fill returns b's text for family f with each {{var:NAME}} replaced by
// the variable's value, quoted by that family's shell. A value is never
// pasted: it is always one quoted word. Each marker is replaced once, so a
// value that looks like a marker stays text.
func Fill(b Builtin, f Family, given map[string]string) (string, error) {
	text, ok := b.Text[f]
	if !ok {
		return "", Unsupported(b, string(f))
	}
	vals, err := Check(b, given)
	if err != nil {
		return "", err
	}
	quote, sep := sshx.Q, " "
	if f == Windows {
		quote, sep = sshx.PSQ, ", " // a list is a PowerShell array
	}
	list, number := map[string]bool{}, map[string]bool{}
	for _, v := range b.Vars {
		list[v.Name], number[v.Name] = v.List, v.Channel == Number
		if err := checkFamily(v, f, vals[v.Name]); err != nil {
			return "", err
		}
	}
	return markerRe.ReplaceAllStringFunc(text, func(m string) string {
		name := markerRe.FindStringSubmatch(m)[1]
		if number[name] {
			return vals[name] // digits only (checkValue): inert to sh and PowerShell
		}
		if !list[name] {
			return quote(vals[name])
		}
		items := strings.Split(vals[name], ",")
		for i, item := range items {
			items[i] = quote(item)
		}
		return strings.Join(items, sep)
	}), nil
}

// checkFamily checks val, each value of a list, against v's pattern for
// family f, when it has one.
func checkFamily(v Var, f Family, val string) error {
	p := v.Families[f]
	if p == nil || val == "" {
		return nil
	}
	items := []string{val}
	if v.List {
		items = strings.Split(val, ",")
	}
	for _, item := range items {
		if !p.MatchString(item) {
			return out.Usage("the value of %s does not match %s, which the %s text takes", v.Name, p, f)
		}
	}
	return nil
}

// Unsupported is the error for a family (or provider) the snippet has no
// body for.
func Unsupported(b Builtin, family string) *out.Error {
	return out.Errf(out.ExitUsage, "SNIPPET_OS_UNSUPPORTED", "read it as text with `komando host ssh exec TARGET -- COMMAND`; the snippet has no JSON for it",
		"snippet %s has no body for %s", b.Name, family)
}

// TypeUnsupported is the error for a target of another entry type.
func TypeUnsupported(b Builtin, target, typ string) *out.Error {
	return out.Errf(out.ExitUsage, "SNIPPET_TYPE_UNSUPPORTED", "run it against a "+b.Type+" entry; see them with `komando list`",
		"%s is a %s, not a %s", target, typ, b.Type)
}

// LongestValue is the longest value v takes: for a list, MaxItems longest
// values.
func LongestValue(v Var) string {
	if !v.List {
		return v.Longest
	}
	return strings.Repeat(v.Longest+",", v.MaxItems-1) + v.Longest
}
