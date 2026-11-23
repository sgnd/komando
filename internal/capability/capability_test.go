package capability

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The closed vocabulary. Changing it is a decision: this list
// changes with it, on purpose.
var specVerbs = strings.Fields(`add create edit list show rename remove delete test check
	exec run raw query shell backup restore read move link copy prune info start stop status
	install uninstall trust discover get set export import update version schema doctor`)

// The 26 top-level names.
var specTop = strings.Fields(`list test config update version schema
	host database cache queue storage cluster registry vpn cloud
	credential group policy snippet copy import export status agent audit doctor`)

func TestVerbsClosed(t *testing.T) {
	var names []string
	for _, v := range Verbs() {
		names = append(names, v.Name)
	}
	if !sameSet(names, specVerbs) {
		t.Errorf("Verbs() = %v, want the closed vocabulary %v", names, specVerbs)
	}
	for _, l := range All() {
		if slices.Contains(specVerbs, l.Verb) {
			continue
		}
		if l.Type == "config" && slices.Contains(configWords, l.Verb) {
			continue // a named exception
		}
		t.Errorf("%s: verb %q is not in the closed vocabulary", l.Key, l.Verb)
	}
}

func TestKeysUnique(t *testing.T) {
	seen := map[Key]bool{}
	for _, l := range All() {
		if seen[l.Key] {
			t.Errorf("%s: two leaves share this key", l.Key)
		}
		seen[l.Key] = true
	}
}

func TestTopLevelClosed(t *testing.T) {
	if got := Children(); !sameSet(got, specTop) {
		t.Errorf("Children() = %v, want the 26 top-level names %v", got, specTop)
	}
}

func TestChildren(t *testing.T) {
	tests := []struct {
		name string
		path []string
		want []string
	}{
		{"providers of host", []string{"host"}, []string{"ssh", "winrm", "telnet", "serial"}},
		{"areas of queue kafka", []string{"queue", "kafka", "consumer"}, []string{"list", "show"}},
		{"a leaf has no children", []string{"version"}, nil},
		{"an unknown word has no children", []string{"conn"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Children(tt.path...); !slices.Equal(got, tt.want) {
				t.Errorf("Children(%v) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// pairs: a leaf with the first verb needs a sibling with the second.
var pairs = [][2]string{{"add", "remove"}, {"create", "remove|delete"}, {"start", "stop"},
	{"install", "uninstall"}, {"backup", "restore"}}

func TestPairs(t *testing.T) {
	for _, l := range All() {
		for _, p := range pairs {
			if l.Verb != p[0] {
				continue
			}
			ok := false
			for _, want := range strings.Split(p[1], "|") {
				k := l.Key
				k.Verb = want
				if _, found := Find(k); found {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s: has %s but no %s beside it", l.Key, p[0], p[1])
			}
		}
	}
}

func TestOptionsSane(t *testing.T) {
	for _, l := range All() {
		names := map[string]bool{}
		for _, o := range l.Options {
			names[o.Name] = true
		}
		seen := map[string]bool{}
		for _, o := range l.Options {
			where := l.Key.String() + " --" + o.Name
			switch {
			case seen[o.Name]:
				t.Errorf("%s: the option is there twice", where)
			case o.Kind == Enum && len(o.Enum) == 0:
				t.Errorf("%s: an Enum option with no values", where)
			case o.Sensitive && o.Default != "":
				t.Errorf("%s: a sensitive option has a default", where)
			case o.Generated && o.Ask != "":
				t.Errorf("%s: komando makes this value, so a person is never asked for it", where)
			}
			seen[o.Name] = true
			if o.Pattern != "" {
				if _, err := regexp.Compile(o.Pattern); err != nil {
					t.Errorf("%s: pattern: %v", where, err)
				}
			}
			for _, n := range append(slices.Clone(o.Needs), o.Conflicts...) {
				if !names[n] {
					t.Errorf("%s: names --%s, which this leaf does not have", where, n)
				}
			}
		}
	}
}

func TestSynonymsNotGone(t *testing.T) {
	goneWords := map[string]bool{}
	for _, g := range Gones() {
		for _, w := range strings.Split(g.Today, ".") {
			goneWords[w] = true
		}
	}
	for _, l := range All() {
		siblings := Children(l.Path()[:len(l.Path())-1]...)
		for _, s := range l.Synonyms {
			if goneWords[s] || slices.Contains(siblings, s) || slices.Contains(specVerbs, s) {
				t.Errorf("%s: synonym %q is a removed word or another verb", l.Key, s)
			}
		}
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
