// Package capability is komando's command tree as data: every command of
// the v2.7 grammar (TYPE PROVIDER [AREA] VERB, or NOUN [KIND] VERB) with
// its options, tier rows and the facts the safety checks need. The cobra
// tree, `komando schema`, help and the person's questions are built from
// it. It imports no cobra and no komando state, so tests and tools can
// read it whole.
//
// Until the v0.18.0 cut nothing imports this package; the fields marked
// "pre-cut" tie today's command IDs to their v2.7 home and go in the cut.
package capability

import "strings"

// Key names one leaf. Type is "" for a top-level action (list, copy, ...);
// Provider is "" for komando's own nouns; Area is "" when the verb sits on
// the provider or noun. For komando's nouns a credential kind or a config
// part (vault, skill, recording) is the Area.
type Key struct{ Type, Provider, Area, Verb string }

// Path is the words a person types, without NAME and flags.
func (k Key) Path() []string {
	var p []string
	for _, w := range []string{k.Type, k.Provider, k.Area, k.Verb} {
		if w != "" {
			p = append(p, w)
		}
	}
	return p
}

func (k Key) String() string { return strings.Join(k.Path(), " ") }

// State says whether a leaf is built. A New leaf is in the plan only: the
// builder leaves it out of the cobra tree, help and schema.
type State uint8

const (
	Built State = iota
	New
)

// Output says whose data a leaf prints. TargetData is read from a server or
// resource: secrets and personal data in it are hidden from AI agents.
type Output uint8

const (
	OwnData Output = iota
	TargetData
)

// OptKind is how an option's value is read.
type OptKind uint8

const (
	String OptKind = iota
	Bool
	Int
	Duration
	Bytes
	Enum
	Credential // the name of a credential
	Entry      // the name of an entry in komando's list
	File       // a path on this computer
)

// Option is one flag of a leaf. Global flags (-o, --dry-run, --yes, ...)
// are not here.
type Option struct {
	Name      string
	Kind      OptKind
	Enum      []string
	Default   string
	Required  bool
	Repeat    bool
	Sensitive bool     // never echoed, never in the audit text
	Generated bool     // komando makes the value at 256 bits; a person never types it
	Pattern   string   // the value must match before any use
	Needs     []string // options this one works only with
	Conflicts []string // options it cannot be used with
	Help      string
	Ask       string // the question a person sees when it is missing
}

// Arg is one positional argument.
type Arg struct {
	Name     string // NAME, ITEM, NEW, ...
	Selector bool   // takes @group, tag:x, label:k=v, all
	Many     bool
	Optional bool
}

// Leaf is one command a person or an agent can run.
type Leaf struct {
	Key
	Args       []Arg
	Options    []Option
	Short      string
	Example    string
	State      State
	Output     Output
	LocalRead  bool     // changes nothing anywhere: runs when the store cannot be written
	LeavesHome bool     // run as root it never touches ~/.komando
	Synonyms   []string // plain words people type for the verb (ls)
	Stops      []string // the in-command stops it runs, by function name

	// Today (pre-cut) are today's command IDs whose safety key (cmdKeys in internal/cli) is
	// this leaf's (type, area, verb). Carries (pre-cut) are today's IDs
	// whose job this leaf does under another key: exec, raw or query in
	// place of a removed command, or one ID that splits into kinds.
	Today   []string
	Carries []string
}

// Option returns the leaf's option with this name.
func (l Leaf) Option(name string) (Option, bool) {
	for _, o := range l.Options {
		if o.Name == name {
			return o, true
		}
	}
	return Option{}, false
}

// All returns every leaf. The slice is a copy; the slices inside each
// leaf are shared with the table, so callers must not change them.
func All() []Leaf { return append([]Leaf(nil), leaves...) }

// Find returns the leaf with this key. Its slices are shared with the
// table, as in All.
func Find(k Key) (Leaf, bool) {
	for _, l := range leaves {
		if l.Key == k {
			return l, true
		}
	}
	return Leaf{}, false
}

// Children returns the distinct next words under path, in table order:
// the types at the top, the providers of a type, and so on.
func Children(path ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range leaves {
		p := l.Path()
		if len(p) <= len(path) || !hasPrefix(p, path) {
			continue
		}
		if w := p[len(path)]; !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out
}

func hasPrefix(p, prefix []string) bool {
	for i, w := range prefix {
		if p[i] != w {
			return false
		}
	}
	return true
}

// leaves is the whole table, in the order help lists it.
var leaves = concat(
	builtinLeaves,
	hostLeaves,
	databaseLeaves,
	cacheLeaves,
	queueLeaves,
	storageLeaves,
	clusterLeaves,
	registryLeaves,
	vpnLeaves,
	cloudLeaves,
	ownLeaves,
)

func concat(parts ...[]Leaf) []Leaf {
	var all []Leaf
	for _, p := range parts {
		all = append(all, p...)
	}
	return all
}
