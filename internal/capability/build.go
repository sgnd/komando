package capability

import (
	"slices"
	"strings"
)

// The helpers below write the leaves every provider shares, so a type's
// file lists only what is its own.

// sessionID is the form of an exec session ID: komando makes it,
// 128 bits random, and checks it before any path use.
const sessionID = `^[a-z0-9]{26}$`

// provider is one provider of a type, as its type file lists it.
type provider struct {
	name                            string
	state                           State
	connect                         []Option // the connection options of add and edit
	url                             string   // an address of this provider, for the example of add
	entry, rawExample, writeExample string   // a read and a write command of the provider, for the examples of raw
}

// ids maps a verb to today's command IDs.
type ids map[string][]string

// inventory is the seven inventory verbs of one provider: Today and
// Carries per verb, and the stops each verb runs.
type inventory struct {
	typ     string
	noun    string // what an entry is, for the leaf texts: "cache"
	extra   bool   // add and edit take the flags of today's conn add and conn edit
	area    string // credential store: the providers sit under an area
	today   ids
	carries ids
	twin    string // the stop that compares addresses: protectedTwinHost or protectedTwinConn
	guard   string // the stop for a protected entry: guardProtection or guardConns
	edit    []Option
}

var inventoryVerbs = []string{"add", "edit", "list", "remove", "rename", "show", "test"}

func (inv inventory) leaves(p provider) []Leaf {
	var out []Leaf
	for _, verb := range inventoryVerbs {
		l := Leaf{
			Key:     Key{Type: inv.typ, Provider: p.name, Area: inv.area, Verb: verb},
			State:   p.state,
			Today:   inv.today[verb],
			Carries: inv.carries[verb],
			Args:    []Arg{{Name: "NAME"}},
		}
		switch verb {
		case "add":
			l.Options = append(clone(p.connect), protectedOpt)
			l.Stops = nonEmpty(inv.twin)
			if inv.extra {
				l.Args = append(l.Args, Arg{Name: "URL", Optional: true})
				l.Options = append(l.Options, connAddOptions...)
			}
		case "edit":
			l.Options = append(append(clone(p.connect), protectedOpt), inv.edit...)
			l.Stops = nonEmpty(inv.guard, inv.twin)
			if inv.extra {
				l.Options = append(l.Options, connEditOptions...)
			}
		case "list":
			l.Args, l.LocalRead, l.Synonyms = nil, true, []string{"ls"}
			if inv.extra {
				l.Args = []Arg{{Name: "TARGET", Selector: true, Optional: true}}
				l.Options = []Option{limitOpt}
			}
		case "show":
			l.LocalRead = true
		case "rename":
			l.Args = []Arg{{Name: "NAME"}, {Name: "NEW"}}
		case "remove":
			l.Stops = nonEmpty(inv.guard, "protectedTargets")
			if inv.extra {
				l.Args = []Arg{{Name: "TARGET", Selector: true, Many: true}}
			}
		case "test":
			l.Args = []Arg{{Name: "NAME", Selector: true}}
			if inv.extra {
				l.Args = []Arg{{Name: "TARGET", Selector: true}}
				l.Options = []Option{endOpt, waitOpt}
			}
		}
		if slices.ContainsFunc(l.Options, func(o Option) bool { return o.Kind == Credential }) {
			// a leaf that names a credential must not name the approval code's
			// seed, and resolves the credential through RefGuard
			l.Stops = append(l.Stops, "reservedSecret", "RefGuard")
		}
		if inv.noun != "" {
			l.Short, l.Example = inv.text(p, verb)
		}
		out = append(out, l)
	}
	return out
}

// text is the Short and the Example of one verb of this provider's entries.
func (inv inventory) text(p provider, verb string) (short, example string) {
	what := p.name + " " + inv.noun
	cmd := "  komando " + inv.typ + " " + p.name + " "
	lines := func(l ...string) string { return strings.Join(l, "\n") }
	switch verb {
	case "add":
		return "Save a " + what + " under a short name", lines(cmd+"add "+p.entry+" "+p.url+" --via web1", cmd+"add "+p.entry+" "+p.url+" --dry-run")
	case "edit":
		return "Change a saved " + what + " (only the flags you pass change)", lines(cmd+"edit "+p.entry+" --add-tag critical", cmd+"edit "+p.entry+" --notes 'main one' --dry-run")
	case "list":
		return "List the saved " + what + "s", lines(cmd+"list", cmd+"list @web")
	case "remove":
		return "Forget a saved " + what + " (the " + inv.noun + " is not touched)", lines(cmd+"remove "+p.entry+" --dry-run", cmd+"remove "+p.entry)
	case "rename":
		return "Rename a saved " + what + " and every reference to it", lines(cmd+"rename "+p.entry+" "+p.entry+"-2 --dry-run", cmd+"rename "+p.entry+" "+p.entry+"-2")
	case "show":
		return "Show a saved " + what + "'s settings (credentials as names)", lines(cmd+"show "+p.entry, cmd+"show "+p.entry+" -o json")
	}
	return "Check that a saved " + what + " answers and lets you in", lines(cmd+"test "+p.entry, cmd+"test @web")
}

// conns is the inventory of a type whose entries are today's conns: add is
// the type's own command (db add), every other verb was conn VERB.
func conns(typ, todayAdd string) inventory {
	return inventory{
		typ:   typ,
		noun:  typ,
		extra: true,
		today: ids{"add": {todayAdd}},
		carries: ids{"add": {"conn.add"}, "edit": {"conn.edit"}, "list": {"conn.list"}, "rename": {"conn.rename"},
			"remove": {"conn.rm"}, "show": {"conn.show"}, "test": {"conn.test"}},
		twin:  "protectedTwinConn",
		guard: "guardConns",
	}
}

// each returns the leaves fn makes for every provider.
func each(ps []provider, fn func(provider) []Leaf) []Leaf {
	var out []Leaf
	for _, p := range ps {
		out = append(out, fn(p)...)
	}
	return out
}

// idsOf returns prefix.verb for each verb.
func idsOf(prefix string, verbs ...string) []string {
	out := make([]string, len(verbs))
	for i, v := range verbs {
		out[i] = prefix + "." + v
	}
	return out
}

func join(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func nonEmpty(words ...string) []string {
	var out []string
	for _, w := range words {
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}

// withStop adds stop to every leaf of ls that does not run it yet.
func withStop(ls []Leaf, stop string) []Leaf {
	for i := range ls {
		if !slices.Contains(ls[i].Stops, stop) {
			ls[i].Stops = append(slices.Clone(ls[i].Stops), stop)
		}
	}
	return ls
}

func clone(o []Option) []Option { return append([]Option(nil), o...) }

var protectedOpt = Option{Name: "protected", Kind: Bool, Help: "changes need a person's yes"}

// writeOpt lets query and raw change things; without it they only read.
var writeOpt = Option{Name: "write", Kind: Bool, Help: "allow a command that changes data (it only reads without this)"}

var credentialOpt = Option{Name: "credential", Kind: Credential, Help: "what it logs in with"}

// The flags of today's conn add and conn edit, which every type that keeps
// its entries as conns takes on its add and edit. A typed option per
// provider (host, port, bucket, ...) waits on row C510; until then the
// URL carries the address.
var (
	viaOpt      = Option{Name: "via", Kind: Entry, Help: "reach it through these servers (bastions) or a VPN first, comma-separated path; no local port is opened"}
	groupOpt    = Option{Name: "group", Kind: Entry, Repeat: true, List: true, Help: "put it in these groups"}
	tagOpt      = Option{Name: "tag", Kind: String, Repeat: true, List: true, Help: "tags, like prod"}
	labelOpt    = Option{Name: "label", Kind: String, Repeat: true, Pairs: true, Help: "label KEY=VALUE"}
	notesOpt    = Option{Name: "notes", Kind: String, Help: "free-form notes, shown to people and agents"}
	optionOpt   = Option{Name: "option", Kind: String, Repeat: true, Pairs: true, Help: "an option of this provider, KEY=VALUE"}
	overwriteOp = Option{Name: "overwrite", Kind: Bool, Help: "replace an entry that has the same name"}
	loginOpt    = Option{Name: "login", Kind: Enum, Enum: []string{"ask", "password", "none"}, Help: "how the password is used: ask at every connect, a stored one, or none"}
	askPassOpt  = Option{Name: "ask-password", Kind: Bool, Help: "type the password now (hidden, a person at a terminal); it is stored as a password credential"}
	limitOpt    = Option{Name: "limit", Short: "n", Kind: Int, Help: "show at most this many (0 = all)"}
	waitOpt     = Option{Name: "wait", Kind: Duration, Help: "wait this long for a person's sign-in"}
)

var connAddOptions = []Option{viaOpt, groupOpt, tagOpt, labelOpt, notesOpt, optionOpt, overwriteOp, loginOpt, askPassOpt}

var connEditOptions = []Option{viaOpt, notesOpt, optionOpt, labelOpt, loginOpt, askPassOpt,
	{Name: "url", Kind: String, Help: "the new URL (the provider may not change)"},
	{Name: "add-group", Kind: Entry, Repeat: true, List: true, Help: "put it in these groups"},
	{Name: "rm-group", Kind: Entry, Repeat: true, List: true, Help: "take it out of these groups"},
	{Name: "add-tag", Kind: String, Repeat: true, List: true, Help: "add these tags"},
	{Name: "rm-tag", Kind: String, Repeat: true, List: true, Help: "remove these tags"},
	{Name: "unset", Kind: String, Repeat: true, List: true, Help: "clear these settings: via, credential, notes, protected"},
}
