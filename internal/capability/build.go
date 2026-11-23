package capability

// The helpers below write the leaves every provider shares, so a type's
// file lists only what is its own.

// sessionID is the form of an exec session ID: komando makes it,
// 128 bits random, and checks it before any path use.
const sessionID = `^[a-z0-9]{26}$`

// provider is one provider of a type, as its type file lists it.
type provider struct {
	name    string
	state   State
	connect []Option // the connection options of add and edit
}

// ids maps a verb to today's command IDs.
type ids map[string][]string

// inventory is the seven inventory verbs of one provider: Today and
// Carries per verb, and the stops each verb runs.
type inventory struct {
	typ     string
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
		case "edit":
			l.Options = append(append(clone(p.connect), protectedOpt), inv.edit...)
			l.Stops = nonEmpty(inv.guard, inv.twin)
		case "list":
			l.Args, l.LocalRead, l.Synonyms = nil, true, []string{"ls"}
		case "show":
			l.LocalRead = true
		case "rename":
			l.Args = []Arg{{Name: "NAME"}, {Name: "NEW"}}
		case "remove":
			l.Stops = nonEmpty(inv.guard, "protectedTargets")
		case "test":
			l.Args = []Arg{{Name: "NAME", Selector: true}}
		}
		out = append(out, l)
	}
	return out
}

// conns is the inventory of a type whose entries are today's conns: add is
// the type's own command (db add), every other verb was conn VERB.
func conns(typ, todayAdd string) inventory {
	return inventory{
		typ:   typ,
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

func clone(o []Option) []Option { return append([]Option(nil), o...) }

var protectedOpt = Option{Name: "protected", Kind: Bool, Help: "changes need a person's yes"}

// writeOpt lets query and raw change things; without it they only read.
var writeOpt = Option{Name: "write", Kind: Bool, Help: "allow a command that changes data (it only reads without this)"}

var credentialOpt = Option{Name: "credential", Kind: Credential, Help: "what it logs in with"}
