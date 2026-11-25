package cli

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// The cobra tree is built from the table (capability.All()): every built
// leaf with a handler becomes a command at its v2.7 words, with its text,
// arguments, options and synonyms from the table. Step C of the v0.18.0
// cut moves today's commands into handlers one type at a time; until a
// type has moved, today's constructors (addCommands) give its commands.

// handler runs one leaf. It gets the call and what was typed, never the
// cobra command: the builder owns cobra and its hooks, so the root's
// begin and start checks run before every handler.
type handler func(cl *call, ctx context.Context, in leafInput) error

// handlers are the leaves built so far, by key. A type joins movedTypes in
// the same pull request that registers its handlers (TestEveryHandlerHasLeaf).
var handlers = map[capability.Key]handler{}

// movedTypes are the types whose every built leaf has a handler.
var movedTypes = []string{}

// groupShorts is the text of each group the builder makes (a provider or
// an area under a type), by its words: "cache redis".
var groupShorts = map[string]string{}

// leafInput is what a person or an agent typed for one leaf: the
// arguments, and each option by its table name.
type leafInput struct {
	Args []string
	ID   string // the leaf's ID, its words with dots
	// Dash is where `--` stood in Args (what follows it is a command for
	// another program), or -1 when it was not typed.
	Dash    int
	vals    map[string]any // *string, *bool, *int, *time.Duration, *int64, *[]string
	changed func(name string) bool
}

func (in leafInput) String(name string) string          { return deref[string](in, name) }
func (in leafInput) Bool(name string) bool              { return deref[bool](in, name) }
func (in leafInput) Int(name string) int                { return deref[int](in, name) }
func (in leafInput) Duration(name string) time.Duration { return deref[time.Duration](in, name) }
func (in leafInput) Bytes(name string) int64            { return deref[int64](in, name) }
func (in leafInput) Strings(name string) []string       { return slices.Clone(deref[[]string](in, name)) }

// Changed says whether the option was typed.
func (in leafInput) Changed(name string) bool { return in.changed != nil && in.changed(name) }

// deref is the value of option name; asking for an option the leaf does
// not have, or as another kind, is a bug in the handler.
func deref[T any](in leafInput, name string) T {
	p, ok := in.vals[name].(*T)
	if !ok {
		panic(fmt.Sprintf("komando: leaf option --%s read as %T", name, *new(T)))
	}
	return *p
}

// mountTable adds the built leaves of the table to today's tree. An error
// is a bug of the table or the handlers, which the build tests catch first.
func mountTable(root *cobra.Command) {
	if err := mountLeaves(root, capability.All(), handlers, groupShorts); err != nil {
		panic("komando: " + err.Error())
	}
}

// mountLeaves adds to root every built leaf of leaves that has a handler.
// It refuses a handler for a leaf that is not built, a leaf with no text,
// a group with no text, and words today's tree already uses.
func mountLeaves(root *cobra.Command, leaves []capability.Leaf, hs map[capability.Key]handler, groups map[string]string) error {
	for _, l := range leaves {
		h := hs[l.Key]
		switch {
		case h == nil:
			continue
		case l.State != capability.Built:
			return fmt.Errorf("%s: a handler for a leaf that is not built", l.Key)
		case l.Short == "":
			return fmt.Errorf("%s: the leaf has no Short text", l.Key)
		}
		words := l.Key.Path()
		parent := root
		for i, w := range words[:len(words)-1] {
			next := childNamed(parent, w)
			if next == nil {
				path := strings.Join(words[:i+1], " ")
				text := groups[path]
				if text == "" {
					return fmt.Errorf("%s: the group %q has no text", l.Key, path)
				}
				next = &cobra.Command{Use: w, Short: text}
				parent.AddCommand(next)
			}
			parent = next
		}
		if childNamed(parent, words[len(words)-1]) != nil {
			return fmt.Errorf("%s: today's tree already has %q", l.Key, strings.Join(words, " "))
		}
		parent.AddCommand(buildLeaf(l, h))
	}
	return nil
}

// childNamed is c's child called name (not an alias), or nil.
func childNamed(c *cobra.Command, name string) *cobra.Command {
	for _, s := range c.Commands() {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

// buildLeaf is the cobra command of one leaf.
func buildLeaf(l capability.Leaf, h handler) *cobra.Command {
	use := []string{l.Key.Path()[len(l.Key.Path())-1]}
	least, most := 0, 0
	for _, a := range l.Args {
		name := a.Name
		if a.Dash {
			name = "-- " + name // the Use line of a passthrough command (args_passthrough.go)
		}
		if a.Many {
			name += "..."
			most = -1
		} else if most >= 0 {
			most++
		}
		if a.Optional {
			name = "[" + name + "]"
		} else {
			least++
		}
		use = append(use, name)
	}
	vals := map[string]any{}
	c := &cobra.Command{
		Use:     strings.Join(use, " "),
		Short:   l.Short,
		Example: l.Example,
		Aliases: slices.Clone(l.Synonyms),
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) < least || most >= 0 && len(args) > most {
				return out.Usage("%s takes %s", strings.Join(l.Key.Path(), " "), strings.Join(use[1:], " "))
			}
			return nil
		},
	}
	for _, o := range l.Options {
		if !o.Generated { // komando makes the value; a person never types it
			addOption(c.Flags(), o, vals)
		}
	}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		in := leafInput{Args: args, ID: strings.Join(l.Key.Path(), "."), Dash: cmd.ArgsLenAtDash(), vals: vals, changed: func(n string) bool { return cmd.Flags().Changed(n) }}
		if err := checkOptions(l, in); err != nil {
			return err
		}
		return h(callOf(cmd), cmd.Context(), in)
	}
	return c
}

// addOption declares o on fs and keeps where its value lands in vals.
func addOption(fs *pflag.FlagSet, o capability.Option, vals map[string]any) {
	if o.Short == "" {
		declareOption(fs, o, vals)
		return
	}
	one := pflag.NewFlagSet(o.Name, pflag.ContinueOnError) // pflag takes a shorthand only when the flag is added
	declareOption(one, o, vals)
	f := one.Lookup(o.Name)
	f.Shorthand = o.Short
	fs.AddFlag(f)
}

func declareOption(fs *pflag.FlagSet, o capability.Option, vals map[string]any) {
	switch {
	case o.Repeat && o.Pairs:
		p := new([]string)
		kvVar(fs, p, o.Name, "", o.Help)
		vals[o.Name] = p
	case o.Repeat && o.List:
		p := new([]string)
		fs.StringSliceVar(p, o.Name, nil, o.Help)
		vals[o.Name] = p
	case o.Repeat:
		p := new([]string)
		fs.StringArrayVar(p, o.Name, nil, o.Help)
		vals[o.Name] = p
	case o.Kind == capability.Bool:
		p := new(bool)
		fs.BoolVar(p, o.Name, o.Default == "true", o.Help)
		vals[o.Name] = p
	case o.Kind == capability.Int:
		p := new(int)
		n, _ := strconv.Atoi(o.Default) // the table's own value; TestBuiltDefaultsParse
		fs.IntVar(p, o.Name, n, o.Help)
		vals[o.Name] = p
	case o.Kind == capability.Duration:
		p := new(time.Duration)
		d, _ := parseSpan(o.Default)
		durVar(fs, p, o.Name, d, o.Help)
		fs.Lookup(o.Name).DefValue = cmp.Or(o.Default, "0") // as the table writes it
		vals[o.Name] = p
	case o.Kind == capability.Bytes:
		p := new(int64)
		*p, _ = parseSize(o.Default)
		fs.Var(&bytesFlag{n: p}, o.Name, o.Help)
		fs.Lookup(o.Name).DefValue = cmp.Or(o.Default, "0")
		vals[o.Name] = p
	default: // String, Enum, Credential, Entry, File
		p := new(string)
		fs.StringVar(p, o.Name, o.Default, o.Help)
		vals[o.Name] = p
	}
}

// checkOptions applies the table's rules for the options: required, one
// of the enum, needs, conflicts and the pattern, before the handler runs.
func checkOptions(l capability.Leaf, in leafInput) error {
	for _, o := range l.Options {
		if o.Generated {
			continue
		}
		set := in.Changed(o.Name)
		switch {
		case o.Required && !set:
			return out.Usage("%s needs --%s", strings.Join(l.Key.Path(), " "), o.Name)
		case !set:
			continue
		case o.Kind == capability.Enum && !slices.Contains(o.Enum, in.String(o.Name)):
			return out.Usage("--%s takes %s", o.Name, strings.Join(o.Enum, ", "))
		}
		if o.Pattern != "" {
			values := []string{}
			if o.Repeat {
				values = in.Strings(o.Name)
			} else if _, ok := in.vals[o.Name].(*string); ok {
				values = []string{in.String(o.Name)}
			}
			for _, v := range values {
				if !regexp.MustCompile(o.Pattern).MatchString(v) {
					return out.Usage("--%s: %q is not in the form it takes", o.Name, v)
				}
			}
		}
		for _, n := range o.Needs {
			if !in.Changed(n) {
				return out.Usage("--%s works only with --%s", o.Name, n)
			}
		}
		for _, n := range o.Conflicts {
			if in.Changed(n) {
				return out.Usage("--%s and --%s cannot go together", o.Name, n)
			}
		}
	}
	return nil
}

// While step C of the v0.18.0 cut moves the commands one type at a time,
// a leaf's handler can run the body that today's command has: runBody
// types the leaf's words back as that command's flags and arguments and
// runs it in the same call. No old spelling is reachable: the old command
// is not in the tree, only its body is called, and when the last type has
// moved the bodies are written as handlers and this file goes.

// runBody runs body, today's command, with what the leaf was given. A
// table option that the body names differently is in renames; the
// credential option is the body's --password-ref (credentialRef).
func runBody(cl *call, ctx context.Context, body *cobra.Command, in leafInput, renames map[string]string) error {
	body.SetArgs(bodyArgv(in, renames))
	body.SilenceErrors, body.SilenceUsage = true, true
	before := cl.out.As
	cl.out.As = in.ID // the envelope and the audit record carry the leaf's ID
	defer func() { cl.out.As = before }()
	return body.ExecuteContext(withCall(ctx, cl))
}

// credentialRef is how today's bodies write the name of a credential: the
// reference to a secret. Row E1 renames it to credential:NAME; this is the
// one place that changes.
func credentialRef(name string) string { return "secret:" + name }

// bodyArgv is the flags the leaf was given, then its arguments, with `--`
// where it was typed.
func bodyArgv(in leafInput, renames map[string]string) []string {
	var argv []string
	for _, name := range slices.Sorted(maps.Keys(in.vals)) {
		if !in.Changed(name) {
			continue
		}
		flag := name
		if to, ok := renames[name]; ok {
			flag = to
		}
		switch p := in.vals[name].(type) {
		case *string:
			v := *p
			if name == "credential" {
				flag, v = "password-ref", credentialRef(v)
			}
			argv = append(argv, "--"+flag+"="+v)
		case *bool:
			argv = append(argv, "--"+flag+"="+strconv.FormatBool(*p))
		case *int:
			argv = append(argv, "--"+flag+"="+strconv.Itoa(*p))
		case *int64:
			argv = append(argv, "--"+flag+"="+strconv.FormatInt(*p, 10))
		case *time.Duration:
			argv = append(argv, "--"+flag+"="+p.String())
		case *[]string:
			for _, v := range *p {
				if name == "unset" && v == "credential" {
					v = "password-ref"
				}
				argv = append(argv, "--"+flag+"="+v)
			}
		default:
			panic(fmt.Sprintf("komando: option --%s has a value of %T", name, p))
		}
	}
	if in.Dash >= 0 {
		return append(append(append(argv, in.Args[:in.Dash]...), "--"), in.Args[in.Dash:]...)
	}
	return append(argv, in.Args...)
}

// typeWords are the table's type words, by the family of a conn kind.
var typeWords = map[string]string{"db": "database"}

// familyOfType is typeWord the other way round.
func familyOfType(typ string) string {
	for fam, w := range typeWords {
		if w == typ {
			return fam
		}
	}
	return typ
}

// providerWord is the word of a kind's provider in the table: the kind's
// own name, but for the kinds the table names otherwise.
func providerWord(k driver.Kind) string {
	if w, ok := map[string]string{"registry": "oci", "ftps": "ftp"}[k.Name]; ok {
		return w
	}
	return k.Name
}

func typeWord(family string) string {
	if w, ok := typeWords[family]; ok {
		return w
	}
	return family
}

// entryIsOf is nil when the saved conn called name is a provider entry of
// this type. Another provider's entry, or another type's, is WRONG_KIND
// with the path that fits it.
func entryIsOf(cl *call, st *store.State, name, typ, provider, verb string) error {
	c, err := findConn(cl, st, name)
	if err != nil {
		return err
	}
	return connIsOf(c, typ, provider, verb)
}

func connIsOf(c *store.Conn, typ, provider, verb string) error {
	t, err := driver.Parse(c.URL)
	if err != nil || (typeWord(t.Kind.Family) == typ && providerWord(t.Kind) == provider) {
		return nil
	}
	return out.Errf(out.ExitUsage, "WRONG_KIND", "use `"+entryPath(t.Kind)+" "+verb+" "+c.Name+"`",
		"%s is a %s %s, not a %s %s", c.Name, providerWord(t.Kind), typeWord(t.Kind.Family), provider, typ)
}

// targetsAreOf is nil when every conn the targets pick is a provider
// entry of this type (see entryIsOf).
func targetsAreOf(cl *call, st *store.State, targets []string, typ, provider, verb string) error {
	for _, target := range targets {
		sel, err := resolveSelection(cl, st, target)
		if err != nil {
			return err
		}
		for _, c := range sel.Conns {
			if err := connIsOf(c, typ, provider, verb); err != nil {
				return err
			}
		}
	}
	return nil
}

// entryPath is the words that run a kind's entries once its type has
// moved to the table, or today's words before.
func entryPath(k driver.Kind) string {
	if slices.Contains(movedTypes, typeWord(k.Family)) {
		return "komando " + typeWord(k.Family) + " " + providerWord(k)
	}
	return "komando " + k.Family
}

// inventoryHandlers registers the seven inventory verbs of an entry type
// for each provider; the type's own verbs (raw, query, ...) are its own.
func inventoryHandlers(typ string, providers ...string) {
	for _, p := range providers {
		p := p
		key := func(verb string) capability.Key { return capability.Key{Type: typ, Provider: p, Verb: verb} }
		handlers[key("add")] = func(cl *call, ctx context.Context, in leafInput) error {
			if len(in.Args) == 2 {
				if err := providerOfURL(in.Args[1], typ, p); err != nil {
					return err
				}
			}
			if len(in.Args) == 1 {
				return out.Errf(out.ExitUsage, "USAGE", "give the address too: komando "+typ+" "+p+" add NAME URL",
					"komando %s %s add needs a name and a URL", typ, p)
			}
			return runBody(cl, ctx, connAddCmdFor(familyOfType(typ)), in, nil)
		}
		handlers[key("edit")] = func(cl *call, ctx context.Context, in leafInput) error {
			if err := withEntry(cl, in.Args[0], typ, p, "edit"); err != nil {
				return err
			}
			return runBody(cl, ctx, connEditCmd(), in, nil)
		}
		handlers[key("list")] = func(cl *call, ctx context.Context, in leafInput) error {
			return runBody(cl, ctx, listCmdKind("conn", p), in, nil)
		}
		handlers[key("show")] = func(cl *call, ctx context.Context, in leafInput) error {
			if err := withEntry(cl, in.Args[0], typ, p, "show"); err != nil {
				return err
			}
			return runBody(cl, ctx, connShowCmd(), in, nil)
		}
		handlers[key("rename")] = func(cl *call, ctx context.Context, in leafInput) error {
			if err := withEntry(cl, in.Args[0], typ, p, "rename"); err != nil {
				return err
			}
			return runBody(cl, ctx, connMvCmd(), in, nil)
		}
		handlers[key("remove")] = func(cl *call, ctx context.Context, in leafInput) error {
			if err := withTargets(cl, in.Args, typ, p, "remove"); err != nil {
				return err
			}
			return runBody(cl, ctx, connRmCmd(), in, nil)
		}
		handlers[key("test")] = func(cl *call, ctx context.Context, in leafInput) error {
			if err := withTargets(cl, in.Args, typ, p, "test"); err != nil {
				return err
			}
			return runBody(cl, ctx, testCmdFor("conn"), in, nil)
		}
	}
}

func withEntry(cl *call, name, typ, provider, verb string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	return entryIsOf(cl, st, name, typ, provider, verb)
}

func withTargets(cl *call, targets []string, typ, provider, verb string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	return targetsAreOf(cl, st, targets, typ, provider, verb)
}

// providerOfURL is nil when the URL is one of this provider; a URL of
// another provider of the same type, or of another type, is WRONG_KIND with
// the path that fits it. A URL that does not parse is left to add to say.
func providerOfURL(raw, typ, provider string) error {
	t, err := driver.Parse(normConnURL(strings.TrimSpace(raw)))
	if err != nil || (typeWord(t.Kind.Family) == typ && providerWord(t.Kind) == provider) {
		return nil
	}
	return out.Errf(out.ExitUsage, "WRONG_KIND", "add it with `"+entryPath(t.Kind)+" add`",
		"%s is a %s URL, not one for `komando %s %s add`", raw, providerWord(t.Kind), typ, provider)
}

// providerIDs are the IDs of a moved type's commands that more than one
// provider has (cache.redis.raw and cache.memcached.raw): they share one
// safety key, which is how the rows of the safety table reach every
// provider (TestSafetyKeys allows exactly these to share).
var providerIDs = map[string]bool{}

// providerOrder is where a moved command stands in the table: of the commands
// that share a key, the first provider's is the one keyID names.
var providerOrder = map[string]int{}

// moveType makes a type's built leaves the commands of their IDs in every
// table keyed by ID, in the same step that registers their handlers: the
// new IDs get the safety key of the leaf and the entries of the old ID in
// personalCmds, localReads, leavesHome and the ssh-gate's no-network list;
// the old IDs lose theirs, so no table names a command that is gone.
func moveType(typ string) {
	movedTypes = append(movedTypes, typ)
	providerIDs[typ] = true // the type's own group shares its key with the provider groups
	for n, l := range capability.All() {
		if l.Type != typ || l.State != capability.Built {
			continue
		}
		words := l.Key.Path()
		id := strings.Join(words, ".")
		providerOrder[id] = n
		cmdKeys[id] = safetyKey{l.Type, l.Area, l.Verb}
		providerIDs[id] = true
		for i := 1; i < len(words)-1; i++ { // the provider and area groups
			gid, gkey := strings.Join(words[:i+1], "."), safetyKey{typ: l.Type}
			if i >= 2 {
				gkey.area = words[2]
			}
			cmdKeys[gid], providerIDs[gid] = gkey, true
			if _, ok := gateNoNetwork[typ]; ok {
				gateNoNetwork[gid] = nil
			}
		}
		if l.LocalRead {
			localReads[id] = true
		}
		if l.LeavesHome {
			leavesHome[id] = true
		}
		for _, old := range l.Today {
			if old == id {
				continue
			}
			delete(cmdKeys, old)
			if f, ok := gateNoNetwork[old]; ok {
				gateNoNetwork[id] = f
				delete(gateNoNetwork, old)
			}
			if personalCmds[strings.ReplaceAll(old, ".", " ")] {
				personalCmds[strings.ReplaceAll(id, ".", " ")] = true
				delete(personalCmds, strings.ReplaceAll(old, ".", " "))
			}
		}
		for _, carried := range l.Carries { // conn.list stays a command until every type has moved
			if f, ok := gateNoNetwork[carried]; ok {
				gateNoNetwork[id] = f
			}
		}
	}
}

// providerOfEntry is the table word of the provider of the saved conn
// called name, for the {P} of a Next: line; PROVIDER when there is none.
func providerOfEntry(name string) string {
	st, err := loadState()
	if err != nil {
		return "PROVIDER"
	}
	if c, ok := st.Conns[name]; ok {
		if t, err := driver.Parse(c.URL); err == nil {
			return providerWord(t.Kind)
		}
	}
	return "PROVIDER"
}
