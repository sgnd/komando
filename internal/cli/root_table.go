package cli

import (
	"cmp"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
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
	Args    []string
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

// tableLeaves is the table the tree is built from; tests add a leaf of
// their own.
var tableLeaves = capability.All

// mountTable takes out of today's tree the commands the table now does,
// then adds the built leaves that have a handler. An error is a bug of the
// table or the handlers, which the build tests catch first.
func mountTable(root *cobra.Command) {
	leaves := tableLeaves()
	hideCarried(root, leaves, handlers)
	if err := mountLeaves(root, leaves, handlers, groupShorts); err != nil {
		panic("komando: " + err.Error())
	}
}

// hideCarried takes out of today's tree each command whose ID every built
// leaf that names it (in Today or Carries) now does: a command several
// types carry (conn add) stays until the last of them has moved. A command
// that exec, query or raw replaces (capability.Replacements) stays until
// cut step D removes it. A today group left with no command goes too.
func hideCarried(root *cobra.Command, leaves []capability.Leaf, hs map[capability.Key]handler) {
	carriers := map[string][]capability.Key{}
	for _, l := range leaves {
		if l.State != capability.Built {
			continue
		}
		for _, id := range slices.Concat(l.Today, l.Carries) {
			carriers[id] = append(carriers[id], l.Key)
		}
	}
	for _, r := range capability.Replacements() {
		delete(carriers, r.Today)
	}
	hide := map[string]bool{}
	for id, keys := range carriers {
		hide[id] = !slices.ContainsFunc(keys, func(k capability.Key) bool { return hs[k] == nil })
	}
	var drop func(c *cobra.Command) bool
	drop = func(c *cobra.Command) (hid bool) {
		for _, s := range c.Commands() {
			if hide[cmdID(s)] {
				c.RemoveCommand(s)
				hid = true
				continue
			}
			if drop(s) {
				hid = true
				if !s.HasSubCommands() && !s.Runnable() {
					c.RemoveCommand(s) // a group whose every command has moved
				}
			}
		}
		return hid
	}
	drop(root)
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
		for _, o := range l.Options {
			if root.PersistentFlags().Lookup(o.Name) != nil {
				return fmt.Errorf("%s: --%s is a global flag; the root reads it for every command", l.Key, o.Name)
			}
		}
		id := strings.Join(l.Key.Path(), ".")
		if commandWithID(root, id) != nil {
			return fmt.Errorf("%s: the ID %s is already in the tree", l.Key, id)
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

// commandWithID is the command under c whose ID is id, or nil.
func commandWithID(c *cobra.Command, id string) *cobra.Command {
	for _, s := range c.Commands() {
		if cmdID(s) == id {
			return s
		}
		if f := commandWithID(s, id); f != nil {
			return f
		}
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
		in := leafInput{Args: args, vals: vals, changed: func(n string) bool { return cmd.Flags().Changed(n) }}
		if err := checkOptions(l, in); err != nil {
			return err
		}
		return h(callOf(cmd), cmd.Context(), in)
	}
	return c
}

// addOption declares o on fs and keeps where its value lands in vals.
func addOption(fs *pflag.FlagSet, o capability.Option, vals map[string]any) {
	switch {
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
