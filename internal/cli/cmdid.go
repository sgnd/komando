package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// Every command has an ID: its dotted path (fs.list, secret.show,
// host.rename). The success and error envelopes, the audit log and every
// table keyed by command (personalCmds, localReads, leavesHome, the
// ssh-gate tables, the secret.show mask line) use it, and
// TestTablesKeyedByID checks that each key is a command's ID, so a rename
// that forgets a table fails there instead of slipping past a check
// (docs/design/command-standard.md, S-1.6). A rename changes the ID with
// the path, in the same commit as every table and testdata/command_ids.txt
// (komando is used internally only). commandKinds and the risk table are
// keyed by (type, area, verb) instead, through cmdKeys (risk_keys.go).
//
// A thin wrapper that runs another command (a synonym that needs its own
// argument rule) carries the ID of the command it runs (withID).
//
// The tree also notes on each command how far it is ready (readyNote): a
// run prepares only the commands its line runs through (openPath), so a
// start does not grow with the commands it never reaches.

// cmdIDNote is the annotation that holds a command's ID.
const cmdIDNote = "komando.id"

// withID gives c the ID id: for a wrapper command, the ID of the command
// it runs.
func withID(c *cobra.Command, id string) *cobra.Command {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[cmdIDNote] = id
	return c
}

// stampID writes c's ID into its annotations: the one withID gave it, else
// its dotted path.
func stampID(c *cobra.Command) {
	withID(c, cmdID(c))
}

// cmdID is c's ID: the withID annotation, else its dotted path without
// "komando" ("komando" for the root itself).
func cmdID(c *cobra.Command) string {
	if id := c.Annotations[cmdIDNote]; id != "" {
		return id
	}
	p := strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), "komando"))
	if p == "" {
		return "komando"
	}
	return strings.ReplaceAll(p, " ", ".")
}

// idKey is c's ID with spaces for dots, as personalCmds writes it
// ("cache keys").
func idKey(c *cobra.Command) string {
	return strings.ReplaceAll(cmdID(c), ".", " ")
}

// readyNote is the annotation that says how far the tree has readied a
// command: listed or prepared.
const readyNote = "komando.ready"

const (
	// readyListed: what a list of commands, Find and a did-you-mean read
	// (listNode)
	readyListed = "listed"
	// readyPrepared: all of it, and its sub-commands listed (openNode)
	readyPrepared = "prepared"
)

// inList reports whether c is ready to be listed and found.
func inList(c *cobra.Command) bool { return c.Annotations[readyNote] != "" }

// prepared reports whether c is ready to run and to show its help.
func prepared(c *cobra.Command) bool { return c.Annotations[readyNote] == readyPrepared }

// completeHelper reports whether c is the command cobra adds as it runs
// to answer the shell's completion; openPath prepares the words it completes.
func completeHelper(c *cobra.Command) bool {
	return c.Name() == cobra.ShellCompRequestCmd && c.HasParent() && !c.Parent().HasParent()
}

// notPrepared fails closed: a command the tree did not prepare runs
// nothing, before any check or handler (the root's PersistentPreRunE).
func notPrepared(c *cobra.Command) *out.Error {
	if prepared(c) || completeHelper(c) {
		return nil
	}
	return out.Errf(out.ExitError, "PREPARE_FAILED", "this is a bug in komando: report it at https://github.com/sgnd/komando/issues",
		"komando did not prepare %s for this line, so it runs nothing", c.CommandPath())
}

func setReady(c *cobra.Command, how string) {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[readyNote] = how
}

// listNode readies c to be listed: its aliases, its group run, its
// person-only mark.
func listNode(c *cobra.Command) {
	if inList(c) {
		return
	}
	applyConventions(c)
	markPersonOnly(c)
	setReady(c, readyListed)
}

// prepareSteps ready a listed command to run and to show its help, in this
// order: each step of every command before the next step (openAll).
var prepareSteps = []func(*cobra.Command){addCompletion, stampID, applyHelpStandard}

// openNode prepares c and lists its sub-commands, which its help, its
// completion and a did-you-mean show.
func openNode(c *cobra.Command) {
	if prepared(c) {
		return
	}
	// the sub-commands first, as openAll lists every command before any
	// step: an example of c may name one by an alias
	listNode(c)
	for _, s := range c.Commands() {
		listNode(s)
	}
	for _, step := range prepareSteps {
		step(c)
	}
	setReady(c, readyPrepared)
}

// openAll prepares every command of the tree under root.
func openAll(root *cobra.Command) {
	var all []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		all = append(all, c)
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	for _, c := range all {
		listNode(c)
	}
	for _, step := range prepareSteps {
		for _, c := range all {
			if !prepared(c) {
				step(c)
			}
		}
	}
	for _, c := range all {
		setReady(c, readyPrepared)
	}
}

// openPath prepares the commands line runs through: the root, then the
// command Find stops at, until Find stops at a prepared one (an alias or
// a group's run is only there once its parent is open). `help LINE` and
// the shell's completion prepare the command of the words after them.
func openPath(root *cobra.Command, line []string) {
	openNode(root)
	line = withoutCompleteWord(root, line)
	for {
		c, rest, _ := root.Find(line)
		if c == nil {
			return
		}
		if !prepared(c) {
			// Find may pass a parent by its name in one step: open from
			// the top, as a parent's step may set up its sub-commands
			// (completion writes the help of each shell's)
			var path []*cobra.Command
			for p := c; p != nil && !prepared(p); p = p.Parent() {
				path = append(path, p)
			}
			for i := len(path) - 1; i >= 0; i-- {
				openNode(path[i])
			}
			continue
		}
		if c.Name() == "help" && c.Parent() == root && len(rest) < len(line) {
			line = rest
			continue
		}
		return
	}
}

// withoutCompleteWord is line without the shell's completion word when that
// is its first word that is neither a flag nor a flag's value: cobra finds
// it there too (`-o json __complete host rm`).
func withoutCompleteWord(root *cobra.Command, line []string) []string {
	for i := 0; i < len(line); i++ {
		w := line[i]
		switch {
		case w == "--":
			return line
		case strings.HasPrefix(w, "-") && len(w) > 1:
			if !strings.Contains(w, "=") && takesValue(root, w) {
				i++ // its value
			}
		case w == cobra.ShellCompRequestCmd || w == cobra.ShellCompNoDescRequestCmd:
			return append(append([]string{}, line[:i]...), line[i+1:]...)
		default:
			return line
		}
	}
	return line
}

// takesValue reports whether the global flag w (--name or -x) takes the
// next word as its value.
func takesValue(root *cobra.Command, w string) bool {
	pf := root.PersistentFlags()
	if name, ok := strings.CutPrefix(w, "--"); ok {
		f := pf.Lookup(name)
		return f != nil && f.NoOptDefVal == ""
	}
	if len(w) != 2 {
		return false
	}
	f := pf.ShorthandLookup(w[1:])
	return f != nil && f.NoOptDefVal == ""
}
