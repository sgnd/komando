package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Questions: a command's arguments and flags (form_cmd.go), or an add
// command's own (form_kinds.go and form_<family>.go), each with a check, a
// default and, where there is one, a list to pick from. A person at a
// terminal who leaves something out is asked them (prompter_fill.go,
// prompter_add.go); the answers build an ordinary komando command line,
// shown before it runs. Passwords are never asked here: the command asks
// them itself, hidden (--ask-password) (docs/design/principles.md, section 11).

// formAnswers are the answers so far, by question key.
type formAnswers map[string]string

// formQ is one question.
type formQ struct {
	key      string // the answer's key
	label    string // its short name in the answers and the review ("Address")
	ask      string // the question ("What is the server's address?")
	help     string // one dim line under it: what it is, where to find it
	example  string // shown while nothing is typed: "for example: 10.0.0.5"
	optional bool   // an empty answer is fine
	advanced bool   // asked only under More options on the review
	addr     bool   // a pasted user:password@ is taken out at once
	free     bool   // with choices: an answer not in the list may be typed
	// def is what Enter takes when nothing is typed (nil: nothing)
	def func(st *store.State, a formAnswers) string
	// choices makes it a list to pick from instead of a line to type
	choices func(st *store.State, a formAnswers) []pickRow
	// show: asked only while it says true (nil: always)
	show func(a formAnswers) bool
	// when: asked only while the inventory allows it (nil: always), like
	// "through which server" while komando knows a server
	when func(st *store.State) bool
	// check says what is wrong with an answer, "" when it is fine
	check func(st *store.State, a formAnswers, v string) string
}

// formSpec is one kind of thing to add: its questions and how the answers
// become commands (the add, then the test or login that shows it works).
type formSpec struct {
	title string // "Add a server"
	qs    []formQ
	build func(st *store.State, a formAnswers) [][]string
}

// formKind is one row of the "what is it?" lists.
type formKind struct {
	label, detail string
	spec          func(cl *call) formSpec
}

// formGroup is a row of the first list: Server, Database, Cache, ...
type formGroup struct {
	label, detail string
	kinds         []formKind
	ask           string // the question above its kinds ("Which database?")
}

// visible says whether q is asked with these answers.
func (q formQ) visible(st *store.State, a formAnswers) bool {
	return (q.show == nil || q.show(a)) && (q.when == nil || q.when(st))
}

// formDefault is q's default with these answers, or "".
func formDefault(st *store.State, q formQ, a formAnswers) string {
	if q.def == nil {
		return ""
	}
	return q.def(st, a)
}

// formBuild builds the commands from the answers of the questions that
// show: an answer to a question an edit has hidden is not used.
func formBuild(st *store.State, sp formSpec, a formAnswers) [][]string {
	shown := formAnswers{}
	for _, q := range sp.qs {
		if v, ok := a[q.key]; ok && q.visible(st, a) {
			shown[q.key] = v
		}
	}
	return sp.build(st, shown)
}

// formDry is the command Try it first runs: the first one that is not a
// secret set (which would ask for the secret), with --dry-run before any
// --, where it is still a flag and not a word of the remote command.
func formDry(cmds [][]string) []string {
	c := cmds[0]
	for _, x := range cmds {
		if len(x) < 2 || x[0] != "secret" || x[1] != "set" {
			c = x
			break
		}
	}
	if i := slices.Index(c, "--"); i >= 0 {
		return slices.Insert(slices.Clone(c), i, "--dry-run")
	}
	return append(slices.Clone(c), "--dry-run")
}

// formEmptyRow: q's list has a row for no answer ("Directly"), so having
// none is a choice already made.
func formEmptyRow(st *store.State, q formQ, a formAnswers) bool {
	return q.choices != nil && slices.ContainsFunc(q.choices(st, a), func(r pickRow) bool { return r.value == "" })
}

// pastedSecret takes the password out of user:password@host or
// scheme://user:password@host, as people paste them from a hosting email.
func pastedSecret(s string) (string, bool) {
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return s, false
	}
	start := 0
	if i := strings.Index(s[:at], "://"); i >= 0 {
		start = i + 3
	}
	user := s[start:at]
	c := strings.Index(user, ":")
	if c < 0 {
		return s, false
	}
	return s[:start] + user[:c] + s[at:], true
}

// formArgs lets an add command take no arguments, for the questions; with
// any argument the usual rule holds.
func formArgs(rule cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		return rule(cmd, args)
	}
}

// formOrUsage is an add command typed with nothing after it: the questions
// for a person at a terminal (asked before the command runs, prompter_add.go), the usual
// usage error for everyone else, AI agents and scripts included.
func formOrUsage(cmd *cobra.Command, kind, example string) error {
	return out.Errf(out.ExitUsage, "USAGE",
		"for example: "+example+". A person can type `komando "+kind+" add` alone at a terminal to be asked step by step",
		"komando %s add needs a name and what to add", kind)
}
