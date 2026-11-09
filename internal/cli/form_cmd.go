package cli

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Every feature as questions: All features in the menu lists komando's
// commands by area, and picking one asks for what the command needs, its
// arguments first (a server, a database ... picked from a list) and the
// flags that matter, the others under More options. The questions come
// from the command itself (its Use line and its flags), so a new command
// or flag shows up here on its own; a formHint makes one read better.

// formHint makes one command's questions read well.
type formHint struct {
	area  string     // its All features area; "" takes it from the command's first word
	args  []formArg  // by position; a missing one is a typed answer named from Use
	flags []formFlag // asked in this order; every other flag waits under More options
	hide  []string   // flags never offered here, besides formNeverFlags
	// form is a hand-made form used instead (host add, conn add, vpn add)
	form func() []formGroup
	// skip keeps it out of All features (ssh-gate: sshd runs it, not a person)
	skip bool
	// always are flags every line gets (rename --prefix)
	always []string
}

// formArg is how one argument is asked.
type formArg struct {
	ask, help, example, def string
	// pick is the list it is picked from: server (one server), host
	// (servers, groups, all), target, conn, db, cache, storage, cluster,
	// registry, vpn, key, group, job, tunnel, secret; "" typed
	pick    string
	free    bool     // with pick: something not in the list may be typed (tag:prod)
	local   bool     // a path on this computer: ~/ is your home folder
	choices []string // the values it takes, when they are few
	// show asks it only while it says true, from the answers so far
	// (keys: arg0, arg1 ... and flag:NAME)
	show func(a formAnswers) bool
}

// formFlag is how one flag is asked, when it is asked before More options.
type formFlag struct {
	name, ask, help, example, def string
	required                      bool
	choices                       []string                 // the values it takes, when they are few
	pick                          string                   // as formArg.pick
	show                          func(a formAnswers) bool // as formArg.show
	local                         bool                     // as formArg.local
	empty                         bool                     // an empty answer is sent (--new= removes the text)
}

// formHints is keyed by the command path without "komando " (db query).
var formHints = map[string]formHint{}

// addFormHints registers hints; a path given twice is a mistake.
func addFormHints(m map[string]formHint) {
	for k, v := range m {
		if _, dup := formHints[k]; dup {
			panic("form hint twice: " + k)
		}
		formHints[k] = v
	}
}

// formNeverFlags are not offered by the menu. A person approves what needs
// a yes when the command asks (or in its window); output is for scripts.
var formNeverFlags = []string{"help", "yes", "allow-dangerous", "reveal", "output", "dry-run"}

// formUseArg is one argument of a Use line: "[SQL]" is optional, "NAME..."
// takes several, "[--]" puts -- before the rest.
type formUseArg struct {
	name           string
	optional, many bool
	dashes         bool // -- comes before this one
}

// formUseArgs reads the arguments from a Use line. A flag in it is skipped
// with its value ("--old TEXT"), a switch alone ("rename --prefix OLD
// NEW"); a choice of flags in parentheses ends it.
func formUseArgs(use string, flags *pflag.FlagSet) []formUseArg {
	f := strings.Fields(use)
	var out []formUseArg
	dashes, skip, optRest := false, false, false
	for _, w := range f[min(1, len(f)):] {
		switch {
		case skip:
			skip = false
			continue
		case w == "|":
			continue
		case w == "[--]" || w == "--":
			dashes = true
			continue
		case w == "[--": // [-- COMMAND...]: an optional rest after --
			dashes, optRest = true, true
			continue
		case w == "[flags]" || strings.HasPrefix(w, "("):
			return out
		case strings.HasPrefix(w, "-") || strings.HasPrefix(w, "[-"):
			name := strings.TrimLeft(strings.Trim(w, "[]"), "-")
			fl := (*pflag.Flag)(nil)
			if flags != nil {
				fl = flags.Lookup(name)
				if fl == nil && len(name) == 1 {
					fl = flags.ShorthandLookup(name)
				}
			}
			skip = fl == nil || fl.Value.Type() != "bool"
			continue
		}
		a := formUseArg{optional: strings.HasPrefix(w, "[") || optRest, dashes: dashes}
		w = strings.Trim(w, "[]")
		a.many = strings.HasSuffix(w, "...")
		a.name = strings.TrimSuffix(w, "...")
		if i := strings.IndexAny(a.name, "[|"); i > 0 {
			a.name = a.name[:i]
		}
		out = append(out, a)
	}
	return out
}

// formArgPick is the list an argument is picked from when no hint says.
func formArgPick(name string) (string, bool) {
	switch name {
	case "TARGET":
		return "target", true
	case "HOST", "SERVER":
		return "host", true
	case "CONN":
		return "conn", false
	case "VPN":
		return "vpn", false
	case "GROUP":
		return "group", true
	case "JOB", "ID":
		return "job", true
	}
	return "", false
}

// formPickRows is what a picker offers.
func formPickRows(st *store.State, pick string) []menuRow {
	var rows []menuRow
	switch pick {
	case "server":
		rows = menuHostRows(st)
	case "files": // where files go: servers, groups, all, file storage
		rows = append(formPickRows(st, "host"), menuConnRows(st, "storage")...)
	case "host", "target":
		rows = menuHostRows(st)
		if pick == "target" {
			rows = append(append(rows, menuConnRows(st, "")...), menuVpnRows(st)...)
		}
		gl := allGroups(st)
		for _, g := range sortedKeys(gl.Groups) {
			rows = append(rows, menuRow{label: "@" + g, detail: "group: " + strings.Join(gl.Groups[g], ", "), value: "@" + g})
		}
		rows = append(rows, menuRow{label: "all", detail: "everything komando knows", value: "all"})
	case "conn":
		rows = menuConnRows(st, "")
	case "db", "cache", "storage", "cluster", "registry":
		rows = menuConnRows(st, pick)
	case "vpn":
		rows = menuVpnRows(st)
	case "group":
		for _, g := range sortedKeys(allGroups(st).Groups) {
			rows = append(rows, menuRow{label: g, value: g})
		}
	case "key":
		for _, n := range menuNames(st.Keys, "key") {
			rows = append(rows, menuRow{label: n, value: n})
		}
	case "job":
		for _, n := range sortedKeys(st.Jobs) {
			rows = append(rows, menuRow{label: n, detail: st.Jobs[n].Host, value: n})
		}
	case "tunnel":
		for _, n := range sortedKeys(st.Tunnels) {
			rows = append(rows, menuRow{label: n, value: n})
		}
	case "secret": // names only: the vault is not opened
		for _, n := range secretNames() {
			rows = append(rows, menuRow{label: n, value: n})
		}
	}
	return rows
}

// formWords is a Use name as a person reads it: SQL stays, TARGET is
// "Target".
func formWords(name string) string {
	n := strings.ToLower(strings.ReplaceAll(name, "_", " "))
	if len(name) <= 3 {
		return name
	}
	return strings.ToUpper(n[:1]) + n[1:]
}

// formCmdSpec makes the questions for one command.
func formCmdSpec(cmd *cobra.Command) formSpec {
	key := commandKey(cmd)
	h := formHints[key]
	sp := formSpec{title: cmd.Short}
	uses := formUseArgs(cmd.Use, cmd.Flags())
	for i, u := range uses {
		sp.qs = append(sp.qs, formArgQ(i, u, h))
	}
	asked := map[string]bool{}
	for _, ff := range h.flags {
		if f := cmd.Flags().Lookup(ff.name); f != nil {
			sp.qs = append(sp.qs, formFlagQ(f, ff, false))
			asked[ff.name] = true
		}
	}
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if asked[f.Name] || f.Hidden || f.Deprecated != "" || slices.Contains(formNeverFlags, f.Name) || slices.Contains(h.hide, f.Name) {
			return
		}
		sp.qs = append(sp.qs, formFlagQ(f, formFlag{name: f.Name}, true))
	})
	sp.build = func(_ *store.State, a formAnswers) [][]string { return [][]string{formCmdArgs(cmd, uses, h, a)} }
	return sp
}

// formArgQ is the question for argument i.
func formArgQ(i int, u formUseArg, h formHint) formQ {
	var ah formArg
	if i < len(h.args) {
		ah = h.args[i]
	}
	if ah.pick == "" && ah.ask == "" {
		ah.pick, ah.free = formArgPick(u.name)
	}
	q := formQ{key: "arg" + strconv.Itoa(i), label: formWords(u.name), optional: u.optional,
		ask: ah.ask, help: ah.help, example: ah.example}
	if q.ask == "" {
		q.ask = formWords(u.name) + "?"
		if u.many {
			q.ask = formWords(u.name) + "? (several: separate them with spaces)"
		}
	}
	if ah.def != "" {
		def := ah.def
		q.def = func(*store.State, formAnswers) string { return def }
	}
	if ah.pick != "" {
		pick := ah.pick
		q.choices = func(st *store.State, _ formAnswers) []menuRow { return formPickRows(st, pick) }
		q.free = ah.free || u.many
	}
	if len(ah.choices) > 0 {
		q.choices = formValueRows(ah.choices)
	}
	q.show = ah.show
	if !u.dashes { // a word starting with - would be read as a flag
		many := u.many
		q.check = func(_ *store.State, _ formAnswers, v string) string {
			words := []string{strings.TrimSpace(v)}
			if many {
				words = formSplitWords(v)
			}
			for _, w := range words {
				if strings.HasPrefix(w, "-") {
					return "an answer here cannot start with -"
				}
			}
			return ""
		}
	}
	return q
}

// formFlagQ is the question for one flag: yes or no for a switch, a line to
// type (or a list of its values) for the rest, checked as the flag would.
func formFlagQ(f *pflag.Flag, ff formFlag, advanced bool) formQ {
	q := formQ{key: "flag:" + f.Name, label: "--" + f.Name, advanced: advanced, optional: !ff.required || ff.empty,
		ask: ff.ask, help: ff.help, example: ff.example}
	if q.ask == "" {
		q.ask = formSentence(f.Usage)
	} else if q.help == "" && f.Usage != "" {
		q.help = formSentence(f.Usage)
	}
	def := ff.def
	if def == "" && f.DefValue != "" && f.DefValue != "[]" && f.DefValue != "0" && f.DefValue != "0s" {
		def = f.DefValue
	}
	switch {
	case f.Value.Type() == "bool":
		if def == "" {
			def = "false"
		}
		q.optional = false // a switch is always yes or no
		q.choices = func(*store.State, formAnswers) []menuRow {
			return []menuRow{{label: "No", value: "false"}, {label: "Yes", value: "true"}}
		}
	case len(ff.choices) > 0:
		q.choices = formValueRows(ff.choices)
	case ff.pick != "":
		pick := ff.pick
		q.choices = func(st *store.State, _ formAnswers) []menuRow { return formPickRows(st, pick) }
		q.free = true
	case strings.HasSuffix(f.Name, "-ref"): // a reference, never the secret itself
		q.check = func(_ *store.State, _ formAnswers, v string) string { return formRefProblem(v) }
	default:
		typ := f.Value.Type()
		q.check = func(_ *store.State, _ formAnswers, v string) string { return formValueProblem(typ, v) }
	}
	if def != "" {
		q.def = func(*store.State, formAnswers) string { return def }
	}
	q.show = ff.show
	return q
}

// formValueRows is a fixed list of values to pick from.
func formValueRows(vals []string) func(*store.State, formAnswers) []menuRow {
	return func(*store.State, formAnswers) []menuRow {
		rows := make([]menuRow, 0, len(vals))
		for _, v := range vals {
			rows = append(rows, menuRow{label: v, value: v})
		}
		return rows
	}
}

// formSentence is a flag's help as a question line: capital first letter.
func formSentence(s string) string {
	if s == "" {
		return "Value?"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// formRefProblem checks a secret reference (secret:NAME, env:VAR ...): a
// pasted password or token is refused before it reaches a command line.
func formRefProblem(v string) string {
	if !vault.ValidRef(v) {
		return "type where the secret is kept, like secret:NAME (komando secret list), not the secret itself"
	}
	return ""
}

// formValueProblem checks a typed value as the flag's type would read it.
func formValueProblem(typ, v string) string {
	switch {
	case strings.HasPrefix(typ, "int") || strings.HasPrefix(typ, "uint"):
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return "type a whole number"
		}
	case typ == "duration":
		if _, err := time.ParseDuration(v); err != nil {
			return "type a time like 30s, 5m or 2h"
		}
	case typ == "float64" || typ == "float32":
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			return "type a number"
		}
	}
	return ""
}

// formJoined are the commands that join the words after -- into one
// shell line themselves: their command is passed as one word, as typed.
var formJoined = []string{"exec", "job start"}

// formCmdArgs is the command line for the answers: the command, its
// arguments in order, then each flag that differs from its default.
func formCmdArgs(cmd *cobra.Command, uses []formUseArg, h formHint, a formAnswers) []string {
	key := commandKey(cmd)
	args := strings.Fields(key)
	for i, u := range uses {
		v := a["arg"+strconv.Itoa(i)]
		if v == "" {
			continue
		}
		var ah formArg
		if i < len(h.args) {
			ah = h.args[i]
		}
		if u.dashes && !slices.Contains(args, "--") {
			args = append(args, "--")
		}
		args = append(args, formArgWords(key, u, ah, v)...)
	}
	flags := slices.Clone(h.always)
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		v, ok := a["flag:"+f.Name]
		ff := formFlagHint(h, f.Name)
		switch {
		case !ok || v == f.DefValue || slices.Contains(h.always, "--"+f.Name):
		case v == "" && ff.empty:
			flags = append(flags, "--"+f.Name+"=")
		case v == "":
		case f.Value.Type() == "bool" && v == "true":
			flags = append(flags, "--"+f.Name)
		case f.Value.Type() == "bool":
			flags = append(flags, "--"+f.Name+"=false")
		case ff.local:
			flags = append(flags, "--"+f.Name+"="+expandHome(v))
		default: // one word, so a value starting with - stays a value
			flags = append(flags, "--"+f.Name+"="+v)
		}
	})
	if i := slices.Index(args, "--"); i >= 0 { // flags go before --, the rest is the command's
		return append(append(slices.Clone(args[:i]), flags...), args[i:]...)
	}
	return append(args, flags...)
}

// formFlagHint is the hint for one flag, or none.
func formFlagHint(h formHint, name string) formFlag {
	for _, f := range h.flags {
		if f.name == name {
			return f
		}
	}
	return formFlag{}
}

// formArgWords is one answer as command line words: several names typed
// with spaces become one selector (web1,web2), the words of a command are
// split as a shell would (quotes kept together), and ~/ in a local path is
// your home folder.
func formArgWords(key string, u formUseArg, ah formArg, v string) []string {
	pick := ah.pick
	if pick == "" && ah.ask == "" {
		pick, _ = formArgPick(u.name)
	}
	switch {
	case u.many && u.name == "COMMAND" && slices.Contains(formJoined, key):
		return []string{v}
	case u.many:
		words := formSplitWords(v)
		if ah.local {
			for i := range words {
				words[i] = expandHome(words[i])
			}
		}
		return words
	case pick == "host" || pick == "target" || pick == "files":
		return []string{strings.Join(strings.Fields(v), ",")}
	case ah.local:
		return []string{expandHome(v)}
	}
	return []string{v}
}

// formSplitWords splits a line into words as a shell does: spaces part
// words, '...' and "..." keep spaces (the quotes go), \ keeps the next
// character.
func formSplitWords(v string) []string {
	var words []string
	var w strings.Builder
	inWord, quote, esc := false, rune(0), false
	for _, r := range v {
		switch {
		case esc:
			w.WriteRune(r)
			esc = false
		case r == '\\' && quote != '\'':
			esc, inWord = true, true
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			w.WriteRune(r)
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				words = append(words, w.String())
				w.Reset()
				inWord = false
			}
		default:
			w.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, w.String())
	}
	return words
}

// --- All features ---

// formAreas is the All features list, in the order people need them, and
// which command words fall in each when no hint says.
var formAreas = []struct {
	label, detail string
	words         []string
}{
	{"Servers", "run commands, logs, services, packages, users, Docker", []string{"exec", "shell", "facts", "logs", "svc", "pkg", "user", "cron", "reboot", "docker", "net", "cert", "script"}},
	{"Files", "read, edit, copy and move files on servers", []string{"fs", "upload", "download", "cp", "sync"}},
	{"Databases", "queries, shells, dumps, users", []string{"db"}},
	{"Cache", "Redis and Memcached keys", []string{"cache"}},
	{"Message queues", "Kafka, RabbitMQ, NATS, SQS, Pub/Sub", []string{"queue"}},
	{"File storage", "buckets, SFTP, FTP, WebDAV", []string{"storage"}},
	{"Kubernetes", "clusters, apps, logs, Helm", []string{"cluster"}},
	{"Container registries", "images and tags", []string{"registry"}},
	{"VPNs, logins and tunnels", "connect, log in once, forward ports", []string{"vpn", "tunnel", "login", "logout"}},
	{"Secrets and keys", "the vault and SSH keys", []string{"secret", "key"}},
	{"Your list", "servers, conns, groups: add, change, import", []string{"host", "conn", "group", "list", "rename", "import", "export", "test"}},
	{"Jobs and recipes", "long tasks and saved commands", []string{"job", "recipe"}},
	{"Safety and audit", "what happened, rules, checks", []string{"audit", "policy", "doctor", "status", "config", "ssh-gate"}},
	{"Setup", "AI agents, the prompt, updates", []string{"guide", "prompt", "update", "version", "schema", "completion"}},
}

// formCommands lists the commands of one area: every runnable command
// whose hint names the area, or whose first word is one of its words.
func formCommands(root *cobra.Command, area int) []*cobra.Command {
	var out []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			if s.Hidden || s.Deprecated != "" || s.Name() == "help" {
				continue
			}
			if formListed(s) && formAreaOf(s) == area {
				out = append(out, s)
			}
			walk(s)
		}
	}
	walk(root)
	return out
}

// formListed: All features offers it. A group command (cache, cluster
// helm) that only shows its help is left out; its subcommands are listed.
func formListed(c *cobra.Command) bool {
	h, hinted := formHints[commandKey(c)]
	switch {
	case !c.Runnable() || h.skip:
		return false
	case c.HasSubCommands() && !hinted:
		return len(formUseArgs(c.Use, c.Flags())) > 0
	}
	return true
}

// formAreaOf is the area a command is listed in, or -1.
func formAreaOf(c *cobra.Command) int {
	key := commandKey(c)
	for i, a := range formAreas {
		if h, ok := formHints[key]; ok && h.area != "" {
			if h.area == a.label {
				return i
			}
			continue
		}
		if slices.Contains(a.words, strings.Fields(key)[0]) {
			return i
		}
	}
	return -1
}

// formAllFeatures asks for an area, then a command in it, then that
// command's questions; Esc goes back one list at a time.
func formAllFeatures(ctx context.Context, t *menuTerm, st *store.State, scr menuScreen, try formTry) ([][]string, error) {
	root := newRoot()
	al := &menuList{title: "All features: which area?"}
	for _, a := range formAreas {
		al.rows = append(al.rows, menuRow{label: a.label, detail: a.detail, value: a.label})
	}
	for {
		row, err := menuChoose(ctx, t, al, scr)
		if err != nil {
			return nil, formQuitIsCancel(err)
		}
		al.point(row.value)
		area := slices.IndexFunc(formAreas, func(a struct {
			label, detail string
			words         []string
		}) bool {
			return a.label == row.value
		})
		cmds, err := formAreaCommands(ctx, t, st, scr, root, area, try)
		if errors.Is(err, errMenuBack) {
			continue
		}
		return cmds, err
	}
}

// formAreaCommands lists one area's commands (type to filter) and asks the
// chosen one's questions.
func formAreaCommands(ctx context.Context, t *menuTerm, st *store.State, scr menuScreen, root *cobra.Command, area int, try formTry) ([][]string, error) {
	cl := &menuList{title: formAreas[area].label + ": what do you want to do?", typing: true,
		empty: "no command here"}
	byKey := map[string]*cobra.Command{}
	for _, c := range formCommands(root, area) {
		key := commandKey(c)
		byKey[key] = c
		cl.rows = append(cl.rows, menuRow{label: key, detail: c.Short, value: key})
	}
	lscr := scr
	lscr.footer = "↑↓ move · Enter choose · Esc back · type to filter"
	for {
		row, err := menuChoose(ctx, t, cl, lscr)
		if err != nil {
			return nil, formQuitIsCancel(err)
		}
		cl.point(row.value)
		c := byKey[row.value]
		var cmds [][]string
		if h := formHints[row.value]; h.form != nil {
			cmds, err = formChoose(ctx, t, st, h.form(), scr, try)
		} else {
			cmds, err = formFill(ctx, t, st, formCmdSpec(c), scr, formTryFor(c, try))
		}
		if errors.Is(err, errMenuBack) {
			continue
		}
		return cmds, err
	}
}

// formQuitIsCancel: q or Ctrl-C on a form's list cancels the form, not the
// menu.
func formQuitIsCancel(err error) error {
	if errors.Is(err, errMenuQuit) {
		return errFormCancel
	}
	return err
}

// formTry runs a command with --dry-run from the review and comes back to
// it, so a person sees what a change would do before it happens.
type formTry func(args []string) error

// formTryFor offers the dry run only for a command that changes things.
func formTryFor(c *cobra.Command, try formTry) formTry {
	if k, ok := kindOf(c); ok && k.Kind == kindRead {
		return nil
	}
	return try
}
