package cli

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Every command as questions: a person at a terminal who types a command
// with something missing is asked for it (prompter_fill.go), its arguments
// first (a server, a database ... picked from a list) and the flags it
// needs. The questions come from the command itself (its Use line and its
// flags), so a new command or flag shows up here on its own; a formHint
// makes one read better (its help on ?, its list, what it needs).

// formHint makes one command's questions read well.
type formHint struct {
	area  string     // its area in formAreas; "" takes it from the command's first word
	args  []formArg  // by position; a missing one is a typed answer named from Use
	flags []formFlag // asked in this order; every other flag waits under More options
	hide  []string   // flags never offered here, besides formNeverFlags
	// form is a hand-made form used instead (host add, conn add, vpn add)
	form func() []formGroup
	// skip: nobody is ever asked its questions (ssh-gate: sshd runs it)
	skip bool
	// always are flags every line gets (rename --starts-with)
	always []string
	// next are the commands that usually follow, {} the first argument:
	// shown on stderr as Next: after it ends well for a person at a terminal
	next []string
}

// formArg is how one argument is asked.
type formArg struct {
	ask, help, example, def string
	label                   string // its short name on the review; "" takes it from Use
	// pick is the list it is picked from: server (one server), host
	// (servers, groups, all), target, conn, db, cache, storage, cluster,
	// queue, registry, vpn, key, group, job, tunnel, secret; "" typed
	pick    string
	free    bool     // with pick: something not in the list may be typed (tag:prod)
	local   bool     // a path on this computer: ~/ is your home folder
	choices []string // the values it takes, when they are few
	// show asks it only while it says true, from the answers so far
	// (keys: arg0, arg1 ... and flag:NAME)
	show func(a formAnswers) bool
	// need: an optional argument a command typed without it is asked for
	// at a person's terminal while this says true (db query's SQL, unless
	// --file gives it)
	need func(a formAnswers) bool
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
	// keep makes a switch three-way for edits: leave it, Yes, or No
	// (--name=false), since No alone would change nothing
	keep bool
	// need, as formArg.need: asked at a person's terminal, when missing,
	// while it says true (required asks it always)
	need func(a formAnswers) bool
}

// formHints is keyed by the command path without "komando " (db query).
var formHints = map[string]formHint{}

// addFormHints registers hints; a path given twice is a mistake. An entry
// with only next (an area's Next: lines) joins the questions given for
// the same path elsewhere, in either order, unless both give next.
func addFormHints(m map[string]formHint) {
	for k, v := range m {
		if old, dup := formHints[k]; dup {
			switch {
			case nextOnly(v) && len(old.next) == 0:
				old.next = v.next
				v = old
			case nextOnly(old) && len(v.next) == 0:
				v.next = old.next
			default:
				panic("form hint twice: " + k)
			}
		}
		formHints[k] = v
	}
}

// nextOnly: h gives Next: lines and nothing else.
func nextOnly(h formHint) bool {
	return len(h.next) > 0 && h.area == "" && h.args == nil && h.flags == nil && h.hide == nil &&
		h.form == nil && !h.skip && h.always == nil
}

// formNeverFlags are never asked or added by a question. A person approves what needs
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
// with its value ("--old TEXT"), a switch alone ("rename --starts-with OLD
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
		a := formUseArg{optional: strings.HasPrefix(w, "[") && strings.HasSuffix(w, "]") && balanced(w[1:len(w)-1]) || optRest, dashes: dashes}
		if a.optional && strings.HasPrefix(w, "[") {
			w = w[1 : len(w)-1]
		}
		a.many = strings.HasSuffix(strings.TrimRight(w, "]"), "...")
		// the word without its optional parts: [USER@]ADDRESS[:PORT] is ADDRESS
		a.name = optionalPart.ReplaceAllString(strings.ReplaceAll(w, "...", ""), "")
		if i := strings.IndexAny(a.name, "[|"); i > 0 {
			a.name = a.name[:i]
		}
		a.name = strings.Trim(a.name, "[]") // the ] of an optional rest after --
		out = append(out, a)
	}
	return out
}

// optionalPart is an optional piece inside a Use word ([USER@], [:PORT]).
var optionalPart = regexp.MustCompile(`\[[^\[\]]*\]`)

// balanced: s opens and closes its brackets in order.
func balanced(s string) bool {
	n := 0
	for _, r := range s {
		switch r {
		case '[':
			n++
		case ']':
			if n--; n < 0 {
				return false
			}
		}
	}
	return n == 0
}

// formArgPick is the list an argument is picked from when no hint says.
func formArgPick(name string) (string, bool) {
	switch name {
	case "TARGET":
		return "target", true
	case "SERVER":
		return "server", false
	case "CONN":
		return "conn", false
	case "VPN":
		return "vpn", false
	case "GROUP":
		return "group", true
	case "JOB":
		return "job", true
	case "TUNNEL":
		return "tunnel", true
	}
	return "", false
}

// formPickRows is what a picker offers.
func formPickRows(st *store.State, pick string) []pickRow {
	var rows []pickRow
	switch pick {
	case "server":
		rows = pickHostRows(st)
	case "files": // where files go: servers, groups, all, file storage
		rows = append(formPickRows(st, "host"), pickConnRows(st, "storage")...)
	case "host", "target":
		rows = pickHostRows(st)
		if pick == "target" {
			rows = append(append(rows, pickConnRows(st, "")...), pickVpnRows(st)...)
		}
		gl := allGroups(st)
		for _, g := range sortedKeys(gl.Groups) {
			rows = append(rows, pickRow{label: "@" + g, detail: "group: " + strings.Join(gl.Groups[g], ", "), value: "@" + g})
		}
		rows = append(rows, pickRow{label: "all", detail: "everything komando knows", value: "all"})
	case "conn":
		rows = pickConnRows(st, "")
	case "db", "cache", "queue", "storage", "cluster", "registry":
		rows = pickConnRows(st, pick)
	case "vpn":
		rows = pickVpnRows(st)
	case "group":
		for _, g := range sortedKeys(allGroups(st).Groups) {
			rows = append(rows, pickRow{label: g, value: g})
		}
	case "key":
		for _, n := range pickNames(st.Keys, "key") {
			rows = append(rows, pickRow{label: n, value: n})
		}
	case "job":
		for _, n := range sortedKeys(st.Jobs) {
			rows = append(rows, pickRow{label: n, detail: st.Jobs[n].Host, value: n})
		}
	case "tunnel":
		for _, n := range sortedKeys(st.Tunnels) {
			rows = append(rows, pickRow{label: n, value: n})
		}
	case "secret": // names only: the vault is not opened
		for _, n := range secretNames() {
			rows = append(rows, pickRow{label: n, value: n})
		}
	case "recipe": // saved commands
		for _, n := range sortedKeys(st.Snippets) {
			rows = append(rows, pickRow{label: n, value: n})
		}
	case "via": // what a server or service is reached through
		rows = append(pickHostRows(st), pickVpnRows(st)...)
	case "setting":
		for _, n := range settingKeys() {
			rows = append(rows, pickRow{label: n, value: n})
		}
	}
	return rows
}

// formWords is a Use name as a person reads it: SQL stays, TARGET is
// "Target", SRC_CONN:IMAGE is "Src conn image".
func formWords(name string) string {
	name = strings.Trim(strings.NewReplacer("[", "", "]", "", ":", " ", "_", " ").Replace(name), " ")
	if slices.Contains(formAcronyms, name) {
		return name
	}
	n := strings.ToLower(strings.Join(strings.Fields(name), " "))
	if n == "" {
		return name
	}
	return strings.ToUpper(n[:1]) + n[1:]
}

// formAcronyms stay in capitals as labels.
var formAcronyms = []string{"SQL", "URL", "PID", "TTL", "ID", "IP", "CSV", "DNS", "OS"}

// formCmdSpec makes the questions for one command.
func formCmdSpec(cmd *cobra.Command) formSpec {
	key := commandKey(cmd)
	h := formHints[key]
	sp := formSpec{title: cmd.Short}
	uses := formUseArgs(cmd.Use, cmd.Flags())
	for i, u := range uses {
		q := formArgQ(i, u, h)
		// TARGET says which kinds it picks, and offers only those (C-A04)
		if kinds := targetKinds(cmd); u.name == "TARGET" && kinds != "" {
			if i >= len(h.args) || h.args[i].label == "" {
				q.label = "Target (" + kinds + ")"
			}
			if i >= len(h.args) || h.args[i].pick == "" && h.args[i].ask == "" {
				pick := targetPick(kinds)
				q.choices = func(st *store.State, _ formAnswers) []pickRow { return formPickRows(st, pick) }
			}
		}
		sp.qs = append(sp.qs, q)
	}
	asked := map[string]bool{}
	for _, ff := range h.flags {
		if slices.Contains(formNeverFlags, ff.name) {
			continue // a hint never brings in --yes, --allow-dangerous or --reveal
		}
		if f := cmd.Flags().Lookup(ff.name); f != nil {
			sp.qs = append(sp.qs, formFlagQ(f, ff, false))
			asked[ff.name] = true
		}
	}
	globals := cmd.Root().PersistentFlags()
	cmd.Flags().VisitAll(func(f *pflag.Flag) { // its own flags and a parent's (docker --sudo)
		if asked[f.Name] || f.Hidden || slices.Contains(formNeverFlags, f.Name) ||
			slices.Contains(h.hide, f.Name) || globals.Lookup(f.Name) != nil {
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
	q := formQ{key: "arg" + strconv.Itoa(i), label: cmp.Or(ah.label, formWords(u.name)), optional: u.optional,
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
		q.choices = func(st *store.State, _ formAnswers) []pickRow { return formPickRows(st, pick) }
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
	if def == "" && f.DefValue != "" && f.DefValue != "[]" && f.DefValue != "0" && f.DefValue != "0s" && f.DefValue != "-1" {
		def = f.DefValue
	}
	switch {
	case f.Value.Type() == "bool" && ff.keep:
		def, q.optional = "", true
		q.choices = func(*store.State, formAnswers) []pickRow {
			return []pickRow{{label: "Leave it as it is", value: ""}, {label: "Yes", value: "true"}, {label: "No", value: "false"}}
		}
	case f.Value.Type() == "bool":
		if def == "" {
			def = "false"
		}
		q.optional = false // a switch is always yes or no
		q.choices = func(*store.State, formAnswers) []pickRow {
			return []pickRow{{label: "No", value: "false"}, {label: "Yes", value: "true"}}
		}
	case len(ff.choices) > 0:
		q.choices = formValueRows(ff.choices)
	case ff.pick != "" || formFlagPick[f.Name] != "" && f.Value.Type() == "string":
		pick := cmp.Or(ff.pick, formFlagPick[f.Name])
		q.choices = func(st *store.State, _ formAnswers) []pickRow { return formPickRows(st, pick) }
		q.free = true
	case strings.HasSuffix(f.Name, "-ref"): // a reference, never the secret itself
		q.check = func(_ *store.State, _ formAnswers, v string) string { return formRefProblem(v) }
	default:
		typ := f.Value.Type()
		q.check = func(_ *store.State, _ formAnswers, v string) string { return formValueProblem(typ, v) }
		if vc, ok := f.Value.(valueChecker); ok { // the flag's own check, in its own words
			q.check = func(_ *store.State, _ formAnswers, v string) string {
				if err := vc.check(v); err != nil {
					msg, _, _ := strings.Cut(err.Error(), flagHintSep)
					return msg
				}
				return ""
			}
		}
	}
	if def != "" {
		q.def = func(*store.State, formAnswers) string { return def }
	}
	q.show = ff.show
	return q
}

// formFlagPick is the list a flag is picked from when no hint says: the
// same names shell completion offers for it.
var formFlagPick = map[string]string{"via": "via", "key": "key"}

// formValueRows is a fixed list of values to pick from.
func formValueRows(vals []string) func(*store.State, formAnswers) []pickRow {
	return func(*store.State, formAnswers) []pickRow {
		rows := make([]pickRow, 0, len(vals))
		for _, v := range vals {
			rows = append(rows, pickRow{label: v, value: v})
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
	case typ == "duration":
		if _, err := parseSpan(v); err != nil {
			return "type a time like 30s, 5m, 2h or 7d"
		}
	case strings.HasPrefix(typ, "int") || strings.HasPrefix(typ, "uint"):
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return "type a whole number"
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
	flags := slices.DeleteFunc(slices.Clone(h.always), func(w string) bool {
		return slices.Contains(formNeverFlags, strings.SplitN(strings.TrimLeft(w, "-"), "=", 2)[0])
	})
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		v, ok := a["flag:"+f.Name]
		ff := formFlagHint(h, f.Name)
		if ok && !slices.Contains(h.always, "--"+f.Name) && (v != f.DefValue || ff.keep) {
			flags = append(flags, formFlagWords(f, ff, v)...)
		}
	})
	if i := slices.Index(args, "--"); i >= 0 { // flags go before --, the rest is the command's
		return append(append(slices.Clone(args[:i]), flags...), args[i:]...)
	}
	return append(args, flags...)
}

// formFlagWords is one flag's answer as command line words: none for an
// empty answer (or an approval flag), --name for a yes, --name=value as one
// word, so a value starting with - stays a value.
func formFlagWords(f *pflag.Flag, ff formFlag, v string) []string {
	switch {
	case f == nil || slices.Contains(formNeverFlags, f.Name):
		return nil
	case v == "" && ff.empty:
		return []string{"--" + f.Name + "="}
	case v == "":
		return nil
	case f.Value.Type() == "bool" && v == "true":
		return []string{"--" + f.Name}
	case f.Value.Type() == "bool":
		return []string{"--" + f.Name + "=false"}
	case ff.local:
		return []string{"--" + f.Name + "=" + expandHome(v)}
	}
	return []string{"--" + f.Name + "=" + v}
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

// Areas.

// formAreas sorts the commands by area, and which command words fall in
// each when no hint says. The areas keep the hints and tests in order.
var formAreas = []struct {
	label, detail string
	words         []string
}{
	{"Servers", "run commands, logs, services, packages, users, Docker", []string{"exec", "shell", "facts", "logs", "svc", "pkg", "user", "cron", "reboot", "docker", "net", "cert"}},
	{"Files", "read, edit, copy and move files on servers", []string{"fs", "upload", "download", "cp", "sync"}},
	{"Databases", "queries, shells, dumps, users", []string{"db"}},
	{"Cache", "Redis and Memcached keys", []string{"cache"}},
	{"Message queues", "Kafka, RabbitMQ, NATS, SQS, Pub/Sub", []string{"queue"}},
	{"File storage", "buckets, SFTP, FTP, WebDAV, SMB", []string{"storage"}},
	{"Kubernetes", "clusters, apps, logs, Helm", []string{"cluster"}},
	{"Container registries", "images and tags", []string{"registry"}},
	{"VPNs, logins and tunnels", "connect, log in once, forward ports", []string{"vpn", "tunnel", "login", "logout"}},
	{"Secrets and keys", "the vault and SSH keys", []string{"secret", "key"}},
	{"Your list", "servers, conns, groups: add, change, import", []string{"host", "conn", "group", "list", "rename", "import", "export", "test"}},
	{"Jobs and recipes", "long tasks and saved commands", []string{"job", "recipe"}},
	{"Safety and audit", "what happened, rules, checks", []string{"audit", "policy", "doctor", "status", "config", "ssh-gate"}},
	{"Setup", "AI agents, updates", []string{"guide", "update", "version", "schema", "completion"}},
}

// formListed: it has questions. A group command (cache, cluster
// helm) that only shows its help is left out; its subcommands are listed.
func formListed(c *cobra.Command) bool {
	h, hinted := formHints[commandKey(c)]
	switch {
	case !c.Runnable() || c.Hidden || h.skip:
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
