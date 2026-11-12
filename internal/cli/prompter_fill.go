package cli

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// A command typed with something missing, by a person at a terminal, is
// filled in before it runs: komando asks for each missing argument and
// required flag (and the few optional values a command is useless without,
// formArg.need), shows the whole command line, asks before a change, and
// then runs that line as if it had been typed. Every check, guard and
// question of the command works as it always does, and what runs is what
// was shown. A command typed in full runs as it always did; nobody else is
// ever asked (promptable).

// promptSkip are the commands never filled in: they are for shells,
// scripts and agents, or print help.
var promptSkip = []string{"help", "completion", "schema", "guide", "ssh-gate", "seal", "prompt", "login-holder", "version"}

// fillDone: the command was handled while filling in (an add form ran its
// commands); its exit code is in code.
type fillDone struct{ code int }

func (f fillDone) Error() string { return "exit " + strconv.Itoa(f.code) }

// promptFill is args with what was missing asked and added, or args as
// they are. Its error is a cancel at a question (or fillDone).
func promptFill(args []string) ([]string, error) {
	promptConfirmed, fillSeen, nextNow = "", fillInfo{}, nil
	if !promptable(outputFlag()) {
		return args, nil
	}
	fillSeen.person = true
	scratch := newRoot() // its flags are parsed here; the real run parses its own
	cmd, rest, err := scratch.Find(args)
	if err != nil || cmd == scratch || !cmd.Runnable() || slices.Contains(promptSkip, strings.Fields(commandKey(cmd))[0]) {
		return args, nil
	}
	// a hidden command is never filled in; a hidden show (tunnel show
	// TUNNEL) still lists the commands for its item afterwards
	if _, show := showKinds[commandKey(cmd)]; cmd.Hidden && !show {
		return args, nil
	}
	if err := cmd.ParseFlags(rest); err != nil {
		return args, nil // the run says what is wrong
	}
	if h, _ := cmd.Flags().GetBool("help"); h {
		return args, nil
	}
	fillSeen.key = commandKey(cmd)
	if pos := cmd.Flags().Args(); len(pos) > 0 {
		fillSeen.first, fillSeen.args = pos[0], pos
	}
	if cmd.Hidden {
		return args, nil
	}
	st, err := loadState()
	if err != nil {
		return args, nil
	}
	promptOn = true
	defer func() { promptOn = false }()
	if formAddCmd(cmd) && len(cmd.Flags().Args()) == 0 {
		local := false
		cmd.LocalFlags().Visit(func(*pflag.Flag) { local = true })
		if local {
			return args, nil // part typed: the usage error says what is missing
		}
		return nil, promptAdd(st, cmd) // its own questions (prompter_add.go)
	}
	f := newFill(st, cmd)
	if len(f.missing) == 0 {
		return args, nil
	}
	for _, i := range f.missing {
		v, err := f.ask(i)
		if err != nil {
			return nil, err
		}
		f.a[f.sp.qs[i].key] = v
	}
	filled := f.argv(args)
	fillSeen.prompted, fillSeen.line = true, filled
	if fillSeen.first == "" && len(f.missing) > 0 && f.sp.qs[f.missing[0]].key == "arg0" {
		fillSeen.first = f.a["arg0"]
	}
	if v, ok := f.a["arg1"]; ok && len(fillSeen.args) < 2 { // rename's NEW, asked
		fillSeen.args = []string{fillSeen.first, v}
	}
	fmt.Fprintln(promptW, "$ komando "+out.MaskSecrets(menuCommandLine(filled)))
	if err := f.confirm(filled); err != nil {
		return nil, err
	}
	return filled, nil
}

// fill is one command being filled in: its questions, the answers given on
// the command line and asked, and which questions are still missing.
type fill struct {
	st      *store.State
	cmd     *cobra.Command
	key     string
	h       formHint
	uses    []formUseArg
	sp      formSpec
	a       formAnswers // given and asked, by question key
	given   map[string]bool
	missing []int // indexes into sp.qs, in order
}

func newFill(st *store.State, cmd *cobra.Command) *fill {
	f := &fill{st: st, cmd: cmd, key: commandKey(cmd), h: formHints[commandKey(cmd)],
		uses: formUseArgs(cmd.Use, cmd.Flags()), sp: formCmdSpec(cmd), a: formAnswers{}, given: map[string]bool{}}
	pos, dash := cmd.Flags().Args(), cmd.Flags().ArgsLenAtDash()
	before, after := pos, []string(nil)
	if dash >= 0 {
		before, after = pos[:dash], pos[dash:]
	}
	for i, u := range f.uses {
		seg := &before
		if u.dashes {
			seg = &after
		}
		if len(*seg) == 0 {
			continue
		}
		k := "arg" + strconv.Itoa(i)
		if u.many {
			f.a[k], *seg = strings.Join(*seg, " "), nil
		} else {
			f.a[k], *seg = (*seg)[0], (*seg)[1:]
		}
		f.given[k] = true
	}
	cmd.Flags().Visit(func(fl *pflag.Flag) {
		f.a["flag:"+fl.Name] = fl.Value.String()
		f.given["flag:"+fl.Name] = true
	})
	for i, q := range f.sp.qs {
		if f.given[q.key] || !q.visible(st, f.a) || !f.needed(q) {
			continue
		}
		f.missing = append(f.missing, i)
	}
	return f
}

// needed: a question the command cannot do without. An argument its Use
// line does not mark optional, a required flag, or one the hint says is
// needed with these answers (db query's SQL, unless --file gives it).
func (f *fill) needed(q formQ) bool {
	if i, ok := strings.CutPrefix(q.key, "arg"); ok {
		n, _ := strconv.Atoi(i)
		if n < len(f.h.args) && f.h.args[n].need != nil {
			return f.h.args[n].need(f.a)
		}
		return !f.uses[n].optional
	}
	name := strings.TrimPrefix(q.key, "flag:")
	ff := formFlagHint(f.h, name)
	if ff.need != nil {
		return ff.need(f.a)
	}
	if fl := f.cmd.Flags().Lookup(name); fl != nil {
		if _, req := fl.Annotations[cobra.BashCompOneRequiredFlag]; req {
			return true
		}
	}
	return ff.required
}

// pick is the inventory list a question picks from, or "".
func (f *fill) pick(key string) string {
	if i, ok := strings.CutPrefix(key, "arg"); ok {
		n, _ := strconv.Atoi(i)
		var ah formArg
		if n < len(f.h.args) {
			ah = f.h.args[n]
		}
		if ah.pick == "" && ah.ask == "" {
			ah.pick, _ = formArgPick(f.uses[n].name)
		}
		return ah.pick
	}
	name := strings.TrimPrefix(key, "flag:")
	return cmp.Or(formFlagHint(f.h, name).pick, formFlagPick[name])
}

// promptKinds says, for a list of existing things, what they are called
// and how one is added; only these are ever picked for the person.
var promptKinds = map[string]struct{ noun, add string }{
	"server": {"servers", "komando host add"}, "host": {"servers", "komando host add"},
	"target": {"servers or services", "komando host add"}, "files": {"servers or file storage", "komando host add"},
	"conn": {"services", "komando conn add"}, "db": {"databases", "komando db add"},
	"cache": {"caches", "komando cache add"}, "queue": {"message queues", "komando queue add"},
	"storage": {"file storages", "komando storage add"}, "cluster": {"clusters", "komando cluster add"},
	"registry": {"registries", "komando registry add"}, "vpn": {"VPNs", "komando vpn add"},
	"job": {"background jobs", "komando job start"}, "tunnel": {"tunnels", "komando tunnel start"},
}

// label is a question's name as the command spells it: CONN (database),
// TARGET, --unit.
func (f *fill) label(i int) string {
	q := f.sp.qs[i]
	if name, ok := strings.CutPrefix(q.key, "flag:"); ok {
		return "--" + name
	}
	n, _ := strconv.Atoi(strings.TrimPrefix(q.key, "arg"))
	l := f.uses[n].name
	if k := f.pick(q.key); l == "CONN" || l == "DATABASE" {
		if word := map[string]string{"db": "database", "cache": "cache", "queue": "message queue", "storage": "file storage", "cluster": "cluster", "registry": "registry"}[k]; word != "" {
			l += " (" + word + ")"
		}
	}
	return l
}

// ask asks question i: from a list when it has one, else typed.
func (f *fill) ask(i int) (string, error) {
	q := f.sp.qs[i]
	pq := promptQ{label: f.label(i), def: formDefault(f.st, q, f.a), optional: q.optional,
		help: strings.TrimSpace(strings.Join([]string{q.ask, q.help, cmp.Or(map[bool]string{true: "For example: " + q.example}[q.example != ""], "")}, " "))}
	if q.check != nil {
		pq.check = func(v string) string { return q.check(f.st, f.a, v) }
	}
	if q.choices == nil {
		return askText(pq)
	}
	rows := slices.DeleteFunc(q.choices(f.st, f.a), func(r menuRow) bool { return r.value == "" })
	if k, ok := promptKinds[f.pick(q.key)]; ok && !q.optional {
		var real []menuRow
		for _, r := range rows {
			if r.value != "all" && !strings.HasPrefix(r.value, "@") {
				real = append(real, r)
			}
		}
		switch {
		case len(real) == 0:
			fmt.Fprintf(promptW, "No %s yet; add one: %s\n", k.noun, k.add)
			return "", errPromptCancel
		case len(real) == 1 && len(rows) <= 2 && !promptProtected(f.st, real[0].value):
			fmt.Fprintf(promptW, "Using %s (the only one of your %s)\n", real[0].value, k.noun)
			return real[0].value, nil
		}
	}
	return askPick(pq, rows, q.free)
}

// promptProtected: name is a protected server or service, which is never
// picked for the person.
func promptProtected(st *store.State, name string) bool {
	if h, ok := st.Hosts[name]; ok {
		return protectedHost(st, h)
	}
	if c, ok := st.Conns[name]; ok {
		return protectedConn(st, c)
	}
	return false
}

// argv is args with the answers added: the new arguments after those
// typed (before --, or after it for the words of a remote command), then
// the new flags. Nothing typed is changed or moved.
func (f *fill) argv(args []string) []string {
	dash := slices.Index(args, "--")
	head, tail := slices.Clone(args), []string(nil)
	if dash >= 0 {
		head, tail = slices.Clone(args[:dash]), slices.Clone(args[dash+1:])
	}
	var flags, dashed []string
	for _, i := range f.missing {
		q := f.sp.qs[i]
		v := f.a[q.key]
		if name, ok := strings.CutPrefix(q.key, "flag:"); ok {
			flags = append(flags, formFlagWords(f.cmd.Flags().Lookup(name), formFlagHint(f.h, name), v)...)
			continue
		}
		if v == "" {
			continue
		}
		n, _ := strconv.Atoi(strings.TrimPrefix(q.key, "arg"))
		var ah formArg
		if n < len(f.h.args) {
			ah = f.h.args[n]
		}
		words := formArgWords(f.key, f.uses[n], ah, v)
		if f.uses[n].dashes {
			dashed = append(dashed, words...)
		} else {
			head = append(head, words...)
		}
	}
	line := append(head, flags...)
	if dash >= 0 || len(dashed) > 0 {
		line = append(append(line, "--"), append(tail, dashed...)...)
	}
	return line
}

// changes says whether the filled-in command changes something: a change,
// or a command that depends on a flag (--write, --read-only) set that way.
func (f *fill) changes() bool {
	k, ok := kindOf(f.cmd)
	switch {
	case !ok || k.Kind == kindChange:
		return true
	case k.Kind == kindRead:
		return false
	case f.cmd.Flags().Lookup("write") != nil:
		return f.a["flag:write"] == "true"
	}
	return f.a["flag:read-only"] != "true"
}

// targets are the servers and services the answers name.
func (f *fill) targets() []string {
	var names []string
	for k, v := range f.a {
		if p := f.pick(k); p != "" {
			if _, ok := promptKinds[p]; ok {
				names = append(names, strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })...)
			}
		}
	}
	slices.Sort(names)
	return names
}

// confirm asks before a filled-in change runs: Run it? (d runs it with
// --dry-run first and asks again). A step that cannot be undone (a T3 row
// of riskOf) then asks the typed name in the command itself, once (S-7.4);
// a T1 row a person types the name for (riskRow.typed: the command does
// not ask) asks it here instead of Run it?. A protected target asks [y/N]
// in the command itself, so it is not asked twice. A read, or a dry run,
// runs at once.
func (f *fill) confirm(filled []string) error {
	if !f.changes() || f.a["flag:dry-run"] == "true" || slices.Contains(filled, "--dry-run") {
		return nil
	}
	targets := f.targets()
	if slices.ContainsFunc(targets, func(n string) bool { return promptProtected(f.st, n) }) {
		return nil // the command asks: "web1 is protected. Change it anyway? [y/N]"
	}
	words := filled
	if path := strings.Fields(commandKey(f.cmd)); len(words) >= len(path) && slices.Equal(words[:len(path)], path) {
		words = words[len(path):]
	}
	if r := riskOf(f.cmd, words); r.typed != "" && len(targets) == 1 { // the rule table, risk.go
		items := riskArgs(words)
		if len(items) > 0 {
			items = items[1:] // what goes: the words after the target
		}
		of := r.items + " on " + targets[0]
		if len(items) == 0 {
			items, of = targets, "targets"
		}
		fmt.Fprintln(promptW, "This "+r.typed+".")
		want, shown := typedAnswer(items, of)
		ok, err := askTypeName(want, shown)
		if err != nil {
			return err
		}
		if !ok {
			return promptNo()
		}
		promptConfirmed = "typed " + want + ": " + r.typed
		return nil
	}
	for {
		v, err := askRun()
		if err != nil {
			return err
		}
		switch v {
		case "y":
			promptConfirmed = "Run it?"
			return nil
		case "n":
			return promptNo()
		}
		dry := formDry([][]string{filled})
		fmt.Fprintln(promptW, "$ komando "+out.MaskSecrets(menuCommandLine(dry)))
		if self, err := os.Executable(); err == nil {
			_, _ = menuRunOne(self, dry)
		}
	}
}

// promptNo is a no to a question komando asked before running something:
// exit 6, like a no at any safety question (S-8.9). Ctrl-C there is
// promptStopped (CANCELLED, exit 1).
func promptNo() error {
	return (&out.Error{Code: "DECLINED", Message: "not run: the person said no; nothing was changed", Hint: "run it again to be asked again", Exit: out.ExitPolicy}).NoFlag().Cancel("Cancelled. Nothing was changed.")
}

// promptStopped is a stop at a question: Ctrl-C, no answer, too many wrong
// answers.
func promptStopped(err error) error {
	var oe *out.Error
	var done fillDone
	if errors.As(err, &oe) || errors.As(err, &done) {
		return err
	}
	return (&out.Error{Code: "CANCELLED", Message: "interrupted; nothing was run", Hint: "run it again", Exit: out.ExitError}).Cancel("Stopped.")
}

// promptConfirmed is what the person said yes to before the command ran
// (Run it?, the name typed); the audit records it as confirm: tty.
var promptConfirmed string
