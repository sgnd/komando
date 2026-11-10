package cli

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/store"
)

// The menu is what `komando` alone opens for a person at a terminal: pick
// what to do with the arrow keys and Enter, pick a server the same way
// (type to filter), and komando runs that command as if it was typed, then
// comes back. It only starts commands the person could type themselves, so
// every safety check and question works as it does on the command line.
// Everyone else (AI agents, scripts, pipes, any flag) gets the first steps
// (docs/design/ux.md, section 10).

// menuWanted: `komando` alone, no flags, and a person at a terminal that
// can draw (stdin, stdout and stderr are terminals, no agent, TERM is not
// dumb).
func menuWanted(cmd *cobra.Command, args []string) bool {
	return menuGate(cmd, args, interactive() && term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("TERM") != "dumb")
}

// menuGate is menuWanted without the terminal checks, so tests can try it:
// any argument or flag (also -o text or --dry-run) keeps the first steps.
func menuGate(cmd *cobra.Command, args []string, person bool) bool {
	return person && len(args) == 0 && cmd.Flags().NFlag() == 0
}

// menuAction is one row of the main menu.
type menuAction struct {
	name, detail string
	args         []string // the komando command it runs, when it runs one at once
	// pick is the screen it opens instead: "servers", "services", "vpns",
	// "running", "add", "add-server", "check", "history", "settings"
	pick string
	// ownExit: the command is a session that ends with its own line
	// ("komando: left web1 (exit 0, 12m)"), so the menu does not say it again.
	ownExit bool
}

// The rows of the main menu, in the order menuMainActions shows them.
var (
	serversAction   = menuAction{name: "Servers", pick: "servers"}
	servicesAction  = menuAction{name: "Databases and services", pick: "services"}
	vpnsAction      = menuAction{name: "VPNs", pick: "vpns"}
	statusAction    = menuAction{name: "Running now", detail: "Jobs, tunnels, VPNs and logins komando left running", pick: "running"}
	addAction       = menuAction{name: "Add something", detail: "A server, a database, a VPN or another service", pick: "add"}
	checkAction     = menuAction{name: "Check everything", detail: "See if every server and service answers", pick: "check"}
	historyAction   = menuAction{name: "History and undo", detail: "What komando and your AI agent changed, and how to put it back", pick: "history"}
	settingsAction  = menuAction{name: "Settings and help", detail: "AI agent, passwords, production servers, SSH keys", pick: "settings"}
	addServerAction = menuAction{name: "Add a server", detail: "Its address and the user you log in with", pick: "add-server"}
	importAction    = menuAction{name: "Bring in my SSH servers", args: []string{"import", "ssh-config"}}
	agentAction     = menuAction{name: "Set up my AI agent", detail: "Lets Claude, Codex, Cursor or Gemini use komando", args: []string{"guide", "install"}}
)

// checkLines is what Check everything runs.
var checkLines = [][]string{{"test", "all"}, {"doctor"}}

// menuWelcome is said above the rows while komando knows nothing yet.
const menuWelcome = "Welcome to komando. Start by adding a server."

// menuNothingAdded is said once after a person cancels an Add;
// menuNothingRun after they cancel any other form.
const (
	menuNothingAdded = "Nothing was added."
	menuNothingRun   = "Nothing was run."
)

// menuHelpKey is the value the ? key gives on any list of the menu.
const menuHelpKey = "\x00help"

// errMenuQuit: the person left the menu.
var errMenuQuit = errors.New("menu: quit")

// menuMemory is what the menu remembers between commands, so a person who
// checked node-087 finds Servers and node-087 under the cursor next time.
// It is kept by name, not by place, and only while the menu is open.
type menuMemory struct{ action, target, task string }

// menuNext is what the menu runs after a person chose it.
type menuNext struct {
	cmds    [][]string
	ownExit bool
}

// runMenu shows the menu until the person quits. Whatever happens, the
// terminal is put back as it was.
//
// It does not use the command's context: Execute cancels that on Ctrl-C,
// and Ctrl-C while a command runs is meant for that command, which gets it
// too (same process group). The menu stops on SIGTERM only; in the menu
// itself the terminal is raw, so Ctrl-C arrives as a key (keyQuit).
func runMenu() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	t, err := newMenuTerm()
	if err != nil {
		return err
	}
	defer t.leave()
	var mem menuMemory
	for {
		st, err := loadState()
		if err != nil {
			return err
		}
		try := func(args []string) error { // Try it first, from a form's review
			again, err := menuRun(ctx, t, self, [][]string{args}, false, "the questions")
			if err == nil && !again {
				err = errMenuQuit // q after Try it first: leave the menu
			}
			return err
		}
		next, err := menuPickCommand(ctx, t, st, &mem, try)
		if errors.Is(err, errMenuQuit) || errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}
		if again, err := menuRun(ctx, t, self, next.cmds, next.ownExit, "the menu"); err != nil || !again {
			return err
		}
	}
}

// menuPickCommand shows the main menu and the screens under it until the
// person picks something to run. Esc on any screen goes back one step.
func menuPickCommand(ctx context.Context, t *menuTerm, st *store.State, mem *menuMemory, try formTry) (menuNext, error) {
	acts := menuMainActions(st, sshConfigNew(st))
	main := menuMain(acts)
	if menuEmpty(st) {
		main.note = menuWelcome
	}
	main.point(mem.action)
	scr := menuScreen{header: menuHeader(st), color: colorOK()}
	for {
		row, err := menuAsk(ctx, t, main, scr, menuHelpMain)
		if err != nil {
			return menuNext{}, err
		}
		main.note = ""
		i := slices.IndexFunc(acts, func(a menuAction) bool { return a.name == row.value })
		if i < 0 {
			continue
		}
		act := acts[i]
		mem.action = act.name
		next, err := menuOpen(ctx, t, st, mem, act, scr, try)
		switch {
		case errors.Is(err, errMenuBack):
			continue
		case errors.Is(err, errFormCancel):
			main.note = menuNothingRun
			if act.pick == "add" || act.pick == "add-server" {
				main.note = menuNothingAdded
			}
			continue
		}
		return next, err
	}
}

// menuOpen is what one row of the main menu does.
func menuOpen(ctx context.Context, t *menuTerm, st *store.State, mem *menuMemory, act menuAction, scr menuScreen, try formTry) (menuNext, error) {
	switch act.pick {
	case "":
		return menuNext{cmds: [][]string{act.args}, ownExit: act.ownExit}, nil
	case "check":
		return menuNext{cmds: checkLines}, nil
	case "add-server":
		cmds, err := formChoose(ctx, t, st, formGroupsFor("host"), scr, try)
		return menuNext{cmds: cmds}, err
	case "add":
		return menuAdd(ctx, t, st, scr, try)
	case "history":
		return menuTaskList(ctx, t, st, mem, scr, "History and undo: what do you want to do?", "", historyTasks, menuHelpHistory, try)
	case "settings":
		return menuTaskList(ctx, t, st, mem, scr, "Settings and help: what do you want to do?", "", settingsTasks(), menuHelpSettings, try)
	case "running":
		return menuRunning(ctx, t, st, mem, scr, try)
	}
	// servers, services or VPNs: pick one, then what to do with it
	list := menuItems(st, act.pick)
	if len(list.rows) == 0 { // nothing of this kind yet: add one
		groups := formGroupsFor("host")
		switch act.pick {
		case "services":
			groups = menuAddGroups("Something else")
			groups = append(menuAddGroups("Database"), groups...)
		case "vpns":
			groups = formGroupsFor("vpn")
		}
		cmds, err := formChoose(ctx, t, st, groups, scr, try)
		if errors.Is(err, errFormCancel) {
			return menuNext{}, errMenuBack
		}
		return menuNext{cmds: cmds}, err
	}
	list.point(mem.target)
	for {
		row, err := menuAsk(ctx, t, list, scr, menuHelpItems)
		if err != nil {
			return menuNext{}, err
		}
		mem.target = row.value
		list.point(row.value)
		kind, tasks := menuItemTasks(st, row.value)
		title := menuItemTitle(st, kind, row.value)
		next, err := menuTaskList(ctx, t, st, mem, scr, title, row.value, tasks, menuHelpTasks, try)
		if errors.Is(err, errMenuBack) {
			continue
		}
		return next, err
	}
}

// menuAdd is Add something: what it is first, then its questions.
func menuAdd(ctx context.Context, t *menuTerm, st *store.State, scr menuScreen, try formTry) (menuNext, error) {
	l := &menuList{title: "Add something: what is it?", hot: menuHot()}
	for _, r := range menuAddRows {
		l.rows = append(l.rows, menuRow{label: r.label, detail: r.detail, value: r.label})
	}
	for {
		row, err := menuAsk(ctx, t, l, scr, menuHelpAdd)
		if err != nil {
			return menuNext{}, err
		}
		l.point(row.value)
		var cmds [][]string
		if row.value == "Bring in what I have" {
			var next menuNext
			next, err = menuTaskList(ctx, t, st, &menuMemory{}, scr, "Bring in what I have: from where?", "", importTasks, menuHelpAdd, try)
			cmds = next.cmds
		} else {
			cmds, err = formChoose(ctx, t, st, menuAddGroups(row.value), scr, try)
		}
		if errors.Is(err, errMenuBack) {
			continue
		}
		return menuNext{cmds: cmds}, err
	}
}

// menuAddRows is the Add something list. Each row but the last opens the
// add forms of these formGroups labels.
var menuAddRows = []struct {
	label, detail string
	groups        []string
}{
	{"Server", "A Linux or Windows machine you log in to", []string{"Server"}},
	{"Database", "PostgreSQL, MySQL, SQL Server, Oracle, MongoDB and others", []string{"Database"}},
	{"VPN", "WireGuard, OpenVPN, Tailscale or your company's VPN app", []string{"VPN"}},
	{"Something else", "A cache, a message queue, file storage, a cluster or a container registry",
		[]string{"Cache", "Message queues", "File storage", "Kubernetes", "Container registry"}},
	{"Bring in what I have", "From ~/.ssh/config, .pgpass, my.cnf or a .env file", nil},
}

// menuAddGroups is the add forms of one Add something row.
func menuAddGroups(label string) []formGroup {
	i := slices.IndexFunc(menuAddRows, func(r struct {
		label, detail string
		groups        []string
	}) bool {
		return r.label == label
	})
	var gs []formGroup
	for _, g := range formGroups() {
		if i >= 0 && slices.Contains(menuAddRows[i].groups, g.label) {
			gs = append(gs, g)
		}
	}
	return gs
}

// menuTask is one thing to do with an item (a server, a database ...), or
// a list of more such things (sub).
type menuTask struct {
	label, detail string
	// cmd is the komando command (its key, "db query"); its questions are
	// asked in the guided form, with fill already answered
	cmd string
	// fill answers the command's arguments by position: "{}" is the item
	// (web1, @web), "{name}" the item without @, "" asks. nil fills the
	// first argument with the item; noItem fills nothing.
	fill   []string
	noItem bool
	// line runs these command lines at once, with {} and {name} filled in
	line [][]string
	// sub opens a list of its own; title is its question
	sub   []menuTask
	title string
	// confirm is asked first ({} is the item), yes is the row that goes on
	confirm, yes string
	ownExit      bool
}

// menuTaskList shows tasks for item and does the one chosen: a sub list,
// a command line, or the guided form of a command with item filled in.
func menuTaskList(ctx context.Context, t *menuTerm, st *store.State, mem *menuMemory, scr menuScreen, title, item string, tasks []menuTask, help string, try formTry) (menuNext, error) {
	l := &menuList{title: title, hot: menuHot(), typing: len(tasks) > 12}
	for _, tk := range tasks {
		d := tk.detail
		if tk.sub != nil && d == "" {
			d = menuSubDetail(tk.sub)
		}
		l.rows = append(l.rows, menuRow{label: tk.label, detail: d, value: tk.label})
	}
	l.point(mem.task)
	for {
		row, err := menuAsk(ctx, t, l, scr, help)
		if err != nil {
			return menuNext{}, err
		}
		l.point(row.value)
		mem.task = row.value
		tk := tasks[slices.IndexFunc(tasks, func(x menuTask) bool { return x.label == row.value })]
		next, err := menuDoTask(ctx, t, st, mem, scr, item, tk, try)
		if errors.Is(err, errMenuBack) {
			continue
		}
		if errors.Is(err, errFormCancel) {
			l.note = menuNothingRun
			continue
		}
		return next, err
	}
}

// menuSubDetail names the first few rows of a sub list.
func menuSubDetail(sub []menuTask) string {
	var names []string
	for _, s := range sub[:min(4, len(sub))] {
		names = append(names, strings.ToLower(s.label[:1])+s.label[1:])
	}
	d := strings.Join(names, ", ")
	if len(sub) > 4 {
		d += " and more"
	}
	return d
}

// menuDoTask does one task for item.
func menuDoTask(ctx context.Context, t *menuTerm, st *store.State, mem *menuMemory, scr menuScreen, item string, tk menuTask, try formTry) (menuNext, error) {
	if tk.sub != nil {
		title := tk.title
		if title == "" {
			title = tk.label + ": what do you want to do?"
			if item != "" {
				title = item + ", " + strings.ToLower(tk.label[:1]) + tk.label[1:] + ": what do you want to do?"
			}
		}
		sub := &menuMemory{}
		return menuTaskList(ctx, t, st, sub, scr, title, item, tk.sub, menuHelpTasks, try)
	}
	if tk.confirm != "" {
		ok, err := menuConfirm(ctx, t, scr, menuFill(tk.confirm, item), tk.yes)
		if err != nil || !ok {
			return menuNext{}, cmp.Or(err, errMenuBack)
		}
	}
	if tk.line != nil {
		var cmds [][]string
		for _, l := range tk.line {
			cmds = append(cmds, menuFillLine(l, item))
		}
		return menuNext{cmds: cmds, ownExit: tk.ownExit}, nil
	}
	c, _, err := newRoot().Find(strings.Fields(tk.cmd))
	if err != nil {
		return menuNext{}, err
	}
	if h := formHints[tk.cmd]; h.form != nil { // a hand-made form (login)
		cmds, err := formChoose(ctx, t, st, h.form(), scr, try)
		return menuNext{cmds: cmds}, err
	}
	sp, ready := menuTaskSpec(st, c, tk, item)
	if ready { // nothing to ask and it only reads: run it
		return menuNext{cmds: sp.build(st, formAnswers{}), ownExit: tk.ownExit}, nil
	}
	cmds, err := formFill(ctx, t, st, sp, scr, formTryFor(c, try))
	return menuNext{cmds: cmds, ownExit: tk.ownExit}, err
}

// menuTaskSpec is the guided form of a task's command with the item
// already answered: those questions are not asked, and every check, list
// and default sees their answers. ready: no question is left before the
// review and the command only reads, so the menu runs it at once.
func menuTaskSpec(st *store.State, c *cobra.Command, tk menuTask, item string) (formSpec, bool) {
	sp := formCmdSpec(c)
	given := menuGiven(tk, item)
	if item != "" {
		sp.title = item + ": " + tk.label
	}
	with := func(a formAnswers) formAnswers {
		m := maps.Clone(a)
		if m == nil {
			m = formAnswers{}
		}
		maps.Copy(m, given)
		return m
	}
	var qs []formQ
	for _, q := range sp.qs {
		if _, ok := given[q.key]; ok {
			continue
		}
		if f := q.show; f != nil {
			q.show = func(a formAnswers) bool { return f(with(a)) }
		}
		if f := q.def; f != nil {
			q.def = func(st *store.State, a formAnswers) string { return f(st, with(a)) }
		}
		if f := q.choices; f != nil {
			q.choices = func(st *store.State, a formAnswers) []menuRow { return f(st, with(a)) }
		}
		if f := q.check; f != nil {
			q.check = func(st *store.State, a formAnswers, v string) string { return f(st, with(a), v) }
		}
		qs = append(qs, q)
	}
	sp.qs = qs
	build := sp.build
	sp.build = func(st *store.State, a formAnswers) [][]string { return build(st, with(a)) }
	ready := !slices.ContainsFunc(qs, func(q formQ) bool { return !q.advanced && q.visible(st, formAnswers{}) })
	if k, ok := kindOf(c); !ok || k.Kind != kindRead {
		ready = false
	}
	return sp, ready
}

// menuGiven is a task's answers given before any question.
func menuGiven(tk menuTask, item string) formAnswers {
	fill := tk.fill
	if fill == nil && !tk.noItem && item != "" {
		fill = []string{"{}"}
	}
	given := formAnswers{}
	for i, f := range fill {
		if f != "" {
			given["arg"+strconv.Itoa(i)] = menuFill(f, item)
		}
	}
	return given
}

// menuFill puts the item in for {} and its name without @ for {name}.
func menuFill(s, item string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "{name}", strings.TrimPrefix(item, "@")), "{}", item)
}

func menuFillLine(l []string, item string) []string {
	out := make([]string, len(l))
	for i, w := range l {
		out[i] = menuFill(w, item)
	}
	return out
}

// menuConfirm asks a yes or no question; No is first, so Enter alone
// never does the thing.
func menuConfirm(ctx context.Context, t *menuTerm, scr menuScreen, question, yes string) (bool, error) {
	l := &menuList{title: question, rows: []menuRow{{label: "No, go back", value: "no"}, {label: cmp.Or(yes, "Yes"), value: "yes"}}}
	row, err := menuAsk(ctx, t, l, scr, menuHelpConfirm)
	if errors.Is(err, errMenuBack) {
		return false, nil
	}
	return row.value == "yes", err
}

// menuHot is the hot keys of every menu list: ? explains the screen.
func menuHot() map[rune]string { return map[rune]string{'?': menuHelpKey} }

// menuKeysFor is the key help under a list.
func menuKeysFor(l *menuList) string {
	more := []string{"Esc back"}
	if l.title == "" {
		more = nil // Esc on the main menu leaves
	}
	if !l.typing {
		more = append(more, "? help")
	}
	return listKeys(l, append(more, "q quit")...)
}

// menuAsk shows l until a row is chosen; ? shows the screen's help and
// comes back to it.
func menuAsk(ctx context.Context, t *menuTerm, l *menuList, scr menuScreen, help string) (menuRow, error) {
	scr.footer = menuKeysFor(l)
	for {
		row, err := menuChoose(ctx, t, l, scr)
		if err != nil || row.value != menuHelpKey {
			return row, err
		}
		again, err := menuHelp(ctx, t, help)
		if err != nil {
			return menuRow{}, err
		}
		if !again {
			return menuRow{}, errMenuQuit
		}
	}
}

// errMenuBack: Esc on a list that has one before it.
var errMenuBack = errors.New("menu: back")

// menuShow draws l and hands each key to handle until it says the screen
// is done. It redraws only after a key or a resize.
func menuShow(ctx context.Context, t *menuTerm, l *menuList, s menuScreen, handle func(k menuKey, page int) (bool, error)) error {
	if err := t.enter(); err != nil {
		return err
	}
	lastW, lastH, dirty := 0, 0, true
	for {
		w, h := t.size()
		if dirty || w != lastW || h != lastH {
			t.draw(l.render(s, w, h))
			lastW, lastH = w, h
		}
		keys, err := t.keys(ctx)
		if err != nil {
			return err
		}
		dirty = len(keys) > 0
		for _, k := range keys {
			if done, err := handle(k, l.pageSize(s, w, h)); done || err != nil {
				return err
			}
		}
	}
}

// menuChoose shows one list until a row is chosen. Esc on the main menu
// quits; on any other list it goes back.
func menuChoose(ctx context.Context, t *menuTerm, l *menuList, s menuScreen) (menuRow, error) {
	var row menuRow
	err := menuShow(ctx, t, l, s, func(k menuKey, page int) (bool, error) {
		switch l.update(k, page) {
		case menuChosen:
			row, _ = l.chosen()
			return true, nil
		case menuQuit:
			return true, errMenuQuit
		case menuBack:
			if l.title == "" {
				return true, errMenuQuit
			}
			return true, errMenuBack
		}
		return false, nil
	})
	return row, err
}

// --- what each kind of item offers ---

// --- screens not tied to one item ---
