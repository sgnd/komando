package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
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

// menuAction is one thing the main menu does.
type menuAction struct {
	name, detail string
	args         []string // the komando command it runs
	// pick is what the menu asks for before it runs args, and adds to them:
	// "host" a server, "target" anything `test` takes (or all), "db" a
	// database conn, "vpn" a VPN, "form" the guided add (form.go).
	pick string
	// ownExit: the command is a session that ends with its own line
	// ("komando: left web1 (exit 0, 12m)"), so the menu does not say it again.
	ownExit bool
}

// The menu's actions. menuMainActions shows the ones that apply.
var (
	importAction = menuAction{"Import", "Bring in the servers from ~/.ssh/config", []string{"import", "ssh-config"}, "", false}
	addAction    = menuAction{"Add", "A server, database, cache, queue, storage, cluster, VPN ...", nil, "form", false}
	shellAction  = menuAction{"Shell", "Open a login shell on a server", []string{"shell"}, "host", true}
	testAction   = menuAction{"Test", "Check that servers, conns and VPNs answer", []string{"test"}, "target", false}
	factsAction  = menuAction{"Facts", "OS, updates, Docker and open ports of a server", []string{"facts"}, "host", false}
	dbAction     = menuAction{"Database", "Open a SQL shell on a database", []string{"db", "shell"}, "db", true}
	vpnAction    = menuAction{"VPN", "Connect a VPN (and log in), or disconnect one", []string{"vpn", "up"}, "vpn", false}
	agentAction  = menuAction{"AI agent", "Teach your AI agents to use komando (once)", []string{"guide", "install"}, "", false}
	listAction   = menuAction{"List", "Everything komando knows about", []string{"list"}, "", false}
	doctorAction = menuAction{"Doctor", "Check your setup, the inventory and its security", []string{"doctor"}, "", false}
	allAction    = menuAction{"All features", "Everything komando does, by area, as questions", nil, "all", false}
	// helpAction is the ? key, not a row: what komando does, by task
	helpAction = menuAction{"Help", "What komando does, by task", nil, "", false}
)

// menuNoServer is said under the header while komando knows nothing yet.
const menuNoServer = "Nothing here yet. Add asks for a name, an address and a user, one at a time."

// menuNothingAdded is said once after a person cancels an Add;
// menuNothingRun after they cancel a command from All features.
const (
	menuNothingAdded = "Nothing was added."
	menuNothingRun   = "Nothing was run."
)

// errMenuQuit: the person left the menu.
var errMenuQuit = errors.New("menu: quit")

// menuMemory is what the menu remembers between commands, so a person who
// runs Facts on node-087 finds Facts and node-087 under the cursor next
// time. It is kept by name, not by place, and only while the menu is open.
type menuMemory struct{ action, target string }

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
		act, cmds, err := menuPickCommand(ctx, t, st, &mem, try)
		if errors.Is(err, errMenuQuit) || errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}
		run := func() (bool, error) { return menuRun(ctx, t, self, cmds, act.ownExit, "the menu") }
		if act.name == helpAction.name {
			run = func() (bool, error) { return menuHelp(ctx, t) }
		}
		if again, err := run(); err != nil || !again {
			return err
		}
	}
}

// menuPickCommand asks what to do and, for an action on a server, conn or
// VPN, which one, and gives the commands to run (Add runs the add, then a
// test). Esc on the second list goes back to the actions.
func menuPickCommand(ctx context.Context, t *menuTerm, st *store.State, mem *menuMemory, try formTry) (menuAction, [][]string, error) {
	acts := menuMainActions(st, sshConfigExists(), sshConfigHasNew(st), !agentSkillInstalled())
	main := menuMain(acts)
	if len(st.Hosts)+len(st.Conns)+len(st.Vpns) == 0 {
		main.note = menuNoServer
	}
	main.point(mem.action)
	scr := menuScreen{header: menuHeader(st), color: colorOK(), footer: listKeys(main, "? help", "q quit")}
	for {
		row, err := menuChoose(ctx, t, main, scr)
		if err != nil {
			return menuAction{}, nil, err
		}
		main.note = ""
		act := helpAction
		if i := slices.IndexFunc(acts, func(a menuAction) bool { return a.name == row.value }); i >= 0 {
			act = acts[i]
		}
		mem.action = act.name
		switch act.pick {
		case "":
			return act, [][]string{act.args}, nil
		case "form", "all":
			var cmds [][]string
			if act.pick == "all" {
				cmds, err = formAllFeatures(ctx, t, st, scr, try)
			} else {
				cmds, err = formChoose(ctx, t, st, formGroups(), scr, try)
			}
			if errors.Is(err, errMenuBack) {
				continue
			}
			if errors.Is(err, errFormCancel) {
				main.note = menuNothingAdded
				if act.pick == "all" {
					main.note = menuNothingRun
				}
				continue
			}
			return act, cmds, err
		}
		list := menuTargets(st, act)
		list.point(mem.target)
		lscr := scr
		lscr.footer = listKeys(list, "Esc back", "Ctrl-C quit")
		row, err = menuChoose(ctx, t, list, lscr)
		if errors.Is(err, errMenuBack) {
			continue
		}
		if err != nil {
			return menuAction{}, nil, err
		}
		mem.target = row.value
		if act.pick == "vpn" && menuVpnUp(st, row.value) {
			return act, [][]string{{"vpn", "down", row.value}}, nil // up: choosing it disconnects
		}
		return act, [][]string{append(slices.Clone(act.args), row.value)}, nil
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

// menuRun runs komando commands in the normal screen, one after the other
// until one fails: each command line first, so the person learns it, then
// its output, then how the last one ended. Then it waits (Enter goes back,
// q quits) and erases the key help, so the scrollback keeps only the
// commands, their output and how they ended.
//
// back is where Enter goes: "the menu", or "the questions" after Try it
// first.
func menuRun(ctx context.Context, t *menuTerm, self string, cmds [][]string, ownExit bool, back string) (bool, error) {
	t.leave()
	result := "exit 0"
	for _, args := range cmds {
		fmt.Fprintf(os.Stderr, "$ komando %s\n", menuCommandLine(args))
		code, err := menuRunOne(self, args)
		// a command that died without undoing raw mode (killed, crashed) must
		// not leave its terminal modes to the menu or to the next command
		t.restoreOrig()
		if err != nil {
			return false, err
		}
		if code != 0 {
			result = fmt.Sprintf("exit %d", code)
			if code < 0 { // ended by a signal, most likely Ctrl-C
				result = "stopped"
			}
			break
		}
	}
	if ownExit && result == "exit 0" {
		result = "" // "komando: left web1 (exit 0, 12m)" said it already
	}
	keys := "Enter back to " + back + " · q quit "
	if result != "" {
		keys = result + " · " + keys
	}
	// one row at most: "\r\x1b[2K" below erases only the row it is on
	w, _ := t.size()
	fmt.Fprintf(os.Stderr, "\n%s", fit([]seg{{keys, ""}}, w-1, false))
	again, err := menuPause(ctx, t)
	fmt.Fprint(os.Stderr, "\r\x1b[2K")
	if result != "" {
		fmt.Fprintln(os.Stderr, result)
	}
	return again, err
}

// menuRunOne runs one komando command on this terminal: its exit code, -1
// when a signal ended it.
func menuRunOne(self string, args []string) (int, error) {
	err := menuCommand(self, args).Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	}
	return 0, err
}

// menuPause waits for Enter or Esc (back to the menu) or q (quit). Keys
// typed while the command ran are thrown away first.
func menuPause(ctx context.Context, t *menuTerm) (bool, error) {
	if _, err := term.MakeRaw(t.in); err != nil {
		return false, err
	}
	defer t.restoreOrig()
	_ = dropTypedAhead(t.in)
	t.pending = nil
	for {
		keys, err := t.keys(ctx)
		if err != nil {
			return false, nil
		}
		for _, k := range keys {
			switch {
			case k.kind == keyEnter || k.kind == keyEsc:
				return true, nil
			case k.kind == keyQuit || k.kind == keyRune && (k.r == 'q' || k.r == 'Q'):
				return false, nil
			}
		}
	}
}

// menuCommandLine is args as a person would type them: a word a shell
// would read differently is quoted, so the line can be copied.
func menuCommandLine(args []string) string {
	words := make([]string, len(args))
	for i, a := range args {
		words[i] = a
		safe := a != "" && !strings.ContainsFunc(a, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./_-", r))
		})
		if !safe {
			words[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return cleanText(strings.Join(words, " "))
}

// menuCommand is the komando command the menu runs, on this terminal. It
// is not tied to a context: Ctrl-C stops the command, not the menu. Its
// environment is komando's own (vault.SelfEnv): komando took
// KOMANDO_VAULT_PASS out of its environment when it started, and the
// command needs it to open a passphrase vault, as it would when typed. The
// command takes it out again before it starts anything else.
func menuCommand(self string, args []string) *exec.Cmd {
	c := exec.Command(self, args...)
	c.Env = vault.SelfEnv()
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c
}

// sshConfigExists: Import has something to read.
func sshConfigExists() bool {
	_, err := os.Stat(expandHome("~/.ssh/config"))
	return err == nil
}

// sshConfigHasNew: ~/.ssh/config names a server komando does not know yet,
// so Import still brings something in.
func sshConfigHasNew(st *store.State) bool {
	hosts, _, err := parseSSHConfig(expandHome("~/.ssh/config"))
	if err != nil {
		return false
	}
	for _, h := range hosts {
		if _, _, known := st.FindName(h.Name); !known {
			return true
		}
	}
	return false
}

// menuVpnUp: komando keeps a session of this VPN up. The process is checked
// by its pid only, as `komando prompt` does: the list must draw at once.
func menuVpnUp(st *store.State, name string) bool {
	s := st.Sessions[name]
	return s != nil && netx.Alive(s.PID)
}

// menuHelpTasks is the ? screen: what komando does, by task, and the
// commands for it.
var menuHelpTasks = []struct {
	task string
	cmds []string
}{
	{"See everything, check it", []string{"komando list", "komando test all", "komando status"}},
	{"Servers", []string{"komando host add", "komando shell", "komando exec"}},
	{"Health and facts", []string{"komando facts", "komando recipe run health"}},
	{"Files", []string{"komando fs cat", "komando upload", "komando download"}},
	{"Services, logs, packages", []string{"komando svc", "komando logs", "komando pkg"}},
	{"Databases and caches", []string{"komando conn add", "komando db", "komando cache"}},
	{"Storage and message queues", []string{"komando storage", "komando queue"}},
	{"Clusters and registries", []string{"komando cluster status", "komando registry ls"}},
	{"VPNs", []string{"komando vpn add", "komando vpn up", "komando vpn down"}},
	{"Passwords", []string{"komando secret set NAME"}},
	{"History and safety", []string{"komando audit", "komando doctor"}},
	{"AI agents", []string{"komando guide install"}},
}

// menuHelpFor is the ? screen for a terminal this wide: a task and its
// commands on one line when every line fits, else the task on its line and
// its commands under it, cut between commands, so a narrow terminal does
// not wrap a command in two.
func menuHelpFor(width int) string {
	const col = 26 // the longest task
	wide := true
	for _, h := range menuHelpTasks {
		wide = wide && 2+col+1+displayWidth(strings.Join(h.cmds, " · ")) <= width
	}
	var b strings.Builder
	b.WriteString("What komando does, by task:\n\n")
	for _, h := range menuHelpTasks {
		cmds := strings.Join(h.cmds, " · ")
		if wide {
			fmt.Fprintf(&b, "  %-*s %s\n", col, h.task, cmds)
			continue
		}
		fmt.Fprintf(&b, "  %s\n", h.task)
		for _, l := range keyLines(cmds, width-5) {
			fmt.Fprintf(&b, "    %s\n", l)
		}
	}
	b.WriteString("\n")
	for _, l := range keyLines("Every command: komando --help · one command: komando COMMAND --help", width-1) {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// menuHelp shows the ? screen in the normal screen, at the terminal's
// width, then waits like a command's end: Enter back to the menu, q quits.
func menuHelp(ctx context.Context, t *menuTerm) (bool, error) {
	t.leave()
	w, _ := t.size()
	fmt.Fprint(os.Stderr, menuHelpFor(w))
	fmt.Fprintf(os.Stderr, "\n%s", fit([]seg{{"Enter back to the menu · q quit ", ""}}, w-1, false))
	again, err := menuPause(ctx, t)
	fmt.Fprint(os.Stderr, "\r\x1b[2K")
	return again, err
}

// menuMainActions is the main menu for this inventory: only the actions
// that have something to act on, counted as the lists count it (a name
// they leave out does not count). While there is no server, Add (and
// Import, when ~/.ssh/config exists) come first; Shell and Facts need a
// server, Test anything to test, Database a database conn and VPN a VPN.
// Add is always there, after the actions once there is a server. Import
// (while ~/.ssh/config holds servers komando does not know) and AI agent
// (while no agent has komando's skill) show when the number keys can
// still reach them: 9 rows at most.
func menuMainActions(st *store.State, sshConfig, newInSSHConfig, skillMissing bool) []menuAction {
	var acts []menuAction
	hosts := len(menuNames(st.Hosts, "host")) > 0
	conns := menuNames(st.Conns, "conn")
	vpns := len(menuNames(st.Vpns, "vpn")) > 0
	if !hosts {
		if sshConfig {
			acts = append(acts, importAction)
		}
		acts = append(acts, addAction)
	}
	if hosts {
		acts = append(acts, shellAction)
	}
	if hosts || len(conns) > 0 || vpns {
		acts = append(acts, testAction)
	}
	if hosts {
		acts = append(acts, factsAction)
	}
	if slices.ContainsFunc(conns, func(n string) bool { return connFamily(st.Conns[n]) == "db" }) {
		acts = append(acts, dbAction)
	}
	if vpns {
		acts = append(acts, vpnAction)
	}
	if hosts {
		acts = append(acts, addAction)
	}
	last := []menuAction{allAction, listAction, doctorAction}
	for _, opt := range []struct {
		show bool
		act  menuAction
	}{{hosts && newInSSHConfig, importAction}, {skillMissing, agentAction}} {
		if opt.show && len(acts)+1+len(last) <= 9 {
			acts = append(acts, opt.act)
		}
	}
	return append(acts, last...)
}

func menuMain(acts []menuAction) *menuList {
	l := &menuList{empty: "nothing to do", hot: map[rune]string{'?': helpAction.name}}
	for _, a := range acts {
		l.rows = append(l.rows, menuRow{label: a.name, detail: a.detail, value: a.name})
	}
	return l
}

// menuTargets is the list an action picks from: servers for Shell and
// Facts, database conns for Database, VPNs for VPN, and for Test all of
// them (and all), each kind sorted by name.
func menuTargets(st *store.State, act menuAction) *menuList {
	l := &menuList{typing: true}
	switch act.pick {
	case "host":
		l.title = act.name + ": which server?"
		l.empty = "no server yet; Esc goes back, then Add or Import brings one in"
		l.rows = menuHostRows(st)
	case "target":
		l.title = act.name + ": which one?"
		l.empty = "nothing to test yet"
		l.rows = append([]menuRow{{label: "all", detail: "every server, conn and VPN", value: "all"}}, menuHostRows(st)...)
		l.rows = append(append(l.rows, menuConnRows(st, "")...), menuVpnRows(st)...)
	case "db":
		l.title = act.name + ": which one?"
		l.empty = "no database yet; Esc goes back, then Add brings one in"
		l.rows = menuConnRows(st, "db")
	case "vpn":
		l.title = act.name + ": which one?"
		l.empty = "no VPN yet; Esc goes back, then Add brings one in"
		l.rows = menuVpnRows(st)
	}
	return l
}

// menuNames is the names a list may offer, sorted. A name the inventory
// would not accept today (a hand-edited state file, or "all" from before it
// was refused) is left out: the menu passes the name as an argument, where
// one starting with - would be read as a flag and "all" would pick
// everything.
func menuNames[T any](m map[string]T, kind string) []string {
	var names []string
	for n := range m {
		if validName(kind, n) == nil {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names
}

func menuHostRows(st *store.State) []menuRow {
	var rows []menuRow
	for _, n := range menuNames(st.Hosts, "host") {
		rows = append(rows, menuRow{label: n, detail: menuHostDetail(st, st.Hosts[n]), value: n})
	}
	return rows
}

// menuConnRows is the conns of one family ("db"), or all with "".
func menuConnRows(st *store.State, family string) []menuRow {
	var rows []menuRow
	for _, n := range menuNames(st.Conns, "conn") {
		c := st.Conns[n]
		if family != "" && connFamily(c) != family {
			continue
		}
		rows = append(rows, menuRow{label: n, detail: menuConnDetail(st, c), value: n})
	}
	return rows
}

func menuVpnRows(st *store.State) []menuRow {
	var rows []menuRow
	for _, n := range menuNames(st.Vpns, "vpn") {
		v := st.Vpns[n]
		parts := []string{"vpn " + v.Kind}
		if menuVpnUp(st, n) {
			parts = []string{"up (Enter disconnects)", "vpn " + v.Kind}
		}
		if w := vpnWhere(v); w != "-" {
			parts = append(parts, w)
		}
		rows = append(rows, menuRow{label: n, detail: menuDetail(parts, v.Groups, v.Tags), value: n})
	}
	return rows
}

// menuHostDetail is whether the server is protected (first, so it is the
// last of the details a narrow screen cuts off), user@address[:port], the
// way there and its groups and tags.
func menuHostDetail(st *store.State, h *store.Host) string {
	addr := h.Address
	if h.User != "" {
		addr = h.User + "@" + addr
	}
	if h.Port != 0 && h.Port != 22 {
		addr += fmt.Sprintf(":%d", h.Port)
	}
	var parts []string
	if menuProtectedHost(st, h) {
		parts = append(parts, "protected")
	}
	parts = append(parts, addr)
	if h.Via != "" {
		parts = append(parts, "via "+h.Via)
	}
	return menuDetail(parts, h.Groups, h.Tags)
}

// menuConnDetail is protected, kind and where, as `komando list` shows
// them: never the URL itself, which may hold a user or a password.
func menuConnDetail(st *store.State, c *store.Conn) string {
	var parts []string
	if menuProtectedConn(st, c) {
		parts = append(parts, "protected")
	}
	parts = append(parts, c.Kind)
	if t, err := driver.Parse(c.URL); err == nil {
		parts = append(parts, t.Where())
	}
	if c.Via != "" {
		parts = append(parts, "via "+c.Via)
	}
	return menuDetail(parts, c.Groups, c.Tags)
}

// menuProtectedHost is protectedHost without asking DNS: the server's own
// mark, or a protected server at the same address and port, written the
// same way. protectedHost also looks names up (2s at most each), and the
// list must draw at once; the question before the command still checks
// everything.
func menuProtectedHost(st *store.State, h *store.Host) bool {
	if h.Protected {
		return true
	}
	for _, o := range st.Hosts {
		if o.Protected && o.EffectivePort() == h.EffectivePort() && sameHostName(o.Address, h.Address) {
			return true
		}
	}
	return false
}

// menuProtectedConn is protectedConn the same way: the conn's own mark, or
// a protected conn of the same family at the same address (or file, or
// bucket), written the same way.
func menuProtectedConn(st *store.State, c *store.Conn) bool {
	key := func(c *store.Conn) string {
		t, err := driver.Parse(c.URL)
		switch {
		case err != nil:
			return ""
		case t.Kind.File:
			return "file " + t.Path
		case t.Bucket != "":
			return "bucket " + normHostPort(t.Address) + "/" + t.Bucket
		}
		return t.Kind.Family + " " + normHostPort(t.Address)
	}
	if c.Protected {
		return true
	}
	k := key(c)
	for _, o := range st.Conns {
		if o.Protected && k != "" && key(o) == k {
			return true
		}
	}
	// an SFTP conn is an SSH server: protected when a protected host is it
	h := sftpHost(c)
	return h != nil && menuProtectedHost(st, h)
}

// menuDetail adds groups and tags, and cleans it all for the screen.
func menuDetail(parts, groups, tags []string) string {
	for _, g := range groups {
		parts = append(parts, "@"+g)
	}
	parts = append(parts, tags...)
	return cleanText(strings.Join(parts, "  "))
}

// menuHeader is the top line: komando, its version, and what it knows.
func menuHeader(st *store.State) []seg {
	counts := []string{menuCount(len(st.Hosts), "server")}
	if n := len(st.Conns); n > 0 {
		counts = append(counts, menuCount(n, "conn"))
	}
	if n := len(st.Vpns); n > 0 {
		vpns := menuCount(n, "VPN")
		up := 0
		for name := range st.Vpns {
			if menuVpnUp(st, name) {
				up++
			}
		}
		if up > 0 {
			vpns += fmt.Sprintf(" (%d up)", up)
		}
		counts = append(counts, vpns)
	}
	return []seg{{"komando", "1"}, {" · " + Version + " · " + strings.Join(counts, ", "), "2"}}
}

func menuCount(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
