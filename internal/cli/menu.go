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
// Everyone else (AI agents, scripts, pipes, any flag) gets the first steps,
// as before (docs/design/ux.md, section 10).

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
	// database conn, "vpn" a VPN, "line" a typed name and address.
	pick string
	// ownExit: the command is a session that ends with its own line
	// ("komando: left web1 (exit 0, 12m)"), so the menu does not say it again.
	ownExit bool
}

// The menu's actions. menuMainActions shows the ones that apply.
var (
	importAction = menuAction{"Import", "Bring in the servers from ~/.ssh/config", []string{"import", "ssh-config"}, "", false}
	addAction    = menuAction{"Add", "Add a server (name user@address) or a conn (name URL)", []string{"host", "add"}, "line", false}
	shellAction  = menuAction{"Shell", "Open a login shell on a server", []string{"shell"}, "host", true}
	testAction   = menuAction{"Test", "Check that servers, conns and VPNs answer", []string{"test"}, "target", false}
	factsAction  = menuAction{"Facts", "OS, updates, Docker and open ports of a server", []string{"facts"}, "host", false}
	dbAction     = menuAction{"Database", "Open a SQL shell on a database", []string{"db", "shell"}, "db", true}
	vpnAction    = menuAction{"VPN", "Connect a VPN (and log in), or disconnect one", []string{"vpn", "up"}, "vpn", false}
	agentAction  = menuAction{"AI agent", "Teach your AI agents to use komando (once)", []string{"guide", "install"}, "", false}
	listAction   = menuAction{"List", "Everything komando knows about", []string{"list"}, "", false}
	auditAction  = menuAction{"Audit", "The last 20 things komando did", []string{"audit", "--limit", "20"}, "", false}
	doctorAction = menuAction{"Doctor", "Check your setup, the inventory and its security", []string{"doctor"}, "", false}
	// helpAction is the ? key, not a row: what komando does, by task
	helpAction = menuAction{"Help", "What komando does, by task", nil, "", false}
)

// menuNoServer is said under the header while komando knows no server: the
// command line Add runs, so the person sees it before choosing.
const menuNoServer = "No servers yet. Add one: komando host add web1 deploy@10.0.0.5"

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
		act, args, err := menuPickCommand(ctx, t, st, &mem)
		if errors.Is(err, errMenuQuit) || errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}
		run := func() (bool, error) { return menuRun(ctx, t, self, args, act.ownExit) }
		if act.name == helpAction.name {
			run = func() (bool, error) { return menuHelp(ctx, t) }
		}
		if again, err := run(); err != nil || !again {
			return err
		}
	}
}

// menuPickCommand asks what to do and, for an action on a server, conn or
// VPN, which one. Esc on the second list goes back to the actions.
func menuPickCommand(ctx context.Context, t *menuTerm, st *store.State, mem *menuMemory) (menuAction, []string, error) {
	acts := menuMainActions(st, sshConfigExists(), sshConfigHasNew(st), !agentSkillInstalled())
	main := menuMain(acts)
	if slices.ContainsFunc(acts, func(a menuAction) bool { return a.name == addAction.name }) {
		main.note = menuNoServer
	}
	main.point(mem.action)
	scr := menuScreen{header: menuHeader(st), color: colorOK(),
		footer: fmt.Sprintf("↑↓ move · Enter or 1-%d choose · ? help · q quit", min(9, len(acts)))}
	for {
		row, err := menuChoose(ctx, t, main, scr)
		if err != nil {
			return menuAction{}, nil, err
		}
		act := helpAction
		if i := slices.IndexFunc(acts, func(a menuAction) bool { return a.name == row.value }); i >= 0 {
			act = acts[i]
		}
		mem.action = act.name
		switch act.pick {
		case "":
			return act, act.args, nil
		case "line":
			args, err := menuAskServer(ctx, t, scr)
			if errors.Is(err, errMenuBack) {
				continue
			}
			return act, args, err
		}
		list := menuTargets(st, act)
		list.point(mem.target)
		lscr := scr
		lscr.footer = "↑↓ move · Enter choose · Esc back · type to filter"
		row, err = menuChoose(ctx, t, list, lscr)
		if errors.Is(err, errMenuBack) {
			continue
		}
		if err != nil {
			return menuAction{}, nil, err
		}
		mem.target = row.value
		if act.pick == "vpn" && menuVpnUp(st, row.value) {
			return act, []string{"vpn", "down", row.value}, nil // up: choosing it disconnects
		}
		return act, append(slices.Clone(act.args), row.value), nil
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
			if done, err := handle(k, l.pageSize(h)); done || err != nil {
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

// menuAsk reads one line of text on the menu's screen: Enter gives it,
// Esc clears it and then goes back.
func menuAsk(ctx context.Context, t *menuTerm, l *menuList, s menuScreen) (string, error) {
	var text string
	err := menuShow(ctx, t, l, s, func(k menuKey, page int) (bool, error) {
		switch k.kind {
		case keyEnter:
			text = l.filter
			return true, nil
		case keyEsc:
			if l.filter == "" {
				return true, errMenuBack
			}
			l.setFilter("")
		case keyQuit:
			return true, errMenuQuit
		case keyRune, keyBackspace, keyClear:
			l.update(k, page)
		}
		return false, nil
	})
	return text, err
}

// menuAskServer is Add: one line, a name and user@address, checked here so
// a typo is fixed in place rather than after a failed command.
func menuAskServer(ctx context.Context, t *menuTerm, s menuScreen) ([]string, error) {
	l := &menuList{title: "Add a server or a conn", typing: true, prompt: "Name and user@address, or name and URL: ",
		empty: "for example: web1 deploy@10.0.0.5 · app-db postgres://app@10.0.0.5/app"}
	s.footer = "Enter add · Esc back"
	for {
		line, err := menuAsk(ctx, t, l, s)
		if err != nil {
			return nil, err
		}
		args, problem := menuAddArgs(line)
		if problem == "" {
			return args, nil
		}
		l.empty = problem
	}
}

// menuAddArgs turns "web1 deploy@10.0.0.5" into the host add command and
// "app-db postgres://app@10.0.0.5/app" into conn add, or says what is wrong
// with it.
func menuAddArgs(line string) ([]string, string) {
	f := strings.Fields(line)
	if len(f) != 2 {
		return nil, "type a name and user@address, or a name and a URL: web1 deploy@10.0.0.5"
	}
	kind, args := "host", slices.Clone(addAction.args)
	if strings.Contains(f[1], "://") {
		kind, args = "conn", []string{"conn", "add"}
	}
	if err := validName(kind, f[0]); err != nil {
		return nil, cleanText(toErr(err).Message)
	}
	if strings.HasPrefix(f[1], "-") {
		return nil, "an address cannot start with -"
	}
	return append(args, f[0], f[1]), ""
}

// menuRun runs one komando command in the normal screen, as if it was
// typed: the command line first, so the person learns it, then its output
// and exit code. Then it waits: Enter goes back to the menu, q quits. The
// key help is erased after that, so the scrollback keeps the command, its
// output and how it ended, not the keys of a menu that is gone.
func menuRun(ctx context.Context, t *menuTerm, self string, args []string, ownExit bool) (bool, error) {
	t.leave()
	fmt.Fprintf(os.Stderr, "$ komando %s\n", menuCommandLine(args))
	c := menuCommand(self, args)
	err := c.Run()
	// a command that died without undoing raw mode (killed, crashed) must
	// not leave its terminal modes to the menu or to the next command
	t.restoreOrig()
	result := "exit 0"
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return false, err
		}
		result = fmt.Sprintf("exit %d", ee.ExitCode())
		if ee.ExitCode() < 0 { // ended by a signal, most likely Ctrl-C
			result = "stopped"
		}
	}
	if ownExit && result == "exit 0" {
		result = "" // "komando: left web1 (exit 0, 12m)" said it already
	}
	keys := "Enter back to the menu · q quit "
	if result != "" {
		keys = result + " · " + keys
	}
	// one row at most: "\r\x1b[2K" below erases only the row it is on
	w, _ := t.size()
	fmt.Fprintf(os.Stderr, "\n%s", fit([]seg{{keys, ""}}, w-1, false))
	again, err := menuPause(ctx, t)
	fmt.Fprint(os.Stderr, "\r\x1b[2K")
	if result != "" {
		fmt.Fprintln(os.Stderr, menuPaint(result, "2"))
	}
	return again, err
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
	return s != nil && (s.Container != "" || netx.Alive(s.PID))
}

// menuHelpText is the ? screen: what komando does, by task, and the
// command for it. It fits 80 columns.
const menuHelpText = `What komando does, and the command for it:

  See everything, check it   komando list · komando test all · komando status
  Servers                    komando host add · komando shell · komando exec
  Health and facts           komando facts · komando recipe run health
  Files                      komando fs cat · komando upload · komando download
  Services, logs, packages   komando svc · komando logs · komando pkg
  Databases, caches, storage komando conn add · komando db · komando cache
  Clusters and registries    komando cluster status · komando registry ls
  VPNs                       komando vpn add · komando vpn up · komando vpn down
  Passwords                  komando secret set NAME
  History and safety         komando audit · komando doctor
  AI agents                  komando guide install

Every command: komando --help · one command: komando COMMAND --help
`

// menuHelp shows menuHelpText in the normal screen, then waits like a
// command's end: Enter back to the menu, q quits.
func menuHelp(ctx context.Context, t *menuTerm) (bool, error) {
	t.leave()
	fmt.Fprint(os.Stderr, menuHelpText)
	w, _ := t.size()
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
	last := []menuAction{listAction, auditAction, doctorAction}
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
		l.empty = "no database conn yet"
		l.rows = menuConnRows(st, "db")
	case "vpn":
		l.title = act.name + ": which one?"
		l.empty = "no VPN yet"
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

// menuPaint styles text for stderr when colour is on.
func menuPaint(s, style string) string { return fit([]seg{{s, style}}, displayWidth(s), colorOK()) }
