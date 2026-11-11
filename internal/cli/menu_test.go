package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

func TestDecodeKeys(t *testing.T) {
	r := func(c rune) menuKey { return menuKey{kind: keyRune, r: c} }
	k := func(kind keyKind) menuKey { return menuKey{kind: kind} }
	cases := map[string][]menuKey{
		"\x1b[A":              {k(keyUp)},
		"\x1b[B":              {k(keyDown)},
		"\x1bOA":              {k(keyUp)}, // application cursor mode
		"\x1b[1;5B":           {k(keyDown)},
		"\x1b[H\x1b[F":        {k(keyHome), k(keyEnd)},
		"\x1b[1~\x1b[4~":      {k(keyHome), k(keyEnd)},
		"\x1b[5~\x1b[6~":      {k(keyPageUp), k(keyPageDown)},
		"\x1b":                {k(keyEsc)},
		"\x1bq":               {k(keyEsc), r('q')}, // Alt+q: Esc, then q
		"\r":                  {k(keyEnter)},
		"\r\n":                {k(keyEnter)}, // a pasted line end is one Enter
		"\x7f\x08":            {k(keyBackspace), k(keyBackspace)},
		"\x03":                {k(keyQuit)},
		"\x04":                {k(keyQuit)},
		"\x15":                {k(keyClear)},
		"\x10\x0e":            {k(keyUp), k(keyDown)},
		"web":                 {r('w'), r('e'), r('b')},
		"é":                   {r('é')},
		"\x1b[200~a\x1b[201~": {r('a')}, // paste marks are dropped
		"\x1b[<0;3;4M":        nil,      // a mouse report is not a key
		"\x1b[12":             nil,      // cut short
		"\x1a\x00\xff":        nil,      // Ctrl-Z, NUL, a broken byte
		"\u009b\u202e":        nil,      // a C1 control and a bidi override
	}
	for in, want := range cases {
		if got, rest := decodeKeys([]byte(in), true); !slices.Equal(got, want) || rest != nil {
			t.Errorf("decodeKeys(%q) = %v %q, want %v", in, got, rest, want)
		}
	}
}

// A read can end inside a key: 86 held Down arrows do not fit in 256 bytes,
// and a slow link can cut a UTF-8 character. The unfinished end waits for
// the next read instead of turning into Esc (which quits) or stray letters.
func TestDecodeKeysAcrossReads(t *testing.T) {
	stream := []byte(strings.Repeat("\x1b[B", 86) + "é\x1bOA")
	for size := 1; size <= 16; size++ { // every way to cut it
		var keys []menuKey
		var pending []byte
		for b := stream; len(b) > 0; {
			n := min(size, len(b))
			k, rest := decodeKeys(append(pending, b[:n]...), false)
			keys, pending, b = append(keys, k...), slices.Clone(rest), b[n:]
		}
		k, _ := decodeKeys(pending, true)
		keys = append(keys, k...)
		down := slices.Repeat([]menuKey{{kind: keyDown}}, 86)
		want := append(down, menuKey{kind: keyRune, r: 'é'}, menuKey{kind: keyUp})
		if !slices.Equal(keys, want) {
			t.Fatalf("reads of %d bytes: %d keys, want %d (first difference matters: no Esc, no letters)", size, len(keys), len(want))
		}
	}
	if keys, rest := decodeKeys([]byte("\x1b"), false); keys != nil || string(rest) != "\x1b" {
		t.Errorf("a lone ESC at the end of a read waits: %v %q", keys, rest)
	}
	if keys, _ := decodeKeys([]byte("\x1b"), true); !slices.Equal(keys, []menuKey{{kind: keyEsc}}) {
		t.Errorf("a lone ESC with nothing after it is Esc: %v", keys)
	}
}

func testMenuList(n int, typing bool) *menuList {
	l := &menuList{typing: typing, empty: "none"}
	for i := range n {
		name := string(rune('a' + i))
		l.rows = append(l.rows, menuRow{label: name + "-row", detail: "detail " + name, value: name})
	}
	return l
}

// render without the caret, for tests that only read the lines
func renderText(l *menuList, s menuScreen, w, h int) []string {
	lines, _ := l.render(s, w, h)
	return lines
}

func TestMenuListMoves(t *testing.T) {
	l := testMenuList(5, false)
	press := func(k menuKey) menuOutcome { return l.update(k, 3) }
	press(menuKey{kind: keyUp}) // already at the top: stays
	if l.cursor != 0 {
		t.Fatalf("cursor %d after Up at the top", l.cursor)
	}
	for range 10 {
		press(menuKey{kind: keyDown})
	}
	if l.cursor != 4 || l.top != 2 {
		t.Fatalf("cursor %d top %d after Down x10, want 4 and 2 (page 3)", l.cursor, l.top)
	}
	press(menuKey{kind: keyRune, r: 'g'})
	if l.cursor != 0 || l.top != 0 {
		t.Fatalf("g: cursor %d top %d", l.cursor, l.top)
	}
	press(menuKey{kind: keyRune, r: 'j'})
	if row, _ := l.chosen(); row.value != "b" {
		t.Fatalf("j: chose %q", row.value)
	}
	if o := press(menuKey{kind: keyRune, r: '4'}); o != menuChosen {
		t.Fatalf("4: outcome %v", o)
	}
	if row, _ := l.chosen(); row.value != "d" {
		t.Fatalf("4: chose %q, want d", row.value)
	}
	if o := press(menuKey{kind: keyRune, r: '9'}); o != menuStay {
		t.Fatalf("9 on 5 rows: outcome %v, want stay", o)
	}
	if o := press(menuKey{kind: keyRune, r: 'q'}); o != menuQuit {
		t.Fatalf("q: outcome %v", o)
	}
	if o := press(menuKey{kind: keyEsc}); o != menuBack {
		t.Fatalf("Esc: outcome %v", o)
	}
	// Left goes back from a list with one before it, never off the main
	// menu: a person stepping back twice must not leave komando
	if o := press(menuKey{kind: keyLeft}); o != menuStay {
		t.Fatalf("Left on the main menu: outcome %v, want stay", o)
	}
	l.title = "Shell: which server?"
	if o := press(menuKey{kind: keyLeft}); o != menuBack {
		t.Fatalf("Left on a server list: outcome %v, want back", o)
	}
}

func TestMenuHotKey(t *testing.T) {
	l := menuMain([]menuAction{serversAction, settingsAction})
	if o := l.update(menuKey{kind: keyRune, r: '?'}, 10); o != menuChosen {
		t.Fatalf("?: outcome %v", o)
	}
	if row, _ := l.chosen(); row.value != menuHelpKey {
		t.Fatalf("? chose %q, want the help", row.value)
	}
	l.update(menuKey{kind: keyDown}, 10) // any other key forgets it
	if row, _ := l.chosen(); row.value != settingsAction.name {
		t.Fatalf("after Down: %q, want Settings and help", row.value)
	}
	f := testMenuList(3, true)
	f.hot = menuHot()
	if o := f.update(menuKey{kind: keyRune, r: '?'}, 10); o != menuStay || f.filter != "?" {
		t.Fatalf("? on a list with a filter is typed: %v %q", o, f.filter)
	}
}

func TestMenuListFilter(t *testing.T) {
	l := testMenuList(4, true)
	typeIn := func(s string) {
		keys, _ := decodeKeys([]byte(s), true)
		for _, k := range keys {
			l.update(k, 10)
		}
	}
	typeIn("q") // q filters on a list with a filter: it does not quit
	if l.filter != "q" || len(l.shown()) != 0 {
		t.Fatalf("filter %q shows %v", l.filter, l.shown())
	}
	if o := l.update(menuKey{kind: keyEnter}, 10); o != menuStay {
		t.Fatalf("Enter with nothing shown: %v", o)
	}
	typeIn("\x7fC-ROW") // matching ignores case
	if row, ok := l.chosen(); !ok || row.value != "c" {
		t.Fatalf("filter %q chose %v %v", l.filter, row, ok)
	}
	if o := l.update(menuKey{kind: keyEsc}, 10); o != menuStay || l.filter != "" {
		t.Fatalf("first Esc clears the filter: %v, filter %q", o, l.filter)
	}
	if o := l.update(menuKey{kind: keyEsc}, 10); o != menuBack {
		t.Fatalf("second Esc goes back: %v", o)
	}
	typeIn("detail b\x15")
	if l.filter != "" {
		t.Fatalf("Ctrl-U left %q", l.filter)
	}
	typeIn("zzz")
	if text := strings.Join(renderText(l, menuScreen{}, 80, 24), "\n"); !strings.Contains(text, "Esc clears the filter") {
		t.Errorf("an empty filtered list says how to clear it:\n%s", text)
	}
}

// The last choice is found by name, so the cursor is on it even when the
// list changed in between; a name that is gone leaves the cursor at the top.
func TestMenuPoint(t *testing.T) {
	l := testMenuList(30, true)
	l.point("t")
	lines, caret := l.render(menuScreen{footer: "keys"}, 40, 12)
	if row, _ := l.chosen(); row.value != "t" || !strings.HasPrefix(lines[caret.line], "> t-row") {
		t.Fatalf("point(t): chose %q, caret on %q", row.value, lines[caret.line])
	}
	l = testMenuList(3, true)
	l.point("gone")
	if l.cursor != 0 {
		t.Errorf("point to a missing name moved the cursor to %d", l.cursor)
	}
}

// A short screen (a small tmux pane) drops blank lines, the note, the
// header and the title first: the cursor row and the key help must stay,
// or Enter would act on a row nobody can see.
func TestMenuRenderShortScreen(t *testing.T) {
	l := testMenuList(17, true)
	l.title = "Test: which server?"
	l.note = "a note"
	s := menuScreen{header: []seg{{"komando", ""}}, footer: "keys"}
	for h := 3; h <= 14; h++ {
		lines, caret := l.render(s, 60, h)
		text := strings.Join(lines, "\n")
		if len(lines) > h || lines[len(lines)-1] != "keys" || !strings.Contains(text, "> a-row") || !strings.Contains(text, "Filter:") {
			t.Errorf("height %d:\n%s", h, text)
		}
		if caret.line < 0 || !strings.HasPrefix(lines[caret.line], "> a-row") {
			t.Errorf("height %d: the hidden cursor is not on the chosen row: %+v", h, caret)
		}
	}
	// every blank line goes before any line with words: at 4 lines the main
	// menu keeps header, note, the row and the key help
	m := testMenuList(3, false)
	m.note = "a note"
	if got := renderText(m, s, 60, 4); !slices.Equal(got, []string{"komando", "a note", "> 1. a-row  detail a", "keys"}) {
		t.Errorf("main menu at 4 lines: %q", got)
	}
}

func TestFitColumns(t *testing.T) {
	cases := []struct {
		in    string
		width int
		want  string
	}{
		{"東京サーバー", 5, "東京…"}, // two columns each, and … for the cut
		{"web-1  東京", 9, "web-1  …"},
		{"abc", 3, "abc"}, // fits: no …
		{"abcd", 3, "ab…"},
		{"abc", 0, ""},
	}
	for _, c := range cases {
		got := fit([]seg{{c.in, ""}}, c.width, false)
		if got != c.want {
			t.Errorf("fit(%q, %d) = %q, want %q", c.in, c.width, got, c.want)
		}
		if w := displayWidth(got); w > c.width {
			t.Errorf("fit(%q, %d) is %d columns wide", c.in, c.width, w)
		}
	}
	if got := fit([]seg{{"ab", "1"}, {"cd", "2"}}, 3, true); got != "\x1b[1mab\x1b[0m\x1b[2m…\x1b[0m" {
		t.Errorf("colour after the cut: %q", got)
	}
}

func TestMenuRender(t *testing.T) {
	l := testMenuList(30, true)
	l.title = "Shell: which server?"
	l.cursor = 20
	s := menuScreen{header: []seg{{"komando", "1"}, {" dev", "2"}}, footer: "keys"}
	lines, caret := l.render(s, 20, 12)
	if len(lines) != 12 || lines[11] != "keys" {
		t.Fatalf("%d lines on a 12-line screen, last %q; want 12 ending in the footer", len(lines), lines[len(lines)-1])
	}
	for _, ln := range lines {
		if n := utf8.RuneCountInString(ln); n >= 20 {
			t.Errorf("line %q is %d wide on a 20-column screen", ln, n)
		}
	}
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, "> u-row") || !strings.HasPrefix(lines[caret.line], "> u-row") || caret.col != 0 {
		t.Errorf("the cursor row is not on the screen, or the caret is not on it (%+v):\n%s", caret, text)
	}
	if strings.Contains(text, "\x1b") {
		t.Errorf("escape codes with colour off:\n%s", text)
	}
	s.color = true
	if text := strings.Join(renderText(l, s, 20, 12), "\n"); !strings.Contains(text, "\x1b[1;7m> u-row") {
		t.Errorf("no colour on the cursor row:\n%s", text)
	}
	// the main menu (no title, no filter): one blank line between the
	// header and the rows, and every line of the screen is used
	m := testMenuList(30, false)
	lines = renderText(m, menuScreen{header: []seg{{"komando", ""}}, footer: "keys"}, 40, 10)
	if len(lines) != 10 || lines[1] != "komando" || lines[2] != "" || !strings.HasPrefix(lines[3], "> 1. a-row") || lines[9] != "keys" {
		t.Errorf("main menu screen:\n%s", strings.Join(lines, "\n"))
	}
	// with a note (no server yet): the note, a blank line, then the rows
	m.note = menuWelcome
	lines = renderText(m, menuScreen{header: []seg{{"komando", ""}}, footer: "keys"}, 80, 10)
	if len(lines) != 10 || lines[3] != menuWelcome || lines[4] != "" || !strings.HasPrefix(lines[5], "> 1. a-row") {
		t.Errorf("main menu with a note:\n%s", strings.Join(lines, "\n"))
	}
}

// The detail column is placed by the widest name in the whole list, so it
// stays where it is while a person types and the rows change.
func TestMenuColumnsStayPut(t *testing.T) {
	l := &menuList{typing: true, rows: []menuRow{
		{label: "a-very-long-server-name", detail: "x.lan", value: "1"},
		{label: "db", detail: "db.lan", value: "2"},
	}}
	col := func() int {
		for _, ln := range renderText(l, menuScreen{}, 80, 20) {
			if i := strings.Index(ln, "db.lan"); i >= 0 {
				return i
			}
		}
		return -1
	}
	before := col()
	l.setFilter("db")
	if after := col(); after != before || before < 0 {
		t.Errorf("the detail column moved from %d to %d while filtering", before, after)
	}
}

func TestMenuAsk(t *testing.T) {
	l := &menuList{title: "Add a server", typing: true, prompt: "Name and user@address: ", empty: "for example: web1 deploy@10.0.0.5"}
	l.setFilter("web1 dep")
	lines, caret := l.render(menuScreen{footer: "Enter add · Esc back"}, 80, 12)
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, "Name and user@address: web1 dep_") || strings.Contains(text, " of ") ||
		!strings.Contains(text, "for example: web1 deploy@10.0.0.5") || strings.Contains(text, "nothing matches") {
		t.Errorf("Add screen:\n%s", text)
	}
	if !strings.HasPrefix(lines[caret.line], "Name and") || caret.col != len("Name and user@address: web1 dep") {
		t.Errorf("caret %+v is not after the typed text", caret)
	}
	// a line longer than the screen shows its end: the last key typed, a
	// typo in it, and the _ after it stay in sight
	for _, w := range []int{80, 40, 20} {
		typed := func(s string) (string, menuCaret) {
			l.setFilter(s)
			lines, caret := l.render(menuScreen{footer: "keys"}, w, 12)
			return lines[caret.line], caret
		}
		com, caret := typed("web1 deploy@ec2-54-123-45-67.eu-west-1.compute.amazonaws.com")
		cm, _ := typed("web1 deploy@ec2-54-123-45-67.eu-west-1.compute.amazonaws.cm")
		if com == cm || !strings.HasSuffix(com, "amazonaws.com_") || !strings.Contains(com, "…") || displayWidth(com) > w-1 {
			t.Errorf("width %d: %q / %q", w, com, cm)
		}
		if caret.col != displayWidth(com)-1 {
			t.Errorf("width %d: caret %+v is not on the _ of %q", w, caret, com)
		}
	}
	f := testMenuList(3, true)
	f.setFilter(strings.Repeat("x", 50))
	if line := renderText(f, menuScreen{}, 40, 12)[3]; !strings.HasPrefix(line, "Filter: …") || strings.Contains(line, " of ") || !strings.HasSuffix(line, "x_") {
		t.Errorf("a long filter at 40 columns: %q", line)
	}
}

func TestMenuCommandLine(t *testing.T) {
	cases := map[string][]string{
		"shell web1":                    {"shell", "web1"},
		"audit --limit 20":              {"audit", "--limit", "20"},
		"host add web1 deploy@10.0.0.5": {"host", "add", "web1", "deploy@10.0.0.5"},
		"host add web1 'a;b'":           {"host", "add", "web1", "a;b"},
		`host add web1 'it'\''s'`:       {"host", "add", "web1", "it's"},
	}
	for want, args := range cases {
		if got := menuCommandLine(args); got != want {
			t.Errorf("menuCommandLine(%q) = %q, want %q", args, got, want)
		}
	}
}

func menuTestState() *store.State {
	st := testState()
	st.Conns = map[string]*store.Conn{
		"app-db": {Name: "app-db", Kind: "postgres", URL: "postgres://app@10.0.0.9:5432/app", Groups: []string{"prod"}},
		"cache":  {Name: "cache", Kind: "redis", URL: "redis://10.0.0.9:6379"},
	}
	st.Vpns = map[string]*store.Vpn{"office": {Name: "office", Kind: "socks", Address: "127.0.0.1:1080"}}
	return st
}

func actionNames(acts []menuAction) []string {
	var names []string
	for _, a := range acts {
		names = append(names, a.name)
	}
	return names
}

func TestMenuMain(t *testing.T) {
	empty := &store.State{Hosts: map[string]*store.Host{}}
	onlyConns := menuTestState()
	onlyConns.Hosts = map[string]*store.Host{}
	fixed := []string{"Servers", "Databases and services", "VPNs", "Add something", "Check everything", "History and undo", "Settings and help"}
	cases := []struct {
		name  string
		st    *store.State
		newIn int // servers in ~/.ssh/config komando does not know
		want  []string
	}{
		{"new, with servers in ~/.ssh/config", empty, 12, []string{"Add a server", "Bring in my SSH servers", "Set up my AI agent", "Settings and help"}},
		{"new, nothing to import", empty, 0, []string{"Add a server", "Set up my AI agent", "Settings and help"}},
		{"conns and a VPN, no server", onlyConns, 3, fixed},
		{"servers", testState(), 0, fixed},
		{"everything", menuTestState(), 0, fixed},
	}
	for _, c := range cases {
		acts := menuMainActions(c.st, c.newIn)
		got := actionNames(acts)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if len(got) > 9 {
			t.Errorf("%s: %d rows; the number keys reach 9", c.name, len(got))
		}
		for _, a := range acts {
			if slices.Contains(strings.Fields(a.name+" "+a.detail), "conn") || strings.Contains(a.name, "All features") {
				t.Errorf("%s: row %q %q says conn or All features", c.name, a.name, a.detail)
			}
		}
	}
	if acts := menuMainActions(empty, 12); acts[1].detail != "12 servers found in ~/.ssh/config" {
		t.Errorf("import detail %q", acts[1].detail)
	}
	if acts := menuMainActions(menuTestState(), 0); acts[2].detail != "office not connected" {
		t.Errorf("VPNs detail %q", acts[2].detail)
	}
	// Running now shows above Add something while something runs
	run := menuTestState()
	run.Tunnels = map[string]*store.Tunnel{"t1": {ID: "t1", Host: "web-1", Kind: "local", Spec: "8080:localhost:80"}}
	got := actionNames(menuMainActions(run, 0))
	if want := []string{"Servers", "Databases and services", "VPNs", "Running now (1)", "Add something", "Check everything", "History and undo", "Settings and help"}; !slices.Equal(got, want) {
		t.Errorf("running: %v", got)
	}
	// names the lists leave out (a host "all" from before it was refused,
	// a hand-edited "-x") do not count: still the first-run screen
	oldNames := &store.State{
		Hosts: map[string]*store.Host{"all": {Name: "all", Address: "old.lan"}},
		Conns: map[string]*store.Conn{"-x": {Name: "-x", Kind: "postgres", URL: "postgres://u@db.lan/x"}},
	}
	if got := actionNames(menuMainActions(oldNames, 0)); got[0] != "Add a server" {
		t.Errorf("only names the lists leave out: %v", got)
	}
	// every command line the main menu runs at once is one komando takes
	root := newRoot()
	for _, a := range []menuAction{importAction, agentAction} {
		if checkExampleLines(t, root, "menu action "+a.name, "komando "+menuCommandLine(a.args)) != 1 {
			t.Errorf("%s: `%v` was not checked", a.name, a.args)
		}
	}
	for _, l := range checkLines {
		if checkExampleLines(t, root, "Check everything", "komando "+menuCommandLine(l)) != 1 {
			t.Errorf("Check everything: `%v` was not checked", l)
		}
	}
	if !slices.ContainsFunc(importSources, func(s importSource) bool { return s.Name == importAction.args[1] }) {
		t.Errorf("Import runs an unknown source %q", importAction.args[1])
	}
}

// The header counts in plain words, never "conn", and names a connected VPN.
func TestMenuHeader(t *testing.T) {
	st := menuTestState()
	h := menuHeader(st)
	text := h[0].text + h[1].text
	if text != "komando  4 servers · 1 database · 1 service · 1 VPN" {
		t.Errorf("header %q", text)
	}
	if h := menuHeader(&store.State{}); len(h) != 1 || h[0].text != "komando" {
		t.Errorf("empty header %v", h)
	}
}

// Every task of every item, settings, history, add and running screen is a
// command komando has, and every command line it runs at once is one
// komando takes, with the item filled in.
func TestMenuTasksAreCommands(t *testing.T) {
	root := newRoot()
	for _, tk := range menuEveryTask(t) {
		if tk.cmd != "" {
			c, _, err := root.Find(strings.Fields(tk.cmd))
			if err != nil || commandKey(c) != tk.cmd {
				t.Errorf("task %q: no command %q", tk.label, tk.cmd)
				continue
			}
			if tk.fill != nil && len(tk.fill) > len(formUseArgs(c.Use, c.Flags())) {
				t.Errorf("task %q fills more arguments than %q takes", tk.label, tk.cmd)
			}
		}
		for _, l := range tk.line {
			line := "komando " + menuCommandLine(menuFillLine(l, "web-1"))
			if checkExampleLines(t, root, "task "+tk.label, line) != 1 {
				t.Errorf("task %q: `%s` was not checked", tk.label, line)
			}
		}
		if tk.confirm != "" && tk.yes == "" {
			t.Errorf("task %q asks %q with no yes row", tk.label, tk.confirm)
		}
	}
}

// menuEveryTask is every task the menu has, sub lists included, for a
// state with something running and a connected VPN.
func menuEveryTask(t *testing.T) []menuTask {
	t.Helper()
	st := menuTestState()
	st.Tunnels = map[string]*store.Tunnel{"t1": {ID: "t1", Host: "web-1", Spec: "8080:localhost:80"}}
	st.Jobs = map[string]*store.Job{"j1": {ID: "j1", Host: "web-1", Command: "make"}}
	st.Logins = map[string]*store.SSHLogin{"web-1": {Host: "web-1"}}
	all := slices.Concat(serverTasks, groupTasks(), vpnTasks(st, "office"), dbTasks, cacheTasks, queueTasks,
		storageTasks, clusterTasks, registryTasks, importTasks, historyTasks, settingsTasks(), runningTasks, menuRunningRows(st))
	// a connected VPN offers Disconnect
	st.Sessions = map[string]*store.VpnSession{"office": {Vpn: "office", PID: os.Getpid()}}
	all = append(all, vpnTasks(st, "office")...)
	all = append(all, menuRunningRows(st)...)
	var flat []menuTask
	var walk func(ts []menuTask)
	walk = func(ts []menuTask) {
		for _, tk := range ts {
			flat = append(flat, tk)
			walk(tk.sub)
		}
	}
	walk(all)
	return flat
}

// Every command a person can use has a home in the menu: a task of some
// item or screen, an Add form, or a reason it is for scripts only.
func TestMenuEveryCommandHasAHome(t *testing.T) {
	root := newRoot()
	home := map[string]bool{}
	for _, tk := range menuEveryTask(t) {
		if tk.cmd != "" {
			home[tk.cmd] = true
		}
		for _, l := range tk.line {
			if c, _, err := root.Find(l); err == nil {
				home[commandKey(c)] = true
			}
		}
	}
	for _, l := range checkLines {
		c, _, _ := root.Find(l)
		home[commandKey(c)] = true
	}
	for _, g := range formGroups() { // Add something: host add, conn add, vpn add
		for _, k := range g.kinds {
			for _, line := range k.spec().build(menuTestState(), formAnswers{"name": "x"}) {
				if c, _, err := root.Find(line); err == nil {
					home[commandKey(c)] = true
				}
			}
		}
	}
	for _, f := range menuFamilies { // db add, cache add ...: the Add forms
		home[f.family+" add"] = true
	}
	for k := range menuCLIOnly {
		if home[k] {
			t.Errorf("%s is in the menu and also marked for scripts only", k)
		}
		home[k] = true
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			// a group command (host, config) shows its list or help; its
			// subcommands are what the menu offers
			if s.Hidden || s.Deprecated != "" || s.Name() == "help" || !formListed(s) || s.HasSubCommands() {
				continue
			}
			if !home[commandKey(s)] {
				t.Errorf("%s has no home in the menu: give it a task, or a reason in menuCLIOnly", commandKey(s))
			}
		}
	}
	walk(root)
}

// A task opens its command's form with the item answered: that question
// is not asked, the command line has it, and a read with nothing left to
// ask runs at once.
func TestMenuTaskSpec(t *testing.T) {
	root := newRoot()
	st := menuTestState()
	spec := func(key string, tk menuTask, item string) (formSpec, bool) {
		c, _, _ := root.Find(strings.Fields(key))
		tk.cmd = key
		return menuTaskSpec(st, c, tk, item)
	}
	sp, ready := spec("facts", menuTask{label: "Facts"}, "web-1")
	if !ready || !slices.Equal(sp.build(st, formAnswers{})[0], []string{"facts", "web-1"}) {
		t.Errorf("facts web-1: ready %v, %v", ready, sp.build(st, formAnswers{}))
	}
	for _, q := range sp.qs {
		if q.key == "arg0" {
			t.Error("the server is asked again")
		}
	}
	if _, ready := spec("host rm", menuTask{label: "Remove"}, "web-1"); ready {
		t.Error("a change runs without its review")
	}
	sp, _ = spec("group add", menuTask{label: "Add", fill: []string{"{name}"}}, "@web")
	if got := sp.build(st, formAnswers{"arg1": "db-1"})[0]; !slices.Equal(got, []string{"group", "add", "web", "db-1"}) {
		t.Errorf("group add: %v", got)
	}
	sp, _ = spec("recipe run", menuTask{label: "Run", fill: []string{"", "{}"}}, "web-1")
	if got := sp.build(st, formAnswers{"arg0": "disk"})[0]; !slices.Equal(got, []string{"recipe", "run", "disk", "web-1"}) {
		t.Errorf("recipe run: %v", got)
	}
}

// Protect or unprotect asks only the production question, and each answer
// builds a command that does it: No takes protection away.
func TestMenuProtectTask(t *testing.T) {
	root := newRoot()
	st := menuTestState()
	for _, key := range []string{"host edit", "conn edit"} {
		i := slices.IndexFunc(menuEveryTask(t), func(tk menuTask) bool { return tk.cmd == key && tk.only != nil })
		if i < 0 {
			t.Fatalf("no Protect or unprotect task for %s", key)
		}
		tk := menuEveryTask(t)[i]
		c, _, _ := root.Find(strings.Fields(key))
		sp, _ := menuTaskSpec(st, c, tk, "")
		for _, q := range sp.qs {
			if strings.HasPrefix(q.key, "flag:") && !q.advanced != (q.key == "flag:protected") {
				t.Errorf("%s: %s advanced %v", key, q.key, q.advanced)
			}
		}
		for v, want := range map[string]string{"true": "--protected", "false": "--protected=false", "": ""} {
			got := formBuild(st, sp, formAnswers{"arg0": "web-1", "flag:protected": v})[0]
			if want == "" && len(got) != 3 || want != "" && !slices.Contains(got, want) {
				t.Errorf("%s, production %q: %v, want %q", key, v, got, want)
			}
		}
	}
}

// A group offers only what runs on several servers: no shell, tunnel,
// login or one-file edit, which would stop at "needs exactly one".
func TestMenuGroupTasks(t *testing.T) {
	var walk func(ts []menuTask)
	seen := map[string]bool{}
	walk = func(ts []menuTask) {
		for _, tk := range ts {
			seen[tk.cmd] = true
			for _, l := range tk.line {
				seen[l[0]] = true
			}
			walk(tk.sub)
		}
	}
	walk(groupTasks())
	for _, cmd := range []string{"shell", "tunnel start", "login", "fs replace", "fs cat"} {
		if seen[cmd] {
			t.Errorf("a group offers %s, which works on one server", cmd)
		}
	}
	for _, cmd := range []string{"logs", "exec", "upload", "recipe run", "group add"} {
		if !seen[cmd] {
			t.Errorf("a group lost %s", cmd)
		}
	}
}

// Log in with a code under a server logs in to that server, not asking
// which one again.
func TestMenuLoginUsesItem(t *testing.T) {
	i := slices.IndexFunc(serverMoreTasks, func(tk menuTask) bool { return tk.cmd == "login" })
	sp, given, ok := menuHandForm(formHints["login"], serverMoreTasks[i], "web-1")
	if !ok || given["arg0"] != "web-1" {
		t.Fatalf("login: ok %v, given %v", ok, given)
	}
	if got := formBuild(menuTestState(), sp, given)[0]; !slices.Equal(got, []string{"login", "web-1"}) {
		t.Errorf("login: %v", got)
	}
	if _, _, ok := menuHandForm(formHints["login"], menuTask{cmd: "login", noItem: true}, ""); ok {
		t.Error("with no item the server is not asked")
	}
}

// A list from komando export comes back with import komando, which takes
// its databases, VPNs and settings too, not only its servers.
func TestMenuImportExported(t *testing.T) {
	i := slices.IndexFunc(importTasks, func(tk menuTask) bool { return tk.label == "A list exported from komando" })
	if tk := importTasks[i]; tk.cmd != "import" || !slices.Equal(tk.fill, []string{"komando"}) {
		t.Errorf("exported list: %s %v", tk.cmd, tk.fill)
	}
}

// Disconnecting a VPN asks first and says what stops answering; Reboot
// asks first. No is the first row, so Enter alone does nothing.
func TestMenuConfirms(t *testing.T) {
	st := menuTestState()
	st.Hosts["web-1"].Via = "office"
	if tk := vpnTasks(st, "office")[0]; tk.label != "Connect" || tk.confirm != "" {
		t.Errorf("not connected: %+v", tk)
	}
	st.Sessions = map[string]*store.VpnSession{"office": {Vpn: "office", PID: os.Getpid()}}
	tk := vpnTasks(st, "office")[0]
	if tk.label != "Disconnect" || menuFill(tk.confirm, "office") != "Disconnect office? 1 server or service behind it stops answering." {
		t.Errorf("connected: %q %q", tk.label, tk.confirm)
	}
	reboot := serverTasks[slices.IndexFunc(serverTasks, func(t menuTask) bool { return t.label == "Reboot" })]
	if reboot.confirm == "" {
		t.Error("Reboot runs without asking")
	}
}

// Every screen's ? text fits the screen and ends with where the commands
// for scripts are.
func TestMenuHelpWidths(t *testing.T) {
	for _, text := range []string{menuHelpMain, menuHelpItems, menuHelpTasks, menuHelpAdd, menuHelpHistory, menuHelpSettings, menuHelpRunning, menuHelpConfirm} {
		for _, w := range []int{40, 80} {
			out := menuHelpFor(text, w)
			for _, ln := range strings.Split(out, "\n") {
				if displayWidth(ln) > w {
					t.Errorf("? at %d columns: %q is wider", w, ln)
				}
			}
			if !strings.Contains(out, "--help") || slices.Contains(strings.Fields(out), "conn") {
				t.Errorf("? text:\n%s", out)
			}
		}
	}
}

// README's menu block is what a new computer shows.
func TestMenuREADMEBlock(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	acts := menuMainActions(&store.State{}, 0)
	l := menuMain(acts)
	l.note = menuWelcome
	scr := menuScreen{header: menuHeader(&store.State{}), footer: menuKeysFor(l)}
	lines := renderText(l, scr, 80, 4+len(acts)+3)
	var b2 strings.Builder
	for _, ln := range lines {
		b2.WriteString(strings.TrimRight(ln, " ") + "\n")
	}
	want := "```text\n" + strings.TrimLeft(strings.TrimRight(b2.String(), "\n"), "\n") + "\n```"
	if !strings.Contains(string(b), want) {
		t.Errorf("README.md menu block is out of date; it should be:\n%s", want)
	}
}

// First run: Import with no ~/.ssh/config says so and how to add a server,
// and an import that adds nothing says that first.
func TestMenuFirstRunImport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg := filepath.Join(home, ".ssh", "config")
	_, err := os.Open(cfg)
	e := toErr(sshConfigErr(cfg, err))
	if e.Code != "FILE_NOT_FOUND" || e.Message != "there is no ~/.ssh/config on this computer" || !strings.Contains(e.Hint, "komando host add web1") {
		t.Errorf("no ~/.ssh/config: %+v", e)
	}
	other := filepath.Join(home, "other")
	_, err = os.Open(other)
	if e := toErr(sshConfigErr(other, err)); !strings.Contains(e.Message, other+" does not exist") || strings.Contains(e.Hint, "host add") {
		t.Errorf("a path someone typed: %+v", e)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}

	r := importResult{File: "~/.ssh/config", Hosts: []string{}, NotFound: []string{"Host *: used as defaults, not a server"}}
	if got := r.Text(); got != "nothing to import from ~/.ssh/config\nnot imported: Host *: used as defaults, not a server\n" {
		t.Errorf("nothing added:\n%s", got)
	}
	// a note about a server that was added is not "not imported"; which
	// notes those are is known, not guessed from the text
	about := "bastion: its identity file ~/.ssh/id_x was not found; left out"
	r.Hosts = []string{"web1", "bastion"}
	r.NotFound = []string{"Host *: used as defaults, not a server", about, "web1: a note from the source file"}
	r.aboutAdded = []string{about}
	want := "servers added: web1, bastion\n" +
		"not imported: Host *: used as defaults, not a server\n" +
		about + "\n" +
		"not imported: web1: a note from the source file\n"
	if got := r.Text(); got != want {
		t.Errorf("notes about added servers carry no 'not imported':\n%s\nwant\n%s", got, want)
	}
}

func TestImportVetHosts(t *testing.T) {
	// --overwrite with a copy that is refused (its --via does not exist)
	// keeps the server it would have replaced
	s := &store.State{Hosts: map[string]*store.Host{"web1": {Name: "web1", Address: "10.0.0.1", User: "u"}}}
	v, err := vetImportHosts(s, []*store.Host{{Name: "web1", Address: "10.0.0.9", Via: "nosuch"}}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Invalid) != 1 || len(v.Add) != 0 || s.Hosts["web1"] == nil || s.Hosts["web1"].Address != "10.0.0.1" {
		t.Errorf("a refused --overwrite must keep the old server: invalid %v, web1 %+v", v.Invalid, s.Hosts["web1"])
	}
	// what was left out of a server is said only for one that is added,
	// in words that are true for --dry-run too
	v, err = vetImportHosts(s, []*store.Host{
		{Name: "web2", Address: "10.0.0.2", Identity: "/no/such/key"},
		{Name: "web3", Address: "10.0.0.3", Identity: "/no/such/key", Via: "nosuch"},
	}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"web2: its identity file /no/such/key was not found; left out"}; !slices.Equal(v.Notes, want) {
		t.Errorf("notes %q, want %q", v.Notes, want)
	}
}

func TestMenuGate(t *testing.T) {
	// TestMain makes interactive() false, as for an agent or a script
	if menuWanted(newRoot(), nil) {
		t.Error("menu opens without a person at a terminal")
	}
	cases := []struct {
		flags  []string
		args   []string
		person bool
		want   bool
	}{
		{nil, nil, true, true},
		{nil, nil, false, false},
		{[]string{"--dry-run"}, nil, true, false},
		{[]string{"-o", "text"}, nil, true, false},
		{[]string{"-P", "5"}, nil, true, false},
		{nil, []string{"web1"}, true, false},
	}
	for _, c := range cases {
		root := newRoot()
		if err := root.ParseFlags(c.flags); err != nil {
			t.Fatal(err)
		}
		if got := menuGate(root, c.args, c.person); got != c.want {
			t.Errorf("flags %v args %v person %v: menu %v, want %v", c.flags, c.args, c.person, got, c.want)
		}
	}
}

// komando takes KOMANDO_VAULT_PASS out of its environment when it starts;
// the command the menu runs must still get it, or a passphrase vault does
// not open (and its values are not hidden) as it would when typed.
func TestMenuCommandKeepsVaultPass(t *testing.T) {
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	vault.Passphrase() // what every command does first (root.go)
	if _, ok := os.LookupEnv("KOMANDO_VAULT_PASS"); ok {
		t.Fatal("Passphrase left the variable in the environment")
	}
	c := menuCommand("/bin/true", []string{"list"})
	if !slices.Contains(c.Env, "KOMANDO_VAULT_PASS=test") {
		t.Error("the menu's command does not get the vault passphrase")
	}
	if c.Stdin != os.Stdin || c.Stdout != os.Stdout || c.Stderr != os.Stderr {
		t.Error("the menu's command must have the terminal")
	}
}

// A problem with an answer is marked "! " and drawn bold, not yellow:
// the mark works without colour, and bold reads on a light terminal too.
func TestMenuWarnNotColourOnly(t *testing.T) {
	l := &menuList{title: "Add a server", typing: true, prompt: "Port: ", note: "a port is a number", warn: true}
	s := menuScreen{footer: "keys", color: true}
	text := strings.Join(renderText(l, s, 80, 12), "\n")
	if !strings.Contains(text, "\x1b[1m! a port is a number\x1b[0m") || strings.Contains(text, "\x1b[33m") {
		t.Errorf("a problem is not bold with its mark, or still yellow:\n%q", text)
	}
	s.color = false
	if text := strings.Join(renderText(l, s, 80, 12), "\n"); !strings.Contains(text, "! a port is a number") {
		t.Errorf("without colour the problem has no mark:\n%s", text)
	}
}

// The key help names only keys the list takes: numbers up to its rows on a
// list without a filter, none on a list that filters.
func TestListKeys(t *testing.T) {
	cases := []struct {
		l    *menuList
		want string
	}{
		{testMenuList(3, false), "↑↓ move · Enter or 1-3 choose · Esc back"},
		{testMenuList(12, false), "↑↓ move · Enter or 1-9 choose · Esc back"},
		{testMenuList(1, false), "↑↓ move · Enter choose · Esc back"},
		{testMenuList(12, true), "↑↓ move · Enter choose · type to filter · Esc back"},
	}
	for _, c := range cases {
		if got := listKeys(c.l, "Esc back"); got != c.want {
			t.Errorf("%d rows, typing %v: %q, want %q", len(c.l.rows), c.l.typing, got, c.want)
		}
	}
}

// On a narrow terminal the key help goes on two lines, cut between keys,
// so "q quit" is not cut off; at 80 columns it is one line. The rows give
// way for the extra line, and on a very short screen the second line goes.
func TestMenuKeyHelpNarrow(t *testing.T) {
	m := testMenuList(9, false)
	s := menuScreen{header: []seg{{"komando", ""}}, footer: listKeys(m, "? help", "q quit")}
	lines := renderText(m, s, 40, 24)
	if len(lines) > 24 || lines[len(lines)-2] != "↑↓ move · Enter or 1-9 choose · ? help" || lines[len(lines)-1] != "q quit" {
		t.Errorf("key help at 40 columns:\n%s", strings.Join(lines, "\n"))
	}
	for _, ln := range lines {
		if displayWidth(ln) > 39 {
			t.Errorf("line %q is wider than a 40-column screen", ln)
		}
	}
	if lines := renderText(m, s, 80, 24); lines[len(lines)-1] != s.footer {
		t.Errorf("key help at 80 columns: %q", lines[len(lines)-1])
	}
	l := testMenuList(30, true)
	l.title = "Shell: which server?"
	l.cursor = 20
	s.footer = listKeys(l, "Esc back", "Ctrl-C quit")
	for h := 3; h <= 14; h++ {
		lines, caret := l.render(s, 40, h)
		last := lines[len(lines)-1]
		if len(lines) > h || !strings.HasPrefix(last, "↑↓ move") && last != "Esc back · Ctrl-C quit" ||
			caret.line < 0 || !strings.HasPrefix(lines[caret.line], "> u-row") {
			t.Errorf("height %d at 40 columns:\n%s", h, strings.Join(lines, "\n"))
		}
	}
	if lines := renderText(l, s, 40, 3); len(lines) != 3 || !strings.HasPrefix(lines[2], "↑↓ move") {
		t.Errorf("a 3-line screen keeps the first line of the key help: %q", lines)
	}
}

// The lists behind Servers, Databases and services, and VPNs: groups
// first, services by kind, bad names left out, protected first in the
// detail, never a URL that may hold a password, no control characters.
func TestMenuItems(t *testing.T) {
	st := menuTestState()
	st.Hosts["web-1"].User, st.Hosts["web-1"].Port, st.Hosts["web-1"].Protected = "deploy", 2222, true
	st.Hosts["web-alias"] = &store.Host{Name: "web-alias", Address: "WEB-1.lan", Port: 2222} // the same server
	st.Hosts["bad\x1b[2Jname"] = &store.Host{Name: "bad\x1b[2Jname", Address: "bad.lan"}
	st.Hosts["-rf"] = &store.Host{Name: "-rf", Address: "flag.lan"}
	st.Hosts["all"] = &store.Host{Name: "all", Address: "old.lan"}
	st.Conns["app-db"].Protected = true
	st.Conns["leaky"] = &store.Conn{Name: "leaky", Kind: "mysql", URL: "mysql://app:hunter2@10.0.0.7/app"}
	labels := func(l *menuList) []string {
		var s []string
		for _, r := range l.rows {
			s = append(s, r.label)
		}
		return s
	}
	detail := func(l *menuList, name string) string {
		i := slices.IndexFunc(l.rows, func(r menuRow) bool { return r.label == name })
		if i < 0 {
			t.Fatalf("no row %s in %v", name, labels(l))
		}
		return l.rows[i].detail
	}
	servers := menuItems(st, "servers")
	if got := labels(servers); !slices.Equal(got, []string{"@db", "@web", "db-1", "dev-1", "web-1", "web-2", "web-alias"}) {
		t.Errorf("Servers rows %v", got)
	}
	if d := detail(servers, "web-1"); d != "protected  deploy@web-1.lan:2222  @web  prod" {
		t.Errorf("web-1 detail %q", d)
	}
	if d := detail(servers, "web-alias"); !strings.HasPrefix(d, "protected  ") {
		t.Errorf("the same server as protected web-1 must say so: %q", d)
	}
	services := menuItems(st, "services")
	if got := labels(services); !slices.Equal(got, []string{"app-db", "leaky", "cache"}) {
		t.Errorf("services rows %v (databases first)", got)
	}
	if d := detail(services, "app-db"); d != "database  protected  postgres  10.0.0.9:5432  @prod" {
		t.Errorf("app-db detail %q", d)
	}
	if d := detail(services, "leaky"); d != "database  mysql" {
		t.Errorf("a URL komando cannot read is never shown: %q", d)
	}
	if got := labels(menuItems(st, "vpns")); !slices.Equal(got, []string{"office"}) {
		t.Errorf("VPNs %v", got)
	}
	for _, l := range []*menuList{servers, services} {
		for _, r := range l.rows {
			if strings.ContainsAny(r.label+r.detail, "\x1b\x07") {
				t.Errorf("control characters reach the screen: %q %q", r.label, r.detail)
			}
		}
	}
	// each kind gets its own tasks, and the title says what the item is
	if kind, tasks := menuItemTasks(st, "app-db"); kind != "db" || tasks[1].label != "Run a query" {
		t.Errorf("app-db: %s %v", kind, tasks[1].label)
	}
	if kind, _ := menuItemTasks(st, "@web"); kind != "group" {
		t.Errorf("@web: %s", kind)
	}
	if got := menuItemTitle(st, "server", "web-1"); got != "web-1 (deploy@web-1.lan): what do you want to do?" {
		t.Errorf("title %q", got)
	}
}

func TestMenuNoteWraps(t *testing.T) {
	long := strings.Repeat("word ", 30)
	for _, warn := range []bool{false, true} {
		l := testMenuList(5, false)
		l.title, l.note, l.warn = "Question", long, warn
		lines, caret := l.render(menuScreen{footer: "keys"}, 40, 20)
		if len(lines) > 20 {
			t.Errorf("warn=%v: %d lines on a 20-line screen", warn, len(lines))
		}
		n := 0
		for _, ln := range lines {
			if displayWidth(ln) > 39 {
				t.Errorf("warn=%v: line wider than 39: %q", warn, ln)
			}
			if strings.HasPrefix(ln, "word") || strings.HasPrefix(ln, "! word") || strings.HasPrefix(ln, "  word") {
				n++
			}
		}
		if n < 2 || n > 3 {
			t.Errorf("warn=%v: the note takes %d lines, want 2 or 3:\n%s", warn, n, strings.Join(lines, "\n"))
		}
		if caret.line < 0 || !strings.HasPrefix(lines[caret.line], "> ") {
			t.Errorf("warn=%v: no cursor row:\n%s", warn, strings.Join(lines, "\n"))
		}
	}
}

func TestMenuRowsPastNineLineUp(t *testing.T) {
	l := testMenuList(12, false)
	lines := renderText(l, menuScreen{footer: "keys"}, 80, 24)
	var nine, ten string
	for _, ln := range lines {
		if strings.Contains(ln, "i-row") {
			nine = ln
		}
		if strings.Contains(ln, "j-row") {
			ten = ln
		}
	}
	if strings.Index(nine, "i-row") != strings.Index(ten, "j-row") || strings.Index(nine, "detail") != strings.Index(ten, "detail") {
		t.Errorf("row 10 is not in line with row 9:\n%q\n%q", nine, ten)
	}
}

// TestRenderRunsWrap: the review's command lines wrap on a narrow screen,
// so every flag a person must check is on it.
func TestRenderRunsWrap(t *testing.T) {
	for _, w := range []int{40, 60} {
		l := &menuList{title: "Add a server: check and run", runs: []string{
			"$ komando host add web1 10.0.0.5 --user deploy --ask-password --protected"}}
		l.rows = []menuRow{{label: "Run it", value: "run"}}
		lines := renderText(l, menuScreen{footer: "keys"}, w, 24)
		text := strings.Join(lines, "\n")
		for _, f := range []string{"web1", "10.0.0.5", "--user", "deploy", "--ask-password", "--protected"} {
			if !strings.Contains(text, f) {
				t.Errorf("width %d: %q missing:\n%s", w, f, text)
			}
		}
		for _, ln := range lines {
			if displayWidth(ln) > w-1 {
				t.Errorf("width %d: line too wide: %q", w, ln)
			}
		}
		if got, want := l.chrome(menuScreen{footer: "keys"}, w), 7+len(l.runLines(w)); got != want {
			t.Errorf("width %d: chrome %d, want %d", w, got, want)
		}
	}
}

// TestFormCancelKey: q cancels a form list without a filter, so its key
// help says so; a list with one shows Ctrl-C.
func TestFormCancelKey(t *testing.T) {
	if got := formCancelKey(&menuList{}); got != "q cancel" {
		t.Errorf("no filter: %q", got)
	}
	if got := formCancelKey(&menuList{typing: true}); got != "Ctrl-C cancel" {
		t.Errorf("filter: %q", got)
	}
}

// Running now lists only jobs that may still run: not one seen ending,
// not one whose server left the list.
func TestMenuRunningLeavesOutEndedJobs(t *testing.T) {
	st := menuTestState()
	st.Jobs = map[string]*store.Job{
		"live": {ID: "live", Host: "web-1", Command: "make"},
		"done": {ID: "done", Host: "web-1", Command: "make", Ended: "exited"},
		"gone": {ID: "gone", Host: "deleted-vm", Command: "make"},
		"lost": {ID: "lost", Host: "web-1", Command: "make", Ended: "lost"},
	}
	var jobs []string
	for _, r := range menuRunningRows(st) {
		if strings.HasPrefix(r.label, "Job ") {
			jobs = append(jobs, r.label)
		}
	}
	if !slices.Equal(jobs, []string{"Job live"}) {
		t.Fatalf("Running now jobs = %v, want only Job live", jobs)
	}
}

// Check everything runs doctor even when a server fails test all, and says
// the worst exit; other lines stop at the first failure, and Ctrl-C stops
// both.
func TestMenuRunLines(t *testing.T) {
	codes := map[string]int{"test": 4, "doctor": 0, "stop": -1}
	cases := []struct {
		cmds      [][]string
		keepGoing bool
		want      string
		ran       int
	}{
		{checkLines, true, "exit 4", 2},
		{checkLines, false, "exit 4", 1},
		{[][]string{{"stop"}, {"doctor"}}, true, "stopped", 1},
		{[][]string{{"doctor"}}, false, "exit 0", 1},
	}
	for _, c := range cases {
		ran := 0
		got, err := menuRunLines(c.cmds, c.keepGoing, func(args []string) (int, error) {
			ran++
			return codes[args[0]], nil
		})
		if err != nil || got != c.want || ran != c.ran {
			t.Errorf("%v keepGoing %v: %q after %d, want %q after %d", c.cmds, c.keepGoing, got, ran, c.want, c.ran)
		}
	}
	if next, _ := menuOpen(context.Background(), nil, nil, nil, checkAction, menuScreen{}, nil); !next.keepGoing {
		t.Error("Check everything stops at the first failure")
	}
}

// Set up my AI agent, tried first: a dry run says what it would do.
func TestGuideInstallDryRunText(t *testing.T) {
	files := []skillFile{{Path: "/h/.claude/skills/komando/SKILL.md", Action: "created"},
		{Path: "/h/.claude/settings.json", Action: "updated", Backup: "/h/.claude/settings.json.bak"}}
	g.dryRun = true
	dry := skillResult{Files: files}.Text()
	g.dryRun = false
	for _, line := range strings.Split(dry, "\n") {
		if strings.HasPrefix(line, "created") || strings.HasPrefix(line, "updated") || strings.Contains(line, "Restart") {
			t.Errorf("dry run says it was done: %q", line)
		}
	}
	if !strings.Contains(dry, "would create") || !strings.Contains(dry, "would be kept") {
		t.Errorf("dry run:\n%s", dry)
	}
	if real := (skillResult{Files: files}).Text(); !strings.HasPrefix(real, "created  ") {
		t.Errorf("real run:\n%s", real)
	}
}

// TestMenuCommandsMDBlock keeps the main-menu sample in
// docs/features/commands.md the same as what the menu draws for a small
// inventory: three servers, a database, a cache, a queue and two VPNs.
func TestMenuCommandsMDBlock(t *testing.T) {
	b, err := os.ReadFile("../../docs/features/commands.md")
	if err != nil {
		t.Fatal(err)
	}
	st := &store.State{
		Hosts: map[string]*store.Host{"web1": {Name: "web1"}, "web2": {Name: "web2"}, "db1": {Name: "db1"}},
		Conns: map[string]*store.Conn{
			"shop-db":      {Name: "shop-db", Kind: "postgres"},
			"cache1":       {Name: "cache1", Kind: "redis"},
			"orders-queue": {Name: "orders-queue", Kind: "kafka"},
		},
		Vpns:     map[string]*store.Vpn{"office": {Name: "office"}, "lab": {Name: "lab"}},
		Sessions: map[string]*store.VpnSession{"office": {Vpn: "office", PID: os.Getpid()}},
	}
	acts := menuMainActions(st, 0)
	l := menuMain(acts)
	scr := menuScreen{header: menuHeader(st), footer: menuKeysFor(l)}
	lines := renderText(l, scr, 100, 4+len(acts)+1)
	var b2 strings.Builder
	for _, ln := range lines {
		b2.WriteString(strings.TrimRight(ln, " ") + "\n")
	}
	want := "```text\n" + strings.TrimLeft(strings.TrimRight(b2.String(), "\n"), "\n") + "\n```"
	if !strings.Contains(string(b), want) {
		t.Errorf("docs/features/commands.md menu block is out of date; it should be:\n%s", want)
	}
}
