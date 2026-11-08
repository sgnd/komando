package cli

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

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
	l := menuMain([]menuAction{shellAction, listAction})
	if o := l.update(menuKey{kind: keyRune, r: '?'}, 10); o != menuChosen {
		t.Fatalf("?: outcome %v", o)
	}
	if row, _ := l.chosen(); row.value != helpAction.name {
		t.Fatalf("? chose %q, want Help", row.value)
	}
	l.update(menuKey{kind: keyDown}, 10) // any other key forgets it
	if row, _ := l.chosen(); row.value != listAction.name {
		t.Fatalf("after Down: %q, want List", row.value)
	}
	f := testMenuList(3, true)
	f.hot = map[rune]string{'?': "Help"}
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
	if text := strings.Join(renderText(l, s, 20, 12), "\n"); !strings.Contains(text, "\x1b[36;1m> u-row") {
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
	m.note = menuNoServer
	lines = renderText(m, menuScreen{header: []seg{{"komando", ""}}, footer: "keys"}, 80, 10)
	if len(lines) != 10 || lines[3] != menuNoServer || lines[4] != "" || !strings.HasPrefix(lines[5], "> 1. a-row") {
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
	cases := map[string]string{
		"web1 deploy@10.0.0.5":     "",
		"  web1   10.0.0.5:2222  ": "",
		"web1":                     "type a name",
		"web1 a b":                 "type a name",
		"-rf deploy@10.0.0.5":      "invalid host name",
		"all deploy@10.0.0.5":      "cannot be a host name",
		"web1 -oProxyCommand=x":    "cannot start with -",
	}
	for in, want := range cases {
		args, problem := menuAddArgs(in)
		switch {
		case want == "" && (problem != "" || len(args) != 4 || args[0] != "host" || args[1] != "add"):
			t.Errorf("%q: %v %q", in, args, problem)
		case want != "" && (args != nil || !strings.Contains(problem, want)):
			t.Errorf("%q: %v %q, want a problem with %q", in, args, problem, want)
		}
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
	cases := []struct {
		name      string
		st        *store.State
		sshConfig bool
		want      []string
	}{
		{"new, with ~/.ssh/config", empty, true, []string{"Import", "Add", "List", "Audit", "Doctor"}},
		{"new, no ~/.ssh/config", empty, false, []string{"Add", "List", "Audit", "Doctor"}},
		{"conns and a VPN, no server", onlyConns, true, []string{"Import", "Add", "Test", "Database", "VPN", "List", "Audit", "Doctor"}},
		{"servers", testState(), true, []string{"Shell", "Test", "Facts", "List", "Audit", "Doctor"}},
		{"everything", menuTestState(), true, []string{"Shell", "Test", "Facts", "Database", "VPN", "List", "Audit", "Doctor"}},
	}
	for _, c := range cases {
		got := actionNames(menuMainActions(c.st, c.sshConfig))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if len(got) > 9 {
			t.Errorf("%s: %d rows; the number keys reach 9", c.name, len(got))
		}
	}
	redisOnly := &store.State{Hosts: map[string]*store.Host{}, Conns: map[string]*store.Conn{"cache": menuTestState().Conns["cache"]}}
	if slices.Contains(actionNames(menuMainActions(redisOnly, false)), "Database") {
		t.Error("Database shows with no database conn (only redis)")
	}
	// names the lists leave out (a host "all" from before it was refused,
	// a hand-edited "-x") do not count: no Shell that opens an empty list
	// and hides Add
	oldNames := &store.State{
		Hosts: map[string]*store.Host{"all": {Name: "all", Address: "old.lan"}},
		Conns: map[string]*store.Conn{"-x": {Name: "-x", Kind: "postgres", URL: "postgres://u@db.lan/x"}},
	}
	if got := actionNames(menuMainActions(oldNames, false)); !slices.Equal(got, []string{"Add", "List", "Audit", "Doctor"}) {
		t.Errorf("only names the lists leave out: %v", got)
	}
	// every action is a command line komando takes: command, sub-command
	// and flags, as the docs examples are checked (docs_test.go)
	root := newRoot()
	picked := map[string]string{"host": " web1", "target": " web1", "db": " app-db", "vpn": " office", "line": " web1 deploy@10.0.0.5"}
	all := []menuAction{importAction, addAction, shellAction, testAction, factsAction, dbAction, vpnAction, listAction, auditAction, doctorAction}
	for _, a := range all {
		line := "komando " + menuCommandLine(a.args) + picked[a.pick]
		if checkExampleLines(t, root, "menu action "+a.name, line) != 1 {
			t.Errorf("%s: `%s` was not checked", a.name, line)
		}
	}
	if !slices.ContainsFunc(importSources, func(s importSource) bool { return s.Name == importAction.args[1] }) {
		t.Errorf("Import runs an unknown source %q", importAction.args[1])
	}
	if helpAction.args[0] != "--help" {
		t.Errorf("? runs %v", helpAction.args)
	}
	// the sessions end with their own line; the menu does not repeat exit 0
	for _, a := range all {
		if want := a.name == "Shell" || a.name == "Database"; a.ownExit != want {
			t.Errorf("%s: ownExit %v", a.name, a.ownExit)
		}
	}
}

func TestMenuTargets(t *testing.T) {
	st := menuTestState()
	st.Hosts["web-1"].User, st.Hosts["web-1"].Port, st.Hosts["web-1"].Protected = "deploy", 2222, true
	st.Hosts["web-alias"] = &store.Host{Name: "web-alias", Address: "WEB-1.lan", Port: 2222} // the same server
	st.Hosts["bad\x1b[2Jname"] = &store.Host{Name: "bad\x1b[2Jname", Address: "bad.lan"}
	st.Hosts["-rf"] = &store.Host{Name: "-rf", Address: "flag.lan"}
	st.Hosts["all"] = &store.Host{Name: "all", Address: "old.lan"} // from before "all" was refused
	st.Hosts["ctl"] = &store.Host{Name: "ctl", Address: "x\x07.lan\x1b[2J", Tags: []string{"t\x1b]0;title\x07"}}
	st.Conns["all"] = &store.Conn{Name: "all", Kind: "postgres", URL: "postgres://x@old.lan/x"}
	st.Conns["prod-db"] = &store.Conn{Name: "prod-db", Kind: "postgres", URL: "postgres://app@10.0.0.9:5432/other"} // same server as app-db
	st.Conns["app-db"].Protected = true
	st.Conns["leaky"] = &store.Conn{Name: "leaky", Kind: "mysql", URL: "mysql://app:hunter2@10.0.0.7/app"}    // komando refuses this URL
	st.Conns["files"] = &store.Conn{Name: "files", Kind: "sftp", URL: "sftp://deploy@web-1.lan:2222/var/www"} // protected web-1 over SFTP

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

	test := menuTargets(st, testAction)
	want := []string{"all", "ctl", "db-1", "dev-1", "web-1", "web-2", "web-alias", "app-db", "cache", "files", "leaky", "prod-db", "office"}
	if got := labels(test); !slices.Equal(got, want) { // the selector all only: no host or conn named all, no bad name, no -rf
		t.Errorf("Test rows %v, want %v", got, want)
	}
	if test.title != "Test: which one?" {
		t.Errorf("Test title %q", test.title)
	}
	if d := detail(test, "web-1"); d != "protected  deploy@web-1.lan:2222  @web  prod" {
		t.Errorf("web-1 detail %q (protected first)", d)
	}
	if d := detail(test, "web-alias"); !strings.HasPrefix(d, "protected  ") {
		t.Errorf("the same server as protected web-1 must say so: %q", d)
	}
	if d := detail(test, "app-db"); d != "protected  postgres  10.0.0.9:5432  @prod" {
		t.Errorf("app-db detail %q", d)
	}
	if d := detail(test, "files"); !strings.HasPrefix(d, "protected  sftp") {
		t.Errorf("an SFTP conn to protected web-1 must say so: %q", d)
	}
	if d := detail(test, "leaky"); d != "mysql" {
		t.Errorf("a URL komando cannot read is never shown, it may hold a password: %q", d)
	}
	if d := detail(test, "prod-db"); !strings.HasPrefix(d, "protected  ") {
		t.Errorf("the same database server as protected app-db must say so: %q", d)
	}
	if d := detail(test, "office"); d != "vpn socks  127.0.0.1:1080" {
		t.Errorf("office detail %q", d)
	}
	for _, r := range test.rows {
		if strings.ContainsAny(r.label+r.detail, "\x1b\x07") {
			t.Errorf("control characters reach the screen: %q %q", r.label, r.detail)
		}
	}

	shell := menuTargets(st, shellAction)
	if got := labels(shell); slices.Contains(got, "all") || slices.Contains(got, "app-db") || slices.Contains(got, "office") || shell.title != "Shell: which server?" {
		t.Errorf("Shell offers %v (%q): servers only", got, shell.title)
	}
	if got := labels(menuTargets(st, dbAction)); !slices.Equal(got, []string{"app-db", "leaky", "prod-db"}) {
		t.Errorf("Database offers %v: database conns only", got)
	}
	if got := labels(menuTargets(st, vpnAction)); !slices.Equal(got, []string{"office"}) {
		t.Errorf("VPN offers %v", got)
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
