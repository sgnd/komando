package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

// formParse checks that komando takes a line a form built: the command
// exists, its flags exist and parse, its arguments fit the command.
func formParse(t *testing.T, source string, args []string) *cobra.Command {
	t.Helper()
	root := newRoot()
	cmd, rest, err := root.Find(args)
	if err != nil || cmd == root || !cmd.Runnable() {
		t.Errorf("%s: `komando %s`: no such command", source, strings.Join(args, " "))
		return nil
	}
	if err := cmd.ParseFlags(rest); err != nil {
		t.Errorf("%s: `komando %s`: %v", source, menuCommandLine(args), err)
		return nil
	}
	if err := cmd.ValidateArgs(cmd.Flags().Args()); err != nil {
		t.Errorf("%s: `komando %s`: %v", source, menuCommandLine(args), err)
	}
	return cmd
}

// formSample is an answer a question takes: its first choice, its example
// or a plain word.
func formSample(st *store.State, q formQ, a formAnswers) string {
	if q.choices != nil {
		if rows := q.choices(st, a); len(rows) > 0 {
			return rows[0].value
		}
	}
	if d := formDefault(st, q, a); d != "" {
		return d
	}
	if q.check != nil {
		for _, v := range []string{"web9", "10.0.0.5", "5", "5m", "1.5", "x", "my-project", "eu-west-1", "123456789012"} {
			if q.check(st, a, v) == "" {
				return v
			}
		}
	}
	return "web9"
}

// Every command's generated questions build a line komando takes, with
// only the asked questions answered and with every flag set too.
func TestFormEveryCommandBuilds(t *testing.T) {
	st := testState()
	n := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if !s.Runnable() || s.Hidden || s.Name() == "help" || formHints[commandKey(s)].form != nil {
				continue
			}
			n++
			sp := formCmdSpec(s)
			for _, every := range []bool{false, true} {
				a := formAnswers{}
				for _, q := range sp.qs {
					if q.visible(st, a) && (every || !q.advanced) {
						a[q.key] = formSample(st, q, a)
					}
				}
				for _, line := range sp.build(st, a) {
					formParse(t, commandKey(s), line)
				}
				// Try it first is a dry run, never the real thing
				if dry := formDry(sp.build(st, a)); true {
					if c := formParse(t, commandKey(s)+" (try)", dry); c != nil {
						if f := c.Flags().Lookup("dry-run"); f == nil || !f.Changed {
							t.Errorf("%s: Try it first runs `komando %s` for real", commandKey(s), menuCommandLine(dry))
						}
					}
				}
			}
		}
	}
	walk(newRoot())
	if n < 150 {
		t.Errorf("only %d commands have questions", n)
	}
}

// Every command is in an All features area.
func TestFormEveryCommandHasAnArea(t *testing.T) {
	root := newRoot()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if s.Runnable() && !s.Hidden && s.Deprecated == "" && s.Name() != "help" && formAreaOf(s) < 0 {
				t.Errorf("%s is in no All features area", commandKey(s))
			}
		}
	}
	walk(root)
	for p, h := range formHints {
		c, _, err := root.Find(strings.Fields(p))
		if err != nil || commandKey(c) != p {
			t.Errorf("hint for %q: no such command", p)
			continue
		}
		if h.area != "" && !slices.ContainsFunc(formAreas, func(a struct {
			label, detail string
			words         []string
		}) bool {
			return a.label == h.area
		}) {
			t.Errorf("hint for %q: no area %q", p, h.area)
		}
		for _, f := range h.flags {
			if c.Flags().Lookup(f.name) == nil {
				t.Errorf("hint for %q: no flag --%s", p, f.name)
			}
		}
	}
}

// The hand-made Add forms build lines komando takes, and conn URLs the
// drivers read, for every kind and every choice of their first questions.
func TestFormAddKindsBuild(t *testing.T) {
	for _, st := range []*store.State{testState(), {Hosts: map[string]*store.Host{}}} {
		for _, g := range formGroups() {
			for _, k := range g.kinds {
				sp := k.spec()
				a := formAnswers{}
				for _, q := range sp.qs {
					if q.visible(st, a) {
						a[q.key] = formSample(st, q, a)
					}
				}
				for _, line := range sp.build(st, a) {
					cmd := formParse(t, g.label+"/"+k.label, line)
					if cmd != nil && commandKey(cmd) == "conn add" {
						if _, err := driver.Parse(cmd.Flags().Arg(1)); err != nil {
							t.Errorf("%s/%s: URL %q: %v", g.label, k.label, cmd.Flags().Arg(1), err)
						}
					}
				}
			}
		}
	}
}

func TestFormUseArgs(t *testing.T) {
	cases := map[string]string{
		"query CONN [SQL]":                                               "CONN [SQL]",
		"exec TARGET [--] COMMAND...":                                    "TARGET --COMMAND...",
		"add NAME [user@address[:port]]":                                 "NAME [user@address]",
		"replace TARGET PATH --old TEXT --new TEXT":                      "TARGET PATH",
		"grant CONN USER (--privileges P,... --on OBJECT | --role ROLE)": "CONN USER",
		"edit NAME|TARGET...":                                            "NAME...",
		"start TARGET [-L spec | -R spec | -D spec]":                     "TARGET",
		"list [flags]":                                                   "",
	}
	for use, want := range cases {
		var got []string
		for _, u := range formUseArgs(use, nil) {
			w := u.name
			if u.many {
				w += "..."
			}
			if u.dashes {
				w = "--" + w
			}
			if u.optional {
				w = "[" + w + "]"
			}
			got = append(got, w)
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%q: %q, want %q", use, strings.Join(got, " "), want)
		}
	}
}

func TestPastedSecret(t *testing.T) {
	cases := map[string]string{
		"root:hunter2@203.0.113.20":          "root@203.0.113.20",
		"root:p@ssw0rd@203.0.113.20":         "root@203.0.113.20",
		"postgres://app:s3cret@10.0.0.5/app": "postgres://app@10.0.0.5/app",
		"root@203.0.113.20":                  "",
		"10.0.0.5:2222":                      "",
		"https://minio.internal:9000":        "",
		"deploy@[2001:db8::1]":               "",
	}
	for in, want := range cases {
		got, found := pastedSecret(in)
		if found != (want != "") || (found && got != want) {
			t.Errorf("%q: %q %v, want %q", in, got, found, want)
		}
	}
}

func TestFormNameProblem(t *testing.T) {
	st := testState()
	for _, n := range menuNames(st.Hosts, "host")[:1] {
		p := formNameProblem(st, "host", strings.ToUpper(n))
		if !strings.Contains(p, "already a server") || strings.Contains(p, "like "+n+",") {
			t.Errorf("taken name %s: %q", n, p)
		}
	}
	for v, want := range map[string]string{"all": "means everything", "-x": "letters", "a b": "letters", "fresh1": ""} {
		if p := formNameProblem(st, "host", v); (want == "") != (p == "") || !strings.Contains(p, want) {
			t.Errorf("%q: %q, want %q", v, p, want)
		}
	}
}

// `komando host add` alone at a terminal asks, one question at a time,
// takes a pasted password out before it is ever drawn, and shows the
// commands it would run; Ctrl-C there adds nothing.
func TestFormHostAddAtATerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	invHome(t)
	p := startPTY(t, "host", "add")
	p.answer("What do you want to call this server?", "web1\r")
	p.answer("What does the server run?", "\r") // Linux
	p.answer("What is the server's address?", "root:hun@ter2@203.0.113.20")
	p.waitFor("a password was in it")
	p.answer("a password was in it", "\r")
	p.answer("User [root]: ", "\r")
	p.answer("Port [22]: ", "\r")
	p.answer("How do you log in?", "2") // A password
	p.answer("hurt real users", "2")    // No
	p.waitFor("check and run")
	p.waitFor("$ komando host add web1 root@203.0.113.20 --ask-password")
	p.waitFor("$ komando test web1")
	p.answer("Run it", "\x03") // Ctrl-C
	if code := p.exit(); code != 1 || !strings.Contains(p.shown(), "nothing was added") {
		t.Errorf("exit %d; the screen:\n%s", code, p.shown())
	}
	if strings.Contains(p.shown(), "ter2") || strings.Contains(p.shown(), "hun") {
		t.Errorf("the pasted password was drawn:\n%s", p.shown())
	}
	if _, err := invRun(t, "host", "show", "web1"); err == nil {
		t.Error("web1 was added after Ctrl-C")
	}
}

// An AI agent (or a script) that types an add command alone gets the usual
// usage error, never questions.
func TestFormAddAloneForAgents(t *testing.T) {
	invHome(t)
	for _, kind := range []string{"host", "conn", "vpn"} {
		_, e := invRun(t, kind, "add")
		if e == nil || e.Code != "USAGE" || !strings.Contains(e.Hint, "alone at a terminal") {
			t.Errorf("%s add: %+v", kind, e)
		}
	}
}

func TestFormDryRunBeforeDashes(t *testing.T) {
	got := formDry([][]string{{"exec", "web1", "--", "systemctl restart nginx"}})
	if strings.Join(got, "|") != "exec|web1|--dry-run|--|systemctl restart nginx" {
		t.Errorf("exec dry run: %q", got)
	}
	got = formDry([][]string{{"secret", "set", "x-authkey"}, {"vpn", "add", "x", "tailscale"}})
	if got[0] != "vpn" {
		t.Errorf("Try it first tries the secret set: %q", got)
	}
}

func TestFormSplitWords(t *testing.T) {
	cases := map[string]string{
		`-c 'ls | wc -l'`:     `-c|ls | wc -l`,
		`a "b c" d`:           `a|b c|d`,
		`  one   two `:        `one|two`,
		`it\'s`:               `it's`,
		`find /tmp -mtime +7`: `find|/tmp|-mtime|+7`,
	}
	for in, want := range cases {
		if got := strings.Join(formSplitWords(in), "|"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// A typed selector is kept as typed, not swapped for the first server it
// filters to; a moved cursor or an exact name picks that row.
func TestFormPicked(t *testing.T) {
	l := &menuList{typing: true, rows: []menuRow{
		{label: "web1", detail: "@web", value: "web1"}, {label: "web2", detail: "@web", value: "web2"},
		{label: "@web", detail: "group", value: "@web"}}}
	for typed, want := range map[string]string{"@web": "@web", "web2": "web2", "tag:prod": "tag:prod",
		"web1 web2": "web1 web2", "we": "web1", "": "web1", "nothing-like-it": "nothing-like-it"} {
		l.setFilter(typed)
		if got := formPicked(l, false); got != want {
			t.Errorf("typed %q: %q, want %q", typed, got, want)
		}
	}
	l.setFilter("web")
	l.cursor = 1
	if got := formPicked(l, true); got != "web2" {
		t.Errorf("moved to web2: %q", got)
	}
}
