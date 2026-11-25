package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/snippet"
	"github.com/sgnd/komando/internal/store"
)

// The samples the engine tests use: production built-ins, and docker-ps,
// which lives in this test file until its own S2 step (C455).

// sampleSvcList and sampleSvcStatus are the production built-ins (C454);
// tests change copies of them.
var sampleSvcList, sampleSvcStatus = production("svc-list"), production("svc-status")

func production(name string) snippet.Builtin {
	b, ok := builtinSnippets.Lookup(name)
	if !ok {
		panic("no built-in " + name)
	}
	return b
}

var sampleDockerPs = snippet.Builtin{
	Name: "docker-ps", Type: "host", Replaces: "docker ps", Reader: "KomandoCall+Docker.swift:10-54", Tier: capability.Read, Shape: "docker-ps/1",
	Checks: []string{"TestSnippetGoldens/docker-ps", "list_order_test.go"},
	Text:   map[snippet.Family]string{snippet.Unix: "docker ps --format '{{json .}}'"},
	Parse: func(o snippet.Output, _ snippet.Family) (any, error) {
		list, ok := parseJSONLines(nil, o.Stdout).([]any) // a line that is not JSON gives the text back: not a shape
		if !ok {
			return nil, errNotJSONLines
		}
		name := func(r any) string { m, _ := r.(map[string]any); return str(m["Names"]) }
		sort.SliceStable(list, func(i, j int) bool { return name(list[i]) < name(list[j]) })
		return list, nil
	},
}

var errNotJSONLines = errors.New("not JSON lines")

var samples = []snippet.Builtin{sampleSvcList, sampleSvcStatus, sampleDockerPs}

// registered is the production list, every type's list in one.
func registered() []snippet.Builtin {
	var all []snippet.Builtin
	for _, l := range builtinLists() {
		all = append(all, l...)
	}
	return all
}

// withSnippets turns the engine on for one test, with list as the built-ins.
func withSnippets(t *testing.T, list ...snippet.Builtin) {
	t.Helper()
	r, err := snippet.New(list)
	if err != nil {
		t.Fatal(err)
	}
	wasOn, was := snippetsOn, builtinSnippets
	snippetsOn, builtinSnippets = true, r
	t.Cleanup(func() { snippetsOn, builtinSnippets = wasOn, was })
}

// snippetData runs `recipe run` with -o json and returns the data of its
// envelope and the error.
func snippetData(t *testing.T, args ...string) (json.RawMessage, *out.Error) {
	t.Helper()
	var err error
	got := captureOutput(t, func() error {
		err = runRoot(t, append([]string{"-o", "json", "recipe", "run"}, args...)...)
		return err
	})
	var env struct {
		Command string          `json:"command"`
		Data    json.RawMessage `json:"data"`
		Error   *out.Error      `json:"error"`
	}
	if i := strings.Index(got, "{"); i >= 0 {
		_ = json.Unmarshal([]byte(got[i:]), &env)
	}
	if env.Data != nil && env.Command != "snippet.exec" {
		t.Errorf("the envelope's command is %q, want snippet.exec", env.Command)
	}
	switch {
	case env.Error != nil && env.Error.Code != "": // a failed server: the envelope names it
		return env.Data, env.Error
	case err != nil:
		return env.Data, toErr(err)
	}
	return env.Data, nil
}

func compact(t *testing.T, b []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	return buf.String()
}

// Nothing reaches the engine while it is off, even with built-ins listed:
// the name is a recipe name as before.
func TestSnippetsOff(t *testing.T) {
	if snippetsOn {
		t.Fatal("snippetsOn is true: the built-ins stay unreachable until the v2.7 cut turns them on")
	}
	rs := startReplayServerWith(t, nil, replayStep{stdout: "x"})
	for _, name := range builtinSnippets.Names() {
		if _, e := snippetData(t, name, "dev"); e == nil || e.Code != recipeNotFound(name).Code {
			t.Errorf("recipe run %s with the engine off = %v, want %s", name, e, recipeNotFound(name).Code)
		}
	}
	r, err := snippet.New(samples)
	if err != nil {
		t.Fatal(err)
	}
	was := builtinSnippets
	builtinSnippets = r
	t.Cleanup(func() { builtinSnippets = was })
	_, e := snippetData(t, "svc-list", "dev")
	if e == nil || e.Code != recipeNotFound("svc-list").Code {
		t.Fatalf("recipe run svc-list with the engine off = %v, want %s", e, recipeNotFound("svc-list").Code)
	}
	if len(rs.execs) != 0 {
		t.Fatalf("the server ran %q with the engine off", rs.execs)
	}
}

// Each sample gives the result today's command gives on the same replayed
// output, and sends the same text.
func TestSnippetSamplesMatchGoldens(t *testing.T) {
	all := append(registered(), sampleDockerPs)
	byName := map[string]snippet.Builtin{}
	for _, b := range all {
		byName[b.Name] = b
	}
	for _, c := range []struct {
		name, family string
		windows      bool
		vars         []string
	}{
		{"svc-list", "systemd", false, nil},
		{"svc-list", "windows", true, nil},
		{"svc-status", "systemd", false, []string{"unit=nginx,postfix"}},
		{"svc-status", "windows", true, []string{"unit=W3SVC,nope"}},
		{"docker-ps", "docker", false, nil},
		{"facts", "centos7", false, nil},
		{"facts", "windows", true, nil},
		{"facts-only", "debian", false, nil},
	} {
		t.Run(c.name+"/"+c.family, func(t *testing.T) {
			b, ok := byName[c.name]
			if !ok {
				t.Fatal("no such built-in")
			}
			withSnippets(t, all...)
			dir := filepath.Join("testdata", "snippets", b.Name)
			in, err := os.ReadFile(filepath.Join(dir, c.family+".in"))
			if err != nil {
				t.Fatal(err)
			}
			rs := startReplayServerWith(t, nil, replayStep{stdout: string(in)})
			if c.windows {
				if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["dev"].OS = store.OSWindows; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{b.Name, "dev"}
			for _, v := range c.vars {
				args = append(args, "--var", v)
			}
			raw, _ := snippetData(t, args...)
			d, err := snippet.Decode(raw, b.Shape)
			if err != nil {
				t.Fatalf("%v: %s", err, raw)
			}
			var golden struct {
				Data struct {
					Results []struct {
						OK    bool            `json:"ok"`
						Data  json.RawMessage `json:"data"`
						Error *out.Error      `json:"error"`
					} `json:"results"`
				} `json:"data"`
			}
			gb, err := os.ReadFile(filepath.Join(dir, c.family+".out.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(gb, &golden); err != nil || len(golden.Data.Results) != 1 {
				t.Fatalf("golden: %v", err)
			}
			today := golden.Data.Results[0]
			if d.OK != today.OK || d.Target != "dev" || d.Snippet != b.Name {
				t.Fatalf("data = %+v, want ok %v", d, today.OK)
			}
			if (d.Error == nil) != (today.Error == nil) || d.Error != nil && (d.Error.Code != today.Error.Code || d.Error.Message != today.Error.Message) {
				t.Fatalf("error = %v, today's %v", d.Error, today.Error)
			}
			var res struct {
				Result json.RawMessage `json:"result"`
			}
			_ = json.Unmarshal(raw, &res)
			if got, want := compact(t, res.Result), compact(t, today.Data); got != want {
				t.Errorf("result differs from today's command\n got:  %s\n want: %s", got, want)
			}
			sent, err := os.ReadFile(filepath.Join(dir, c.family+".sent.txt"))
			if err != nil {
				t.Fatal(err)
			}
			rs.mu.Lock()
			got := strings.Join(rs.sent, "\n----\n") + "\n"
			rs.mu.Unlock()
			if got != string(sent) {
				t.Errorf("sent text differs from today's command\n got:  %s\n want: %s", got, sent)
			}
		})
	}
}

// A filled variable gives the text and the result today's command gives
// for the same unit.
func TestSnippetFilledLikeTheReplacedCommand(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("testdata", "snippets", "svc-status", "systemd.in"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, json.RawMessage) {
		rs := startReplayServerWith(t, nil, replayStep{stdout: string(in)})
		var data json.RawMessage
		got := captureOutput(t, func() error { return runRoot(t, append([]string{"-o", "json"}, args...)...) })
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		_ = json.Unmarshal([]byte(got[strings.Index(got, "{"):]), &env)
		data = env.Data
		rs.mu.Lock()
		defer rs.mu.Unlock()
		return strings.Join(rs.sent, "\n----\n"), data
	}
	wantSent, today := run("svc", "status", "dev", "nginx")
	withSnippets(t, samples...)
	gotSent, mine := run("recipe", "run", "svc-status", "dev", "--var", "unit=nginx")
	if gotSent != wantSent {
		t.Errorf("sent\n got:  %s\n want: %s", gotSent, wantSent)
	}
	var a struct {
		Results []struct {
			Data json.RawMessage `json:"data"`
		} `json:"results"`
	}
	var b struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(today, &a); err != nil || len(a.Results) != 1 {
		t.Fatalf("today: %v %s", err, today)
	}
	if err := json.Unmarshal(mine, &b); err != nil {
		t.Fatal(err)
	}
	if g, w := compact(t, b.Result), compact(t, a.Results[0].Data); g != w {
		t.Errorf("result\n got:  %s\n want: %s", g, w)
	}
}

// notWeaker says why b is weaker than the command it replaces, or "".
func notWeaker(b snippet.Builtin) string {
	// the command's words, the target, then its flags: "facts --only x"
	// is rated as `facts dev --only x`
	words := strings.Fields(b.Replaces)
	n := slices.IndexFunc(words, func(w string) bool { return strings.HasPrefix(w, "-") })
	if n < 0 {
		n = len(words)
	}
	line := append(append(slices.Clone(words[:n]), "dev"), words[n:]...)
	for _, v := range b.Vars {
		line = append(line, strings.Split(snippet.LongestValue(v), ",")...)
	}
	if c, _, _ := lineWords(line); n == 0 || c == nil || c.Name() != words[n-1] {
		return fmt.Sprintf("replaces %q, which is not a command", b.Replaces)
	}
	if today := riskOfLine(line); int(b.Tier) < int(today.tier) {
		return fmt.Sprintf("is %v, weaker than %q at %v", b.Tier, b.Replaces, today.tier)
	}
	if len(b.Checks) == 0 {
		return "carries no checks"
	}
	return ""
}

// No sample is weaker than the command it replaces (rule 3.4).
func TestSnippetNotWeaker(t *testing.T) {
	for _, b := range append(registered(), samples...) {
		if why := notWeaker(b); why != "" {
			t.Errorf("%s %s", b.Name, why)
		}
	}
	restart := sampleSvcStatus
	restart.Replaces = "svc restart"
	if notWeaker(restart) == "" {
		t.Error("a read snippet replacing svc restart passed")
	}
	restart.Tier = capability.Change
	if why := notWeaker(restart); why != "" {
		t.Errorf("a change snippet replacing svc restart: %s", why)
	}
	none := sampleSvcList
	none.Replaces = "svc nosuchverb"
	if notWeaker(none) == "" {
		t.Error("a snippet replacing no command passed")
	}
	bare := sampleSvcList
	bare.Checks = nil
	if notWeaker(bare) == "" {
		t.Error("a snippet carrying no checks passed")
	}
}

// Each text, filled with every variable's longest value, finds no exec
// rule (rule 3.5, Audit A-C368-4).
func TestSnippetFilledTextRules(t *testing.T) {
	for _, b := range append(registered(), samples...) {
		given := map[string]string{}
		for _, v := range b.Vars {
			given[v.Name] = snippet.LongestValue(v)
		}
		for f := range b.Text {
			text, err := snippet.Fill(b, f, given)
			if err != nil {
				t.Fatalf("%s %s: %v", b.Name, f, err)
			}
			if hits := policy.Check(text, nil); len(hits) > 0 {
				t.Errorf("%s %s: the filled text hits %v", b.Name, f, hits)
			}
		}
	}
}

// The filled text goes through the same guard as a typed exec line: a
// rule hit stops it, and a change asks on a protected server.
func TestSnippetGuardSeesTheFilledText(t *testing.T) {
	wipe := snippet.Builtin{Name: "wipe", Type: "host", Replaces: "svc list", Reader: "test", Tier: capability.Read, Shape: "wipe/1",
		Vars:  []snippet.Var{{Name: "path", Channel: snippet.Text, Pattern: regexp.MustCompile(`^/[a-z/]*$`), MaxLen: 4, Longest: "/etc"}},
		Text:  map[snippet.Family]string{snippet.Unix: "rm -rf {{var:path}}"},
		Parse: func(o snippet.Output, _ snippet.Family) (any, error) { return o.Stdout, nil }}
	setCallerEnv(t, "CLAUDECODE", "1")
	rs := startReplayServerWith(t, nil, replayStep{stdout: "x"})
	withSnippets(t, wipe)
	if _, e := snippetData(t, "wipe", "dev", "--var", "path=/etc"); e == nil || e.Code != "POLICY_BLOCKED" {
		t.Fatalf("a filled rm -rf = %v, want POLICY_BLOCKED", e)
	}
	change := sampleSvcList
	change.Name, change.Shape, change.Tier = "svc-change", "svc-change/1", capability.Change
	withSnippets(t, change)
	if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["dev"].Protected = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, e := snippetData(t, "svc-change", "dev"); e == nil || e.Code != "PROTECTED_TARGET" {
		t.Fatalf("a change on a protected server = %v, want PROTECTED_TARGET", e)
	}
	withSnippets(t, sampleSvcList)
	if _, e := snippetData(t, "svc-list", "dev"); e != nil {
		t.Fatalf("a read on a protected server = %v; a read needs nothing", e)
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if len(rs.execs) != 1 || !strings.Contains(rs.execs[0], "list-units") {
		t.Errorf("only the read may run; the server ran %q", rs.execs)
	}
}

func TestSnippetRefusalsRunNothing(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		windows bool
		code    string
	}{
		{"unknown variable", []string{"svc-list", "dev", "--var", "x=1"}, false, "UNKNOWN_VAR"},
		{"value off pattern", []string{"svc-status", "dev", "--var", "unit=a;reboot"}, false, "USAGE"},
		{"missing variable", []string{"svc-status", "dev"}, false, "USAGE"},
		{"no Windows body", []string{"docker-ps", "dev"}, true, "SNIPPET_OS_UNSUPPORTED"},
		{"off the Windows pattern", []string{"svc-status", "dev", "--var", "unit=W3SVC,a:b"}, true, "USAGE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withSnippets(t, samples...)
			rs := startReplayServerWith(t, nil, replayStep{stdout: "x"})
			if c.windows {
				if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["dev"].OS = store.OSWindows; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			if _, e := snippetData(t, c.args...); e == nil || e.Code != c.code {
				t.Fatalf("got %v, want %s", e, c.code)
			}
			rs.mu.Lock()
			defer rs.mu.Unlock()
			if len(rs.execs) != 0 {
				t.Fatalf("the server ran %q", rs.execs)
			}
		})
	}
}

// A built-in of another entry type is refused before anything runs.
func TestSnippetTypeUnsupported(t *testing.T) {
	dbInfo := snippet.Builtin{Name: "db-info", Type: "database", Replaces: "db info", Reader: "KomandoCall.swift:69-72", Tier: capability.Read, Shape: "db-info/1",
		Run: func(context.Context, snippet.Values) (any, error) { return map[string]any{}, nil }}
	withSnippets(t, dbInfo)
	rs := startReplayServerWith(t, nil, replayStep{stdout: "x"})
	if _, e := snippetData(t, "db-info", "dev"); e == nil || e.Code != "SNIPPET_TYPE_UNSUPPORTED" {
		t.Fatalf("got %v, want SNIPPET_TYPE_UNSUPPORTED", e)
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if len(rs.execs) != 0 {
		t.Fatalf("the server ran %q", rs.execs)
	}
}

func TestSnippetParseFailedShowsNoText(t *testing.T) {
	withSnippets(t, samples...)
	startReplayServerWith(t, nil, replayStep{stdout: "not json: s3cret-raw-line\n"})
	raw, e := snippetData(t, "docker-ps", "dev")
	if e == nil || e.Code != "SNIPPET_PARSE_FAILED" {
		t.Fatalf("got %v, want SNIPPET_PARSE_FAILED", e)
	}
	if strings.Contains(string(raw), "s3cret-raw-line") || strings.Contains(string(raw), `"result"`) {
		t.Fatalf("a failed parse shows raw text or a result: %s", raw)
	}
	// the server's own row says it failed, and why
	d, err := snippet.Decode(raw, sampleDockerPs.Shape)
	if err != nil {
		t.Fatal(err)
	}
	if d.OK || d.Error == nil || d.Error.Code != "SNIPPET_PARSE_FAILED" {
		t.Fatalf("the row = ok %v, error %v; want SNIPPET_PARSE_FAILED", d.OK, d.Error)
	}
}

func TestSnippetResultIsMaskedForAnAgent(t *testing.T) {
	leaky := sampleDockerPs
	leaky.Name, leaky.Shape = "leaky", "leaky/1"
	leaky.Parse = func(snippet.Output, snippet.Family) (any, error) {
		return map[string]any{"password": "hunter2-value", "user": "ana"}, nil
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	withSnippets(t, leaky)
	startReplayServerWith(t, nil, replayStep{stdout: "x"})
	raw, e := snippetData(t, "leaky", "dev")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), "hunter2-value") || !strings.Contains(string(raw), "ana") {
		t.Fatalf("the result is not masked for an agent: %s", raw)
	}
}

// Each tier stops a run the way the command it replaces would (Audit
// S1-1): dangerous needs --allow-dangerous, safety needs --yes, person
// needs a person at a terminal; a rule hit in the filled text makes even a
// change snippet dangerous. Stand-in built-ins over svc-list's text.
func TestSnippetTierStops(t *testing.T) {
	at := func(name string, tier capability.Tier) snippet.Builtin {
		b := sampleSvcList
		b.Name, b.Shape, b.Tier = name, name+"/1", tier
		return b
	}
	hit := at("hit-change", capability.Change)
	hit.Text = map[snippet.Family]string{snippet.Unix: "rm -rf /srv/old; systemctl list-units --type=service --all --no-legend --plain --no-pager"}
	list := []snippet.Builtin{at("t-read", capability.Read), at("t-change", capability.Change), at("t-protected", capability.Protected),
		at("t-dangerous", capability.Dangerous), at("t-safety", capability.Safety), at("t-person", capability.Person), hit}
	in, err := os.ReadFile(filepath.Join("testdata", "snippets", "svc-list", "systemd.in"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		agent bool
		args  []string
		code  string // "" runs
	}{
		{true, []string{"t-read", "dev"}, ""},
		{true, []string{"t-change", "dev"}, ""},
		{true, []string{"t-protected", "dev"}, ""},
		{true, []string{"t-dangerous", "dev"}, "POLICY_BLOCKED"},
		{true, []string{"t-safety", "dev"}, "SAFETY_SETTING"},
		{true, []string{"t-person", "dev"}, "NEEDS_PERSON"},
		{true, []string{"hit-change", "dev"}, "POLICY_BLOCKED"},
		{false, []string{"t-dangerous", "dev"}, "POLICY_BLOCKED"},
		{false, []string{"t-dangerous", "dev", "--allow-dangerous"}, ""},
		{false, []string{"t-safety", "dev"}, "SAFETY_SETTING"},
		{false, []string{"t-safety", "dev", "--yes"}, ""},
		{false, []string{"t-person", "dev", "--yes", "--allow-dangerous"}, "NEEDS_PERSON"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("agent=%v/%s", c.agent, strings.Join(c.args, " ")), func(t *testing.T) {
			if c.agent {
				setCallerEnv(t, "CLAUDECODE", "1")
			} else {
				noAgent(t)
			}
			withSnippets(t, list...)
			rs := startReplayServerWith(t, nil, replayStep{stdout: string(in)})
			_, e := snippetData(t, c.args...)
			rs.mu.Lock()
			ran := len(rs.execs)
			rs.mu.Unlock()
			switch {
			case c.code == "" && (e != nil || ran != 1):
				t.Fatalf("want a run, got %v and %d execs", e, ran)
			case c.code != "" && (e == nil || e.Code != c.code || ran != 0):
				t.Fatalf("want %s and no exec, got %v and %d execs", c.code, e, ran)
			}
		})
	}
	// --dry-run reports the person stop as would_be_blocked, as every
	// policy stop does (policyStop), and writes no blocked audit record
	t.Run("agent=true/t-person dev --dry-run", func(t *testing.T) {
		setCallerEnv(t, "CLAUDECODE", "1")
		withSnippets(t, list...)
		rs := startReplayServerWith(t, nil, replayStep{stdout: string(in)})
		d, e := snippetData(t, "t-person", "dev", "--dry-run")
		rs.mu.Lock()
		ran := len(rs.execs)
		rs.mu.Unlock()
		if e != nil || ran != 0 {
			t.Fatalf("want a preview and no exec, got %v and %d execs", e, ran)
		}
		var data struct {
			WouldBeBlocked *out.Error `json:"would_be_blocked"`
		}
		if err := json.Unmarshal(d, &data); err != nil || data.WouldBeBlocked == nil || data.WouldBeBlocked.Code != "NEEDS_PERSON" {
			t.Fatalf("want data.would_be_blocked NEEDS_PERSON, got %s", d)
		}
		if strings.Contains(auditText(t), "NEEDS_PERSON") {
			t.Fatal("a dry run wrote a blocked audit record")
		}
	})
}

// facts-only on a Windows host gives what `facts --only` gives there (the
// full probe, its keys kept) and sends the same text. No S0 golden has a
// Windows facts --only, so the two run side by side on facts' Windows .in.
func TestSnippetFactsOnlyWindowsLikeTheCommand(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("testdata", "snippets", "facts", "windows.in"))
	if err != nil {
		t.Fatal(err)
	}
	// the S0 input has none of the polled keys; the second carries them
	polled := "os_version=6.3.9600\nuptime_sec=86400\nmem_total_mb=8192\nmem_available_mb=2048\n" +
		"disk_root_total_gb=127\ndisk_root_used_pct=40\ndisk=C:\t133169152\t53267660\t79901492\t40\tC:\\\n"
	for name, in := range map[string]string{"s0": string(base), "polled": string(base) + polled} {
		t.Run(name, func(t *testing.T) { factsOnlyWindowsLikeTheCommand(t, in) })
	}
}

func factsOnlyWindowsLikeTheCommand(t *testing.T, in string) {
	run := func(args ...string) (string, json.RawMessage) {
		rs := startReplayServerWith(t, nil, replayStep{stdout: in})
		if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["dev"].OS = store.OSWindows; return nil }); err != nil {
			t.Fatal(err)
		}
		got := captureOutput(t, func() error { return runRoot(t, append([]string{"-o", "json"}, args...)...) })
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if i := strings.Index(got, "{"); i >= 0 {
			_ = json.Unmarshal([]byte(got[i:]), &env)
		}
		rs.mu.Lock()
		defer rs.mu.Unlock()
		return strings.Join(rs.sent, "\n----\n"), env.Data
	}
	wantSent, today := run("facts", "dev", "--only", strings.Join(factsOnlyAll, ","))
	withSnippets(t, registered()...)
	gotSent, mine := run("recipe", "run", "facts-only", "dev")
	if gotSent != wantSent {
		t.Errorf("sent\n got:  %s\n want: %s", gotSent, wantSent)
	}
	var a struct {
		Results []struct {
			Data json.RawMessage `json:"data"`
		} `json:"results"`
	}
	var b struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(today, &a); err != nil || len(a.Results) != 1 {
		t.Fatalf("today: %v %s", err, today)
	}
	if err := json.Unmarshal(mine, &b); err != nil || len(b.Result) == 0 {
		t.Fatalf("snippet: %v %s", err, mine)
	}
	if g, w := compact(t, b.Result), compact(t, a.Results[0].Data); g != w {
		t.Errorf("result\n got:  %s\n want: %s", g, w)
	}
}

// A list variable gives the text and the result `svc status` gives for
// the same units, in the order given.
func TestSnippetListLikeTheReplacedCommand(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("testdata", "snippets", "svc-status", "systemd.in"))
	if err != nil {
		t.Fatal(err)
	}
	withSnippets(t, samples...)
	rs := startReplayServerWith(t, nil, replayStep{stdout: string(in)})
	if _, e := snippetData(t, "svc-status", "dev", "--var", "unit=nginx,postfix"); e != nil {
		t.Fatal(e)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "snippets", "svc-status", "systemd.sent.txt"))
	if err != nil {
		t.Fatal(err)
	}
	rs.mu.Lock()
	got := strings.Join(rs.sent, "\n----\n") + "\n"
	rs.mu.Unlock()
	if got != string(want) {
		t.Errorf("sent\n got:  %s\n want: %s", got, want)
	}
}

// A snippet with Sudo runs its Unix text with sudo, as the command it
// replaces does; --no-sudo runs it without.
func TestSnippetSudo(t *testing.T) {
	b := sampleSvcList
	b.Name, b.Shape, b.Sudo = "sudo-list", "sudo-list/1", true
	in, err := os.ReadFile(filepath.Join("testdata", "snippets", "svc-list", "systemd.in"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		b    snippet.Builtin
		args []string
		sudo bool
	}{
		{"sudo", b, nil, true},
		{"no-sudo", b, []string{"--no-sudo"}, false},
		{"no sudo field", sampleSvcList, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			withSnippets(t, c.b)
			rs := startReplayServerWith(t, nil, replayStep{stdout: string(in)})
			if _, e := snippetData(t, append([]string{c.b.Name, "dev"}, c.args...)...); e != nil {
				t.Fatal(e)
			}
			rs.mu.Lock()
			sent := strings.Join(rs.sent, "\n")
			rs.mu.Unlock()
			if got := strings.HasPrefix(sent, "sudo -n "); got != c.sudo {
				t.Fatalf("sent with sudo = %v, want %v: %s", got, c.sudo, sent)
			}
		})
	}
}

// svc-status takes the unit names each family's command takes today: a
// systemd name (with \\x escapes) in the Unix text, a Windows service name
// (winServiceName) in the PowerShell text, refused before anything runs.
func TestSnippetSvcUnitNames(t *testing.T) {
	b := sampleSvcStatus
	for _, c := range []struct {
		f    snippet.Family
		unit string
		ok   bool
	}{
		{snippet.Unix, "nginx.service", true},
		{snippet.Unix, "user@1000.service", true},
		{snippet.Unix, `systemd-fsck@dev-disk-by\x2duuid.service`, true},
		{snippet.Unix, "MSSQL$SQLEXPRESS", false},
		{snippet.Unix, "web app", false},
		{snippet.Windows, "W3SVC", true},
		{snippet.Windows, "MSSQL$SQLEXPRESS", true},
		{snippet.Windows, "web app", true},
		{snippet.Windows, `a\x2db`, false},
		{snippet.Windows, "a:b", false},
		{snippet.Windows, "_x", false},
		{snippet.Unix, "a;b", false},
		{snippet.Windows, "a'b", false},
	} {
		_, err := snippet.Fill(b, c.f, map[string]string{"unit": c.unit})
		if (err == nil) != c.ok {
			t.Errorf("%s %q: %v, want ok %v", c.f, c.unit, err, c.ok)
		}
	}
}
