package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/snippet"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// The S1 samples: three built-ins over today's texts and parsers, to prove
// the engine end to end against the S0 goldens. They live in this test
// file only: the production list is empty until the S2 moves (design 7).

func rr(o snippet.Output) *sshx.RunResult {
	return &sshx.RunResult{Stdout: o.Stdout, Stderr: o.Stderr, ExitCode: o.ExitCode}
}

var sampleSvcList = snippet.Builtin{
	Name: "svc-list", Type: "host", Replaces: "svc list", Reader: "KomandoCall+Services.swift:36-43", Tier: capability.Read, Shape: "svc-list/1",
	Checks: []string{"TestSnippetGoldens/svc-list", "list_order_test.go"},
	Text: map[snippet.Family]string{
		snippet.Unix:    noSystemd + "systemctl list-units --type=service --all --no-legend --plain --no-pager",
		snippet.Windows: winSvcListScript,
	},
	Parse: func(o snippet.Output, f snippet.Family) (any, error) {
		if f == snippet.Windows {
			return winSvcList("")(nil, rr(o))
		}
		return svcListResult(rr(o))
	},
}

var unitVar = snippet.Var{Name: "unit", Channel: snippet.Text, Pattern: regexp.MustCompile(`^[A-Za-z0-9@._:\\-]+$`), MaxLen: 256, Required: true, Longest: strings.Repeat("a", 256)}

var sampleSvcStatus = snippet.Builtin{
	Name: "svc-status", Type: "host", Replaces: "svc status", Reader: "KomandoCall+Services.swift:36-43", Tier: capability.Read, Shape: "svc-status/1",
	Vars:   []snippet.Var{unitVar},
	Checks: []string{"TestSnippetGoldens/svc-status"},
	Text:   map[snippet.Family]string{snippet.Unix: noSystemd + "systemctl show --no-pager -p " + strings.Join(svcProps, ",") + " -- {{var:unit}}"},
	Parse:  func(o snippet.Output, _ snippet.Family) (any, error) { return svcResult(rr(o)) },
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
	}
	if i := strings.Index(got, "{"); i >= 0 {
		_ = json.Unmarshal([]byte(got[i:]), &env)
	}
	if env.Data != nil && env.Command != "snippet.exec" {
		t.Errorf("the envelope's command is %q, want snippet.exec", env.Command)
	}
	if err != nil {
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
	if len(builtinSnippets.Names()) != 0 {
		t.Fatalf("the production list has built-ins %v: they come with the S2 moves", builtinSnippets.Names())
	}
	rs := startReplayServer(t, replayStep{stdout: "x"})
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
	for _, c := range []struct {
		b       snippet.Builtin
		family  string
		windows bool
	}{
		{sampleSvcList, "systemd", false},
		{sampleSvcList, "windows", true},
		{sampleDockerPs, "docker", false},
	} {
		t.Run(c.b.Name+"/"+c.family, func(t *testing.T) {
			withSnippets(t, samples...)
			dir := filepath.Join("testdata", "snippets", c.b.Name)
			in, err := os.ReadFile(filepath.Join(dir, c.family+".in"))
			if err != nil {
				t.Fatal(err)
			}
			rs := startReplayServer(t, replayStep{stdout: string(in)})
			if c.windows {
				if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["dev"].OS = store.OSWindows; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			raw, e := snippetData(t, c.b.Name, "dev")
			if e != nil {
				t.Fatalf("snippet %s: %v", c.b.Name, e)
			}
			d, err := snippet.Decode(raw, c.b.Shape)
			if err != nil {
				t.Fatal(err)
			}
			if !d.OK || d.Target != "dev" || d.Snippet != c.b.Name {
				t.Fatalf("data = %+v", d)
			}
			var golden struct {
				Data struct {
					Results []struct {
						Data json.RawMessage `json:"data"`
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
			var res struct {
				Result json.RawMessage `json:"result"`
			}
			_ = json.Unmarshal(raw, &res)
			if got, want := compact(t, res.Result), compact(t, golden.Data.Results[0].Data); got != want {
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
		rs := startReplayServer(t, replayStep{stdout: string(in)})
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

// No sample is weaker than the command it replaces (rule 3.4).
func TestSnippetNotWeaker(t *testing.T) {
	for _, b := range samples {
		line := append(strings.Fields(b.Replaces), "dev")
		for _, v := range b.Vars {
			line = append(line, v.Longest)
		}
		today := riskOfLine(line)
		if int(b.Tier) < int(today.tier) {
			t.Errorf("%s is %v, weaker than %q at %v", b.Name, b.Tier, b.Replaces, today.tier)
		}
		if c, _, _ := lineWords(line); c == nil {
			t.Errorf("%s replaces %q, which is not a command", b.Name, b.Replaces)
		}
		if len(b.Checks) == 0 {
			t.Errorf("%s carries no checks", b.Name)
		}
	}
}

// Each text, filled with every variable's longest value, finds no exec
// rule (rule 3.5, Audit A-C368-4).
func TestSnippetFilledTextRules(t *testing.T) {
	for _, b := range samples {
		given := map[string]string{}
		for _, v := range b.Vars {
			given[v.Name] = v.Longest
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
	rs := startReplayServer(t, replayStep{stdout: "x"})
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
		{"no Windows body", []string{"svc-status", "dev", "--var", "unit=W3SVC"}, true, "SNIPPET_OS_UNSUPPORTED"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withSnippets(t, samples...)
			rs := startReplayServer(t, replayStep{stdout: "x"})
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
func TestSnippetWrongType(t *testing.T) {
	dbInfo := snippet.Builtin{Name: "db-info", Type: "database", Replaces: "db info", Reader: "KomandoCall.swift:69-72", Tier: capability.Read, Shape: "db-info/1",
		Run: func(context.Context, snippet.Values) (any, error) { return map[string]any{}, nil }}
	withSnippets(t, dbInfo)
	rs := startReplayServer(t, replayStep{stdout: "x"})
	if _, e := snippetData(t, "db-info", "dev"); e == nil || e.Code != "SNIPPET_WRONG_TYPE" {
		t.Fatalf("got %v, want SNIPPET_WRONG_TYPE", e)
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if len(rs.execs) != 0 {
		t.Fatalf("the server ran %q", rs.execs)
	}
}

func TestSnippetParseFailedShowsNoText(t *testing.T) {
	withSnippets(t, samples...)
	startReplayServer(t, replayStep{stdout: "not json: s3cret-raw-line\n"})
	raw, e := snippetData(t, "docker-ps", "dev")
	if e == nil || e.Code != "SNIPPET_PARSE_FAILED" {
		t.Fatalf("got %v, want SNIPPET_PARSE_FAILED", e)
	}
	if strings.Contains(string(raw), "s3cret-raw-line") || strings.Contains(string(raw), `"result"`) {
		t.Fatalf("a failed parse shows raw text or a result: %s", raw)
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
	startReplayServer(t, replayStep{stdout: "x"})
	raw, e := snippetData(t, "leaky", "dev")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), "hunter2-value") || !strings.Contains(string(raw), "ana") {
		t.Fatalf("the result is not masked for an agent: %s", raw)
	}
}
