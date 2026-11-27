package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/snippet"
	"github.com/sgnd/komando/internal/store"
)

// sampleSvcList, sampleSvcStatus and sampleDockerPs are production
// built-ins; tests change copies of them.
var sampleSvcList, sampleSvcStatus, sampleDockerPs = production("svc-list"), production("svc-status"), production("docker-ps")

func production(name string) snippet.Builtin {
	b, ok := builtinSnippets.Lookup(name)
	if !ok {
		panic("no built-in " + name)
	}
	return b
}

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
	all := registered()
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
		{"docker-images", "docker", false, nil},
		{"docker-stats", "docker", false, nil},
		{"facts", "centos7", false, nil},
		{"facts", "windows", true, nil},
		{"facts-only", "debian", false, nil},
		{"pkg-upgradable", "apt", false, nil},
		{"pkg-upgradable", "apk", false, nil},
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
			step := replayStep{stdout: string(in)}
			if e, err := os.ReadFile(filepath.Join(dir, c.family+".err")); err == nil {
				step.stderr = string(e)
			}
			rs := startReplayServerWith(t, nil, step)
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

// previewReads are the command lines a written rule rates as reads where
// the static rating of a line gives the worst case: a dry-run preview
// that only reads (rule 3.8, decided by the chief with apps N9, accepted
// in Audit's delta read), and a command whose tier depends on a flag
// without it (rule 3.1: --refresh makes pkg upgradable and pkg security a
// change, and pkg-security-refresh keeps the change).
var previewReads = map[string]bool{"docker prune --dry-run": true, "fs write --dry-run": true,
	"pkg upgradable": true, "pkg security": true}

// notWeaker says why b is weaker than the command it replaces, or "".
func notWeaker(b snippet.Builtin) string {
	// the command's words, the target, then its flags: "facts --only x"
	// is rated as `facts dev --only x`
	words := strings.Fields(b.Replaces)
	n := slices.IndexFunc(words, func(w string) bool { return strings.HasPrefix(w, "-") })
	if n < 0 {
		n = len(words)
	}
	// a command step D removed has no rating left to compare with: exec
	// carries it, and TestReplacedIDsNameTheirRules pins what protects it
	if n > 0 && slices.Contains(removedIDs, strings.Join(words[:n], ".")) {
		if len(b.Checks) == 0 {
			return "carries no checks"
		}
		return ""
	}
	line := append(append(slices.Clone(words[:n]), "dev"), words[n:]...)
	for _, v := range b.Vars {
		line = append(line, strings.Split(snippet.LongestValue(v), ",")...)
	}
	if c, _, _ := lineWords(line); n == 0 || c == nil || c.Name() != words[n-1] {
		return fmt.Sprintf("replaces %q, which is not a command", b.Replaces)
	}
	if previewReads[b.Replaces] {
		if b.Tier != capability.Read {
			return fmt.Sprintf("is %v; this line is a read by its written rule (3.1 or 3.8)", b.Tier)
		}
	} else if today := riskOfLine(line); int(b.Tier) < int(today.tier) {
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
	install := sampleSvcStatus
	install.Replaces = "pkg install"
	if notWeaker(install) == "" {
		t.Error("a read snippet replacing pkg install passed")
	}
	install.Tier = capability.Change
	if why := notWeaker(install); why != "" {
		t.Errorf("a change snippet replacing pkg install: %s", why)
	}
	none := sampleSvcList
	none.Replaces = "svc nosuchverb"
	if notWeaker(none) == "" {
		t.Error("a snippet replacing no command passed")
	}
	prune := production("docker-prune-preview")
	prune.Replaces = "docker prune"
	if notWeaker(prune) == "" {
		t.Error("a read snippet replacing docker prune (no --dry-run) passed")
	}
	refresh := production("pkg-security-refresh")
	refresh.Tier = capability.Read
	if notWeaker(refresh) == "" {
		t.Error("pkg-security-refresh at read tier passed: --refresh is a change")
	}
	prune = production("docker-prune-preview")
	prune.Tier = capability.Change
	if notWeaker(prune) == "" {
		t.Error("a preview at change tier passed: rule 3.8 makes it a read")
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

// likeTheCommand runs today's command and the snippet on the same replayed
// step and compares what they send, their result and their error.
func likeTheCommand(t *testing.T, step replayStep, command []string, snip []string) {
	t.Helper()
	type row struct {
		OK     bool            `json:"ok"`
		Data   json.RawMessage `json:"data"`
		Stdout *string         `json:"stdout"` // a raw row (logs): the text a log snippet splits into lines
		Error  *out.Error      `json:"error"`
	}
	run := func(args ...string) (string, string) {
		rs := startReplayServerWith(t, nil, step)
		got := captureOutput(t, func() error { return runRoot(t, append([]string{"-o", "json"}, args...)...) })
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if i := strings.Index(got, "{"); i >= 0 {
			_ = json.Unmarshal([]byte(got[i:]), &env)
		}
		rs.mu.Lock()
		defer rs.mu.Unlock()
		return strings.Join(rs.sent, "\n----\n"), string(env.Data)
	}
	wantSent, today := run(command...)
	gotSent, mine := run(append([]string{"recipe", "run"}, snip...)...)
	if gotSent != wantSent {
		t.Errorf("sent\n got:  %s\n want: %s", gotSent, wantSent)
	}
	var a struct{ Results []row }
	var b struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *out.Error      `json:"error"`
	}
	if err := json.Unmarshal([]byte(today), &a); err != nil || len(a.Results) != 1 {
		t.Fatalf("today: %v %s", err, today)
	}
	if err := json.Unmarshal([]byte(mine), &b); err != nil {
		t.Fatalf("snippet: %v %s", err, mine)
	}
	w := a.Results[0]
	if b.OK != w.OK || (b.Error == nil) != (w.Error == nil) || b.Error != nil && (b.Error.Code != w.Error.Code || b.Error.Message != w.Error.Message) {
		t.Fatalf("ok %v error %v, today ok %v error %v", b.OK, b.Error, w.OK, w.Error)
	}
	switch {
	case w.Stdout != nil && len(b.Result) == 0:
		if *w.Stdout != "" {
			t.Errorf("no lines, today's stdout %q", *w.Stdout)
		}
	case w.Stdout != nil:
		lb, _ := json.Marshal(logLines(snippet.Output{}, *w.Stdout))
		if g := compact(t, b.Result); g != string(lb) {
			t.Errorf("lines\n got:  %s\n want: %s", g, lb)
		}
	case len(w.Data) > 0 && string(w.Data) != "null":
		if g, want := compact(t, b.Result), compact(t, w.Data); g != want {
			t.Errorf("result\n got:  %s\n want: %s", g, want)
		}
	}
}

// docker-ps, docker-images and docker-stats fail as today's commands do:
// docker missing, no access to its socket, another docker error; and they
// sort as today.
func TestSnippetDockerLikeTheCommand(t *testing.T) {
	withSnippets(t, registered()...)
	steps := map[string]replayStep{
		"missing":    {exit: 127},
		"permission": {exit: 1, stderr: "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get ...: dial unix /var/run/docker.sock: connect: permission denied"},
		"error":      {exit: 1, stderr: "Error response from daemon: something broke"},
		// each sort key gives another order: Names api db web, Name x y z
		// (db api web), Repository and Tag alpine:3 shop:1 shop:2
		"unsorted": {stdout: `{"Names":"web","Name":"z","Repository":"shop","Tag":"2"}` + "\n" + `{"Names":"api","Name":"y","Repository":"shop","Tag":"1"}` + "\n" +
			`{"Names":"db","Name":"x","Repository":"alpine","Tag":"3"}` + "\n"},
	}
	for _, c := range [][]string{{"docker", "ps"}, {"docker", "images"}, {"docker", "stats"}} {
		for name, step := range steps {
			t.Run(strings.Join(c, "-")+"/"+name, func(t *testing.T) {
				likeTheCommand(t, step, append(slices.Clone(c), "dev"), []string{strings.Join(c, "-"), "dev"})
			})
		}
		// today's command shows a line that is not JSON as text; a snippet
		// has no shape for it and shows no text (design 5.1)
		t.Run(strings.Join(c, "-")+"/not json", func(t *testing.T) {
			startReplayServerWith(t, nil, replayStep{stdout: "WARNING: something\n" + `{"Names":"web"}` + "\n"})
			raw, e := snippetData(t, strings.Join(c, "-"), "dev")
			if e == nil || e.Code != "SNIPPET_PARSE_FAILED" || strings.Contains(string(raw), "WARNING") || strings.Contains(string(raw), `"result"`) {
				t.Fatalf("got %v %s, want SNIPPET_PARSE_FAILED and no text", e, raw)
			}
		})
		// recipe run has no --sudo: the hint names the command, which asks
		// as today, and never steers to the docker group (root on that
		// server)
		t.Run(strings.Join(c, "-")+"/permission hint", func(t *testing.T) {
			startReplayServerWith(t, nil, steps["permission"])
			_, e := snippetData(t, strings.Join(c, "-"), "dev")
			want := "the login user cannot use docker on this server; run `komando " + strings.Join(c, " ") + " TARGET --sudo` (the command, which asks as it does today), or ask the person whether this user should have docker access"
			if e == nil || e.Code != "DOCKER_PERMISSION" || e.Hint != want {
				t.Fatalf("got %+v, want DOCKER_PERMISSION with the hint %q (Audit A-455-1)", e, want)
			}
		})
		// a failed docker that printed text keeps today's error, not the text
		t.Run(strings.Join(c, "-")+"/failed with text", func(t *testing.T) {
			startReplayServerWith(t, nil, replayStep{exit: 1, stdout: "Cannot connect\n", stderr: "Error response from daemon: something broke"})
			raw, e := snippetData(t, strings.Join(c, "-"), "dev")
			if e == nil || e.Code != "DOCKER_ERROR" || strings.Contains(string(raw), "Cannot connect") {
				t.Fatalf("got %v %s, want DOCKER_ERROR and no text", e, raw)
			}
		})
	}
}

// docker-prune-preview sends today's preview script and gives today's
// per-host preview without host, ok and error, which its answer carries
// itself (decided by CLI-5 on C455).
func TestSnippetDockerPrunePreview(t *testing.T) {
	dir := filepath.Join("testdata", "snippets", "docker-prune-preview")
	in, err := os.ReadFile(filepath.Join(dir, "docker.in"))
	if err != nil {
		t.Fatal(err)
	}
	withSnippets(t, registered()...)
	rs := startReplayServerWith(t, nil, replayStep{stdout: string(in)})
	raw, e := snippetData(t, "docker-prune-preview", "dev")
	if e != nil {
		t.Fatal(e)
	}
	sent, err := os.ReadFile(filepath.Join(dir, "docker.sent.txt"))
	if err != nil {
		t.Fatal(err)
	}
	rs.mu.Lock()
	gotSent := strings.Join(rs.sent, "\n----\n") + "\n"
	rs.mu.Unlock()
	if gotSent != string(sent) {
		t.Errorf("sent\n got:  %s\n want: %s", gotSent, sent)
	}
	var golden struct {
		Data struct {
			Results []json.RawMessage `json:"results"`
		} `json:"data"`
	}
	gb, err := os.ReadFile(filepath.Join(dir, "docker.out.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(gb, &golden); err != nil || len(golden.Data.Results) != 1 {
		t.Fatalf("golden: %v", err)
	}
	var res struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	// the same keys as today's object, less the three the answer carries
	var today, mine map[string]any
	_ = json.Unmarshal(golden.Data.Results[0], &today)
	_ = json.Unmarshal(res.Result, &mine)
	for _, k := range []string{"host", "ok", "error"} {
		delete(today, k)
	}
	if g, w := slices.Sorted(maps.Keys(mine)), slices.Sorted(maps.Keys(today)); !slices.Equal(g, w) {
		t.Fatalf("keys %v, today's %v", g, w)
	}
	var want prunePreviewResult
	if err := json.Unmarshal(golden.Data.Results[0], &want); err != nil {
		t.Fatal(err)
	}
	var wb bytes.Buffer
	enc := json.NewEncoder(&wb)
	enc.SetEscapeHTML(false) // komando prints <none> as it is
	if err := enc.Encode(want); err != nil {
		t.Fatal(err)
	}
	if g, w := compact(t, res.Result), strings.TrimSpace(wb.String()); g != w {
		t.Errorf("result\n got:  %s\n want: %s", g, w)
	}
}

// A preview on a server without docker fails as today's preview does,
// and one without access to docker points to the command.
func TestSnippetDockerPrunePreviewFails(t *testing.T) {
	withSnippets(t, registered()...)
	startReplayServerWith(t, nil, replayStep{exit: 127})
	raw, e := snippetData(t, "docker-prune-preview", "dev")
	if want := dockerErr("", 127); e == nil || e.Code != want.Code || e.Message != "dev: "+want.Message || strings.Contains(string(raw), `"result"`) {
		t.Fatalf("got %v %s, want %s and no result", e, raw, want.Code)
	}
	startReplayServerWith(t, nil, replayStep{exit: 1, stderr: "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"})
	_, e = snippetData(t, "docker-prune-preview", "dev")
	want := "the login user cannot use docker on this server; run `komando docker prune TARGET --dry-run --sudo` (the command, which asks as it does today), or ask the person whether this user should have docker access"
	if e == nil || e.Code != "DOCKER_PERMISSION" || e.Hint != want {
		t.Fatalf("got %+v, want the hint %q", e, want)
	}
}

// logs and docker-logs send today's text and give today's lines in the
// log shape (design 2.1: {"lines": [{"text": ...}], "truncated": bool}).
func TestSnippetLogsGoldens(t *testing.T) {
	withSnippets(t, registered()...)
	for _, c := range []struct {
		name, family string
		vars         []string
	}{
		{"logs", "journal", []string{"unit=nginx", "limit=3"}},
		{"docker-logs", "docker", []string{"container=api", "limit=3"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join("testdata", "snippets", c.name)
			in, err := os.ReadFile(filepath.Join(dir, c.family+".in"))
			if err != nil {
				t.Fatal(err)
			}
			rs := startReplayServerWith(t, nil, replayStep{stdout: string(in)})
			args := []string{c.name, "dev"}
			for _, v := range c.vars {
				args = append(args, "--var", v)
			}
			raw, e := snippetData(t, args...)
			if e != nil {
				t.Fatal(e)
			}
			sent, err := os.ReadFile(filepath.Join(dir, c.family+".sent.txt"))
			if err != nil {
				t.Fatal(err)
			}
			rs.mu.Lock()
			got := strings.Join(rs.sent, "\n----\n") + "\n"
			rs.mu.Unlock()
			if got != string(sent) {
				t.Errorf("sent\n got:  %s\n want: %s", got, sent)
			}
			var golden struct {
				Data struct {
					Results []struct {
						Stdout string `json:"stdout"`
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
			want := logResult{Lines: []snippetLogLine{}}
			for _, l := range strings.Split(strings.TrimSuffix(golden.Data.Results[0].Stdout, "\n"), "\n") {
				want.Lines = append(want.Lines, snippetLogLine{Text: l})
			}
			wb, _ := json.Marshal(want)
			var res struct {
				Result json.RawMessage `json:"result"`
			}
			_ = json.Unmarshal(raw, &res)
			if g, w := compact(t, res.Result), string(wb); g != w {
				t.Errorf("result\n got:  %s\n want: %s", g, w)
			}
		})
	}
}

// logs fails as today's command does on the same server answer, and its
// permission hint points to the command, never to a group that reads every
// log (as A-455-1 for docker).
func TestSnippetLogsLikeTheCommand(t *testing.T) {
	withSnippets(t, registered()...)
	for name, step := range map[string]replayStep{
		"no systemd": {stdout: "#komando:no-systemd\n"},
		"permission": {stderr: "Hint: You are currently not seeing messages from other users and the system.\n      Users in groups 'adm', 'systemd-journal' can see all messages.\n      Pass -q to turn off this notice.\nNo journal files were opened due to insufficient permissions."},
		"no journal": {stderr: "No journal files were found.\n"},
		"empty":      {},
		"failed":     {exit: 1, stdout: "a line\n"},
	} {
		t.Run(name, func(t *testing.T) {
			likeTheCommand(t, step, []string{"logs", "dev", "--unit", "nginx"}, []string{"logs", "dev", "--var", "unit=nginx"})
		})
	}
	t.Run("permission hint", func(t *testing.T) {
		startReplayServerWith(t, nil, replayStep{stderr: "No journal files were opened due to insufficient permissions."})
		_, e := snippetData(t, "logs", "dev", "--var", "unit=nginx")
		want := "the login user cannot read the system journal; run `komando logs TARGET --unit UNIT --sudo` (the command, which asks as it does today), or ask the person whether this user should read the whole journal"
		if e == nil || e.Code != "JOURNAL_PERMISSION" || e.Hint != want {
			t.Fatalf("got %+v, want JOURNAL_PERMISSION with the hint %q (as Audit A-455-1)", e, want)
		}
	})
	t.Run("own entries only", func(t *testing.T) {
		startReplayServerWith(t, nil, replayStep{stdout: "a line\n", stderr: "Hint: You are currently not seeing messages from other users and the system."})
		raw, e := snippetData(t, "logs", "dev", "--var", "unit=nginx")
		var d struct {
			Warnings []string  `json:"warnings"`
			Result   logResult `json:"result"`
		}
		_ = json.Unmarshal(raw, &d)
		if e != nil || len(d.Warnings) != 1 || !strings.Contains(d.Warnings[0], "only your own journal entries") || len(d.Result.Lines) != 1 {
			t.Fatalf("got %v %s, want one line and the own-entries warning", e, raw)
		}
	})
	t.Run("docker-logs failed", func(t *testing.T) {
		likeTheCommand(t, replayStep{exit: 1, stdout: "Error: No such container: api\n"}, []string{"docker", "logs", "dev", "api"}, []string{"docker-logs", "dev", "--var", "container=api"})
	})
}

// A log cut at --max-output says so.
func TestSnippetLogsTruncated(t *testing.T) {
	withSnippets(t, registered()...)
	startReplayServerWith(t, nil, replayStep{stdout: strings.Repeat("a log line\n", 100)})
	raw, e := snippetData(t, "logs", "dev", "--var", "unit=nginx", "--max-output", "64B")
	var d struct {
		Result logResult `json:"result"`
	}
	_ = json.Unmarshal(raw, &d)
	if e != nil || !d.Result.Truncated {
		t.Fatalf("got %v %s, want truncated", e, raw)
	}
}

// The values logs and docker-logs take: today's container names, a
// systemd unit, and a count.
func TestSnippetLogsValues(t *testing.T) {
	withSnippets(t, registered()...)
	for _, args := range [][]string{
		{"logs", "dev", "--var", "unit=nginx", "--var", "limit=-1"},
		{"logs", "dev", "--var", "unit=nginx", "--var", "limit=3;reboot"},
		{"logs", "dev", "--var", "unit=-x"},
		{"logs", "dev", "--var", "unit=a b"},
		{"logs", "dev"},
		{"docker-logs", "dev", "--var", "container=-it"},
		{"docker-logs", "dev", "--var", "container=a/b"},
		{"docker-logs", "dev"},
	} {
		rs := startReplayServerWith(t, nil, replayStep{stdout: "x\n"})
		if _, e := snippetData(t, args...); e == nil || e.Exit != out.ExitUsage {
			t.Errorf("%q: %v, want a usage refusal", args, e)
		}
		rs.mu.Lock()
		if len(rs.execs) != 0 {
			t.Errorf("%q ran %q", args, rs.execs)
		}
		rs.mu.Unlock()
	}
}

// pkg-security and pkg-security-refresh run today's script cut before its
// apply branch, and give today's row without host, ok and the apply fields.
func TestSnippetPkgSecurity(t *testing.T) {
	withSnippets(t, registered()...)
	for _, c := range []struct{ name, family string }{
		{"pkg-security", "apt"}, {"pkg-security-refresh", "apt"},
	} {
		t.Run(c.name+"/"+c.family, func(t *testing.T) {
			dir := filepath.Join("testdata", "snippets", c.name)
			in, err := os.ReadFile(filepath.Join(dir, c.family+".in"))
			if err != nil {
				t.Fatal(err)
			}
			step := replayStep{stdout: string(in)}
			if e, err := os.ReadFile(filepath.Join(dir, c.family+".err")); err == nil {
				step.stderr = string(e)
			}
			rs := startReplayServerWith(t, nil, step)
			raw, _ := snippetData(t, c.name, "dev")
			var golden struct {
				Data struct {
					Results []json.RawMessage `json:"results"`
				} `json:"data"`
			}
			gb, err := os.ReadFile(filepath.Join(dir, c.family+".out.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(gb, &golden); err != nil || len(golden.Data.Results) != 1 {
				t.Fatalf("golden: %v", err)
			}
			var today map[string]any
			_ = json.Unmarshal(golden.Data.Results[0], &today)
			var d struct {
				OK     bool            `json:"ok"`
				Result json.RawMessage `json:"result"`
				Error  *out.Error      `json:"error"`
			}
			_ = json.Unmarshal(raw, &d)
			if d.OK != (today["ok"] == true) {
				t.Fatalf("ok %v, today %v: %s", d.OK, today["ok"], raw)
			}
			if te, _ := today["error"].(map[string]any); te != nil {
				if d.Error == nil || d.Error.Code != te["code"] || d.Error.Message != te["message"] {
					t.Fatalf("error %v, today %v", d.Error, te)
				}
			} else {
				var mine map[string]any
				_ = json.Unmarshal(d.Result, &mine)
				for _, k := range []string{"host", "ok", "error", "stderr", "duration_ms"} {
					delete(today, k)
				}
				if g, w := slices.Sorted(maps.Keys(mine)), slices.Sorted(maps.Keys(today)); !slices.Equal(g, w) {
					t.Fatalf("keys %v, today's %v", g, w)
				}
				var want pkgSecResult
				if err := json.Unmarshal(golden.Data.Results[0], &want); err != nil {
					t.Fatal(err)
				}
				var wb bytes.Buffer
				enc := json.NewEncoder(&wb)
				enc.SetEscapeHTML(false)
				_ = enc.Encode(want)
				if g, w := compact(t, d.Result), strings.TrimSpace(wb.String()); g != w {
					t.Errorf("result\n got:  %s\n want: %s", g, w)
				}
			}
			rs.mu.Lock()
			sent := strings.Join(rs.sent, "\n")
			rs.mu.Unlock()
			if !strings.HasPrefix(sent, "sudo -n sh -c ") || strings.Contains(sent, "only-upgrade -o DPkg") || strings.Contains(sent, "rmdir") {
				t.Errorf("sent the apply branch or without sudo:\n%s", sent)
			}
			refresh := map[bool]string{true: "REFRESH=1", false: "REFRESH=0"}[c.name == "pkg-security-refresh"]
			if !strings.HasPrefix(sent, "sudo -n sh -c 'ACTION=list "+refresh+" ") {
				t.Errorf("sent without %s:\n%.80s", refresh, sent)
			}
		})
	}
}

// The list script is today's script up to its apply branch, which it ends.
func TestPkgSecListScriptIsTodaysUpToApply(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		today, mine := pkgSecScript(false, refresh, true), pkgSecListScript(refresh)
		cut := strings.TrimSuffix(mine, "exit 0\n")
		if !strings.HasPrefix(today, cut) || cut == mine || !strings.HasPrefix(today[len(cut):], pkgSecApplyLine) {
			t.Errorf("refresh=%v: the list script is not today's script cut at its apply line", refresh)
		}
		if hits := policy.Check(mine, nil); len(hits) > 0 {
			t.Errorf("refresh=%v: the list script hits %v", refresh, hits)
		}
	}
}

// An unknown package manager is an error the app reads, not a skipped host.
func TestSnippetPkgSecurityUnsupported(t *testing.T) {
	withSnippets(t, registered()...)
	startReplayServerWith(t, nil, replayStep{stdout: "#komando:unsupported\nportage\n"})
	_, e := snippetData(t, "pkg-security", "dev")
	if e == nil || e.Code != "SECURITY_UNSUPPORTED" {
		t.Fatalf("got %v, want SECURITY_UNSUPPORTED", e)
	}
}

// pkg-security fails as today's command does, and warns as it does when
// the updates would remove a package the server needs.
func TestSnippetPkgSecurityFailsAndWarns(t *testing.T) {
	withSnippets(t, registered()...)
	startReplayServerWith(t, nil, replayStep{exit: 1, stderr: "E: the package lists are broken"})
	if _, e := snippetData(t, "pkg-security", "dev"); e == nil || e.Code != "PKG_FAILED" {
		t.Fatalf("got %v, want PKG_FAILED", e)
	}
	in, err := os.ReadFile(filepath.Join("testdata", "snippets", "pkg-security", "apt.in"))
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(in), "#komando:removes")
	if i < 0 {
		t.Fatal("no removes section in the S0 input")
	}
	startReplayServerWith(t, nil, replayStep{stdout: string(in[:i]) + "#komando:removes\nlibc6\n"})
	raw, e := snippetData(t, "pkg-security", "dev")
	var d struct {
		Result pkgSecResult `json:"result"`
	}
	_ = json.Unmarshal(raw, &d)
	if e != nil || len(d.Result.Warnings) != 1 || !strings.Contains(d.Result.Warnings[0], "libc6") || !slices.Contains(d.Result.WouldRemove, "libc6") {
		t.Fatalf("got %v %s, want the libc6 warning", e, raw)
	}
}

// pkg-upgradable warns as today when the package index is old.
func TestSnippetPkgUpgradableStaleIndex(t *testing.T) {
	withSnippets(t, registered()...)
	startReplayServerWith(t, nil, replayStep{stderr: "# package-manager: apt\n# index-age: 259200\n"})
	raw, e := snippetData(t, "pkg-upgradable", "dev")
	var d struct {
		Warnings []string `json:"warnings"`
	}
	_ = json.Unmarshal(raw, &d)
	if e != nil || len(d.Warnings) != 1 {
		t.Fatalf("got %v %s, want today's stale index warning", e, raw)
	}
}

// Every built-in whose text raises itself with sudo refuses --no-sudo
// (Audit A-457-1), and the list of them is the one a person reads here:
// adding a built-in that elevates itself changes it on purpose.
func TestBuiltinsThatRaiseThemselvesRefuseNoSudo(t *testing.T) {
	var self []string
	for _, name := range builtinSnippets.Names() {
		b, _ := builtinSnippets.Lookup(name)
		if b.Run != nil || !snippet.SelfElevates(b) {
			continue
		}
		self = append(self, name)
		err := runSnippet(tcl, context.Background(), b, "nobody", nil, true)
		if e, ok := err.(*out.Error); !ok || e.Code != "USAGE" || !strings.Contains(e.Message, name) {
			t.Errorf("%s --no-sudo: %v, want a usage error naming the snippet", name, err)
		}
	}
	// facts reads with `sudo -n` (S in its script) when passwordless sudo works;
	// pkg-upgradable raises itself with `exec sudo -n sh -c`. The package
	// security reads use the runner's sudo (Builtin.Sudo), which --no-sudo drops.
	want := []string{"facts", "pkg-upgradable"}
	if !slices.Equal(self, want) {
		t.Errorf("built-ins whose text raises itself: %v, want %v", self, want)
	}
}
