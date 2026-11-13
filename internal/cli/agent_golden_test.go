package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// Agents and scripts see no change when a person at a terminal is asked
// for what a command misses: for every command typed with too few
// arguments, what an AI agent or a script gets (stdout, stderr and the exit
// code, in JSON and in text) is the same, byte for byte, as recorded in
// testdata/agent_golden.txt. The test never runs at a terminal, so nothing
// may be asked. KOMANDO_GOLDEN_UPDATE=1 records it again (only on purpose).
func TestAgentGolden(t *testing.T) {
	if testing.Short() || raceOn { // the same bytes with or without the race detector, which makes it slow
		t.Skip("runs every command")
	}
	unixOnly(t, "the recording is made on Unix: local paths and doctor's platform notes differ on Windows")
	var b strings.Builder
	variants := []struct {
		name  string
		agent bool
		out   string
	}{{"agent json", true, "json"}, {"agent text", true, "text"}, {"script json", false, "json"}, {"script text", false, "text"}}
	for _, args := range goldenCases(t) {
		for _, v := range variants {
			full := append([]string{"-o", v.out}, args...)
			stdout, stderr, code := goldenRun(t, v.agent, full)
			fmt.Fprintf(&b, "### komando %s (%s)\nexit %d\n--- stdout\n%s--- stderr\n%s", strings.Join(full, " "), v.name, code, stdout, stderr)
		}
	}
	// the safety stops, in a home with servers and conns (goldenGates)
	for _, args := range goldenGates {
		for _, v := range variants {
			full := append([]string{"-o", v.out}, args...)
			stdout, stderr, code := goldenRunWith(t, v.agent, full, goldenGateSetup)
			fmt.Fprintf(&b, "### komando %s (%s, gate inventory)\nexit %d\n--- stdout\n%s--- stderr\n%s", strings.Join(full, " "), v.name, code, stdout, stderr)
		}
	}
	// the exit and error code changes of the release notes (changes.md
	// 11b) that need servers or conns to show, in the same home
	for _, args := range goldenNotes {
		for _, v := range variants {
			full := append([]string{"-o", v.out}, args...)
			stdout, stderr, code := goldenRunWith(t, v.agent, full, goldenGateSetup)
			fmt.Fprintf(&b, "### komando %s (%s, release note)\nexit %d\n--- stdout\n%s--- stderr\n%s", strings.Join(full, " "), v.name, code, stdout, stderr)
		}
	}
	// the ssh-gate code changes of the release notes (changes.md 11b, C-C08):
	// what a read-only key gets for the command it sent. Each is refused, so
	// nothing runs; a key's command that got through would fail here
	savedExec := gateExec
	gateExec = func(string, []string, []string) error { return errors.New("a read-only key's command ran") }
	for _, line := range goldenGateKeys {
		t.Setenv("SSH_ORIGINAL_COMMAND", line)
		for _, v := range variants {
			full := []string{"-o", v.out, "ssh-gate", "--name", "phone-read", "--read-only"}
			stdout, stderr, code := goldenRunWith(t, v.agent, full, gateInventory)
			fmt.Fprintf(&b, "### komando %s, SSH_ORIGINAL_COMMAND='%s' (%s, read-only key)\nexit %d\n--- stdout\n%s--- stderr\n%s", strings.Join(full, " "), line, v.name, code, stdout, stderr)
		}
	}
	t.Setenv("SSH_ORIGINAL_COMMAND", "")
	gateExec = savedExec
	// the schema values of the release notes (changes.md 11a): kind,
	// approvals and each flag's type, shorthand and default, without the
	// help text, which the cases above already pin
	for _, path := range goldenSchema {
		stdout, _, code := goldenRun(t, false, append([]string{"-o", "json", "schema"}, path...))
		fmt.Fprintf(&b, "### komando schema %s (schema values)\nexit %d\n%s", strings.Join(path, " "), code, schemaValues(t, stdout))
	}
	got := b.String()
	file := filepath.Join("testdata", "agent_golden.txt")
	if os.Getenv("KOMANDO_GOLDEN_UPDATE") == "1" {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := range min(len(gl), len(wl)) {
			if gl[i] != wl[i] {
				head := ""
				for j := i; j >= 0; j-- {
					if strings.HasPrefix(gl[j], "### ") {
						head = gl[j]
						break
					}
				}
				t.Fatalf("what an agent or a script sees changed\n%s\nline %d\n got: %s\nwant: %s", head, i+1, gl[i], wl[i])
			}
		}
		t.Fatalf("what an agent or a script sees changed: %d lines, want %d", len(gl), len(wl))
	}
}

// goldenCases are the command lines that miss an argument: every command
// typed alone and with one argument too few, where its argument rule
// refuses that (so nothing runs), and the add commands alone.
func goldenCases(t *testing.T) [][]string {
	t.Helper()
	cases := [][]string{{}} // komando alone
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if !s.Runnable() || s.Hidden || s.Name() == "help" || strings.HasPrefix(s.Name(), "__") {
				continue
			}
			path := strings.Fields(commandKey(s))
			if slices.Contains([]string{"host add", "conn add", "vpn add"}, commandKey(s)) || formFamilyAdd[commandKey(s)] != "" {
				cases = append(cases, path)
				continue
			}
			if s.Args == nil {
				continue
			}
			ok := -1 // the fewest arguments its rule takes
			for n := range 5 {
				if s.Args(s, slices.Repeat([]string{"x1"}, n)) == nil {
					ok = n
					break
				}
			}
			if ok <= 0 {
				continue
			}
			cases = append(cases, path)
			if ok > 1 {
				cases = append(cases, append(slices.Clone(path), slices.Repeat([]string{"x1"}, ok-1)...))
			}
		}
	}
	walk(newRoot())
	if len(cases) < 150 {
		t.Fatalf("only %d cases", len(cases))
	}
	return append(cases, goldenExtra...)
}

// goldenExtra are command lines whose exit code changed on purpose
// (release note, changes.md 11b), recorded so they stay as decided.
var goldenExtra = [][]string{
	// C-S02: words for the other program only after -- (USAGE, exit 2)
	{"exec", "x1", "apt-get", "install", "-y", "nginx"},
	{"exec", "x1", "uptime", "--dry-run"},
	{"exec", "x1", "stray", "--", "uptime"},
	{"job", "start", "x1", "uptime"},
	{"docker", "exec", "x1", "x2", "id"},
	{"docker", "compose", "x1", "ps"},
	{"docker", "raw", "x1", "ps"},
	{"cluster", "exec", "x1", "x2", "id"},
	{"cluster", "shell", "x1", "x2", "sh"},
	{"cluster", "run", "x1", "get", "pods"},
	{"cache", "run", "x1", "GET", "k"},
	// C-F02: two KEY=VALUE pairs in one value (USAGE, exit 2)
	{"conn", "add", "x1", "postgres://u@10.0.0.9/app", "--option", "a=on,b=x"},
	{"host", "add", "x1", "u@10.0.0.1", "--env", "A=1,B=2"},
	// C-S01: -n is --namespace in cluster; a count there is refused (USAGE, exit 2)
	{"cluster", "ls", "x1", "pods", "-n", "50"},
	{"cluster", "events", "x1", "-n", "50"},
	{"cluster", "logs", "x1", "x2", "-n", "50"},
	// C-F03: storage rm -n is --max-remove for one release (noted), then USAGE
	{"storage", "rm", "x1", "--prefix", "a/", "-n", "10", "--dry-run"},
}

// goldenGateKeys are the command lines a read-only ssh-gate key sends
// whose answer changed (changes.md 11b): SSH_GATE_READ_ONLY, exit 6.
var goldenGateKeys = []string{
	"komando storage link s3 report.pdf",
	"komando cluster forward k8s svc/web 8080",
}

// goldenSchema are commands whose schema values the release notes list
// (changes.md 11a), one or more per row.
var goldenSchema = [][]string{
	{"storage", "link"}, {"cluster", "forward"}, // C-C08: kind read -> change
	{"host", "add"}, {"conn", "add"}, // C-F02: --env, --option stringArray
	{"cache", "set"}, {"cert", "check"}, {"registry", "prune"}, // C-F04: duration
	{"cluster", "logs"},              // C-F05, C-S01
	{"cache", "get"}, {"fs", "list"}, // C-F08: --limit int
	{"fs", "cat"}, {"exec"}, // C-F09: bytes
	{"queue", "create"},                                            // C-F22: no -1 default
	{"cluster", "events"}, {"cluster", "list"}, {"cluster", "get"}, // C-S01: -n
}

// schemaValues is one line per command of a schema answer, then one per
// flag: what an agent branches on, not what it reads to a person.
func schemaValues(t *testing.T, stdout string) string {
	t.Helper()
	var d struct {
		Data struct {
			Commands []struct {
				Path    string           `json:"path"`
				Kind    string           `json:"kind"`
				Confirm any              `json:"confirm"`
				Flags   []map[string]any `json:"flags"`
			} `json:"commands"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &d); err != nil {
		t.Fatalf("schema: %v: %s", err, stdout)
	}
	var b strings.Builder
	for _, c := range d.Data.Commands {
		conf, _ := json.Marshal(c.Confirm)
		fmt.Fprintf(&b, "%s kind=%s confirm=%s\n", c.Path, c.Kind, conf)
		for _, f := range c.Flags {
			fmt.Fprintf(&b, "  --%v", f["name"])
			for _, k := range []string{"shorthand", "type", "default", "default_from"} {
				if v, ok := f[k]; ok {
					fmt.Fprintf(&b, " %s=%v", k, v)
				}
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// goldenNoise is what differs between runs and machines, not between
// versions of komando: the home folder, times.
var goldenNoise = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`"(duration_ms|elapsed_ms|took_ms)":\d+`), `"$1":0`},
	{regexp.MustCompile(`"version":"[^"]*"`), `"version":"V"`},
}

// goldenRun runs komando in this process as an agent or a script would,
// stdin, stdout and stderr not terminals, and gives what it printed.
func goldenRun(t *testing.T, agent bool, args []string) (string, string, int) {
	t.Helper()
	return goldenRunWith(t, agent, args, nil)
}

// goldenRunWith is goldenRun in a home that setup filled first.
func goldenRunWith(t *testing.T, agent bool, args []string, setup func(*testing.T)) (string, string, int) {
	t.Helper()
	invHome(t)
	if setup != nil {
		setup(t)
	}
	if agent {
		t.Setenv("KOMANDO_AGENT", "1")
		resetApproval()
	} else {
		noAgent(t)
	}
	home := os.Getenv("KOMANDO_HOME")
	savedArgs, savedOut, savedErr, savedIn := os.Args, os.Stdout, os.Stderr, os.Stdin
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	inR, inW, _ := os.Pipe()
	inW.Close()
	os.Args, os.Stdout, os.Stderr, os.Stdin = append([]string{"komando"}, args...), outW, errW, inR
	got := make(chan [2]string)
	go func() {
		var o, e bytes.Buffer
		done := make(chan bool)
		go func() { _, _ = io.Copy(&e, errR); done <- true }()
		_, _ = io.Copy(&o, outR)
		<-done
		got <- [2]string{o.String(), e.String()}
	}()
	out.P.W = outW
	code := executeArgs(args)
	os.Args, os.Stdout, os.Stderr, os.Stdin = savedArgs, savedOut, savedErr, savedIn
	out.P.W = savedOut
	outW.Close()
	errW.Close()
	inR.Close()
	r := <-got
	for i := range r {
		r[i] = strings.ReplaceAll(r[i], home, "$KOMANDO_HOME")
		for _, n := range goldenNoise {
			r[i] = n.re.ReplaceAllString(r[i], n.with)
		}
	}
	return r[0], r[1], code
}

// In a real terminal too, an AI agent is never asked: a sample of commands
// missing arguments ends as the recording says, with its error on the
// screen and no question.
func TestAgentGoldenPTY(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	rec, err := os.ReadFile(filepath.Join("testdata", "agent_golden.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"logs"}, {"db", "query"}, {"host", "show"}, {"exec"}, {"host", "add"}, {"db", "add"}, {"fs", "replace"}} {
		head := "### komando -o text " + strings.Join(args, " ") + " (agent text)\n"
		i := strings.Index(string(rec), head)
		if i < 0 {
			t.Fatalf("no recording for %v", args)
		}
		block := strings.SplitN(string(rec)[i+len(head):], "\n### ", 2)[0]
		var code int
		fmt.Sscanf(block, "exit %d", &code)
		msg := strings.TrimSpace(strings.SplitN(strings.SplitN(block, "--- stderr\n", 2)[1], "\n", 2)[0])
		invHome(t)
		mustRun(t, "host", "add", "web1", "root@10.0.0.5")
		p := startPTYEnv(t, []string{"KOMANDO_PTY_AS=agent"}, args...)
		if got := p.exit(); got != code || !strings.Contains(p.shown(), msg) || strings.Contains(p.shown(), "$ komando") {
			t.Errorf("%v: exit %d, want %d and %q; the screen:\n%s", args, got, code, msg, p.shown())
		}
	}
}
