package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

func TestClassifyDockerGlobalFlags(t *testing.T) {
	for cmd, want := range map[string]driver.Risk{
		"-l debug rm x":                         driver.RiskDestructive,
		"--log-level=debug rm x":                driver.RiskDestructive,
		"--host unix:///x.sock rm -f x":         driver.RiskDestructive,
		"-H tcp://h:2375 ps":                    driver.RiskRead,
		"--context other volume rm data":        driver.RiskDestructive,
		"--tls --tlsverify ps":                  driver.RiskRead,
		"compose -p proj down -v":               driver.RiskDestructive,
		"compose --project-name=p down":         driver.RiskWrite,
		"compose -f a.yml --env-file e down":    driver.RiskWrite,
		"compose -f a.yml rm -f":                driver.RiskDestructive,
		"compose ps":                            driver.RiskRead,
		"compose -p p logs --tail 5":            driver.RiskRead,
		"compose up -d":                         driver.RiskWrite,
		"--weird value rm x":                    driver.RiskDestructive, // unknown leading flag: assume the worst
		"run -d nginx":                          driver.RiskWrite,
		"run --pid=host alpine":                 driver.RiskDestructive,
		"run -v /:/host alpine":                 driver.RiskDestructive,
		"run -v /var/run/docker.sock:/s alpine": driver.RiskDestructive,
		"container run -d nginx":                driver.RiskWrite,
		"container exec c sh":                   driver.RiskDestructive,
		"exec c ls":                             driver.RiskDestructive,
		"logs web":                              driver.RiskRead,
		"service logs web":                      driver.RiskRead,
	} {
		if got := classifyDocker(strings.Fields(cmd)); got != want {
			t.Errorf("docker %s: %v, want %v", cmd, got, want)
		}
	}
}

func TestDockerVerbArgs(t *testing.T) {
	for in, want := range map[string]string{
		"-l debug rm x":                 "rm x",
		"--host=unix:///s compose ps":   "compose ps",
		"compose -p p -f f.yml down -v": "compose down -v",
		"ps -a":                         "ps -a",
	} {
		got, err := dockerVerbArgs(strings.Fields(in))
		if err != nil || strings.Join(got, " ") != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"--weird x rm y", "-l", "compose --nope down"} {
		if _, err := dockerVerbArgs(strings.Fields(bad)); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestDockerExecLine(t *testing.T) {
	got := dockerExecLine("api", []string{"sh", "-c", "echo out; exit 3"})
	if got != `docker exec -i 'api' 'sh' '-c' 'echo out; exit 3'` {
		t.Errorf("exec line: %s", got)
	}
}

func TestDockerErr(t *testing.T) {
	for msg, exit := range map[string]int{
		"[]\nError: No such object: nope":                        out.ExitNotFound,
		"Error response from daemon: No such container: x":       out.ExitNotFound,
		"Error: no such service: web":                            out.ExitNotFound,
		"service web not found":                                  out.ExitNotFound,
		"Error response from daemon: conflict: unable to remove": out.ExitRemote,
	} {
		e := dockerErr(msg, 1)
		if e.Exit != exit || e.Message == "" || strings.HasPrefix(e.Message, "[]") {
			t.Errorf("%q: exit %d message %q", msg, e.Exit, e.Message)
		}
	}
	if e := dockerErr("", 2); e.Message == "" {
		t.Error("an empty docker error still needs a message")
	}
	body, code := splitExitMarker("[{\"Id\":\"x\"}]\nkomando-exit:0\n")
	if code != 0 || body != `[{"Id":"x"}]` {
		t.Errorf("marker: %q %d", body, code)
	}
	if _, code := splitExitMarker("[]\nkomando-exit:1"); code != 1 {
		t.Errorf("marker exit %d", code)
	}
}

func TestLimitValue(t *testing.T) {
	n := 0
	v := &limitValue{&n}
	if err := v.Set("5"); err != nil || n != 5 {
		t.Errorf("--limit 5: %v %d", err, n)
	}
	if err := v.Set("shop"); err == nil || !strings.Contains(err.Error(), "--namespace shop") {
		t.Errorf("--limit shop must point at --namespace: %v", err)
	}
}

// C-S01: -n is --namespace on every cluster command that has one; a
// number given as -n (the old count) is refused,
// and --namespace=N still names a namespace N.
func TestClusterDashN(t *testing.T) {
	root := newRoot(tcl)
	n := 0
	for _, c := range allCommands(root) {
		ns := c.Flags().Lookup("namespace")
		if ns == nil || !strings.HasPrefix(c.CommandPath(), "komando cluster ") {
			continue
		}
		n++
		if ns.Shorthand != "n" {
			t.Errorf("%s: --namespace has no -n", c.CommandPath())
		}
		if l := c.Flags().Lookup("limit"); l != nil && l.Shorthand != "" {
			t.Errorf("%s: --limit has -%s", c.CommandPath(), l.Shorthand)
		}
		if h := c.LocalFlags().FlagUsages(); !strings.Contains(h, "-n, --namespace") { // derived sets do not panic, and show it
			t.Errorf("%s help: %s", c.CommandPath(), h)
		}
		for _, args := range [][]string{{"-n", "shop"}, {"-nshop"}, {"-n=shop"}, {"--namespace", "50"}, {"--namespace=50"}, {"-An", "x"}} {
			var got string
			cmd := clusterParse(t, c.CommandPath(), args)
			if cmd == nil {
				continue // -A on a command without it
			}
			got, _ = cmd.Flags().GetString("namespace")
			if want := map[string]string{"-n": "shop", "-nshop": "shop", "-n=shop": "shop", "--namespace": "50", "--namespace=50": "50", "-An": "x"}[args[0]]; got != want {
				t.Errorf("%s %v: namespace %q, want %q", c.CommandPath(), args, got, want)
			}
		}
		for _, args := range [][]string{{"-n", "50"}, {"-n50"}, {"-n=7"}} {
			cmd := newRoot(treeCall())
			found, _, _ := cmd.Find(strings.Fields(strings.TrimPrefix(c.CommandPath(), "komando ")))
			if err := found.ParseFlags(args); err == nil || !strings.Contains(err.Error(), "is a count, but") {
				t.Errorf("%s %v: %v", c.CommandPath(), args, err)
			}
		}
	}
	if n != 3 { // kubernetes exec, shell and tunnel start
		t.Errorf("%d cluster commands have --namespace, want 3", n)
	}
	invHome(t)
	e := mainErr(t, "cluster", "kubernetes", "exec", "x1", "api", "-n", "50")
	if e.Code != "USAGE" || e.Exit != 2 || e.Message != "-n: 50 is a count, but -n is --namespace in cluster commands" ||
		e.Hint != "`--limit 50`, or `--namespace=50` for a namespace named 50" {
		t.Errorf("cluster kubernetes exec -n 50: %+v", e)
	}
}

// clusterParse parses args for the command at path in a fresh tree; nil
// when the command has no flag args need.
func clusterParse(t *testing.T, path string, args []string) *cobra.Command {
	t.Helper()
	found, _, _ := newRoot(treeCall()).Find(strings.Fields(strings.TrimPrefix(path, "komando ")))
	if strings.HasPrefix(args[0], "-A") && found.Flags().Lookup("all-namespaces") == nil {
		return nil
	}
	if err := found.ParseFlags(args); err != nil {
		t.Errorf("%s %v: %v", path, args, err)
		return nil
	}
	return found
}

func TestDiffObjectSecret(t *testing.T) {
	before := []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","resourceVersion":"1"},"data":{"a":"b25l","b":"eA=="}}`)
	after := []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","resourceVersion":"2"},"data":{"a":"dHdv","b":"eA==","c":"eQ=="}}`)
	c := diffObject(tcl, "secret/s", before, after)
	if c.Action != "change" {
		t.Fatalf("a changed Secret value is a change, got %s", c.Action)
	}
	if strings.Contains(c.Diff, "dHdv") || strings.Contains(c.Diff, "b25l") || !strings.Contains(c.Diff, "+  a: '[hidden, changed]'") || !strings.Contains(c.Diff, "+  c: '[hidden, new]'") {
		t.Errorf("diff:\n%s", c.Diff)
	}
	if c := diffObject(tcl, "secret/s", before, before); c.Action != "none" {
		t.Errorf("same values: %s", c.Action)
	}
	d := diffObject(tcl, "deployment/d", []byte(`{"kind":"Deployment","spec":{"template":{"spec":{"x":1}}}}`), []byte(`{"kind":"Deployment","spec":{"template":{"spec":{"x":2}}}}`))
	if !strings.Contains(d.Diff, "\n-      x: 1") {
		t.Errorf("diff uses 2-space YAML:\n%s", d.Diff)
	}
}

func TestKubeErr(t *testing.T) {
	for _, c := range []struct {
		err  error
		exit int
	}{
		{&kube.APIError{Code: 404, Reason: "NotFound", Message: `deployments.apps "x" not found`}, out.ExitNotFound},
		{wrapErr("deployment/x", &kube.APIError{Code: 404, Reason: "NotFound", Message: `namespaces "t" not found`}), out.ExitNotFound},
		{&kube.APIError{Code: 400, Reason: "BadRequest", Message: "container nope is not valid for pod p"}, out.ExitNotFound},
		{&kube.APIError{Code: 400, Reason: "BadRequest", Message: "unable to parse requirement"}, out.ExitUsage},
		{&kube.APIError{Code: 403, Reason: "Forbidden"}, out.ExitConnect},
	} {
		e := toErr(kubeErr(c.err))
		if e.Exit != c.exit || e.Message == "" {
			t.Errorf("%v: exit %d %q", c.err, e.Exit, e.Message)
		}
	}
	if e := toErr(kubeErr(wrapErr("deployment/x", &kube.APIError{Code: 404, Message: "gone"}))); !strings.HasPrefix(e.Message, "deployment/x: ") {
		t.Errorf("a wrapped error keeps its object: %q", e.Message)
	}
}

type wrapped struct {
	pre string
	err error
}

func (w wrapped) Error() string { return w.pre + ": " + w.err.Error() }
func (w wrapped) Unwrap() error { return w.err }

func wrapErr(pre string, err error) error { return wrapped{pre, err} }

func TestKubectlFailure(t *testing.T) {
	if f := kubectlFailure(0, ""); f != nil {
		t.Error("exit 0 is no failure")
	}
	if f := kubectlFailure(1, "Error from server (NotFound): pods \"x\" not found\n"); f.Exit != out.ExitNotFound || f.Message != `pods "x" not found` {
		t.Errorf("not found: %+v", f)
	}
	if f := kubectlFailure(3, "command terminated with exit code 3\n"); f.Exit != out.ExitRemote {
		t.Errorf("remote: %+v", f)
	}
}

func TestKindSuggestion(t *testing.T) {
	if got := kube.Nearest("deploymnt", []string{"deployments", "deployment", "deploy", "pods", "daemonset"}); got != "deployment" {
		t.Errorf("nearest %q", got)
	}
	if got := kube.Nearest("zzzzzz", []string{"pods", "nodes"}); got != "" {
		t.Errorf("nothing close: %q", got)
	}
}

func TestApplyDataJSON(t *testing.T) {
	a := applyData{Conn: "k", DryRun: true, Objects: []objectChange{{Object: "deployment/web", Action: "create"}}}
	b, _ := a.MarshalJSON()
	if !strings.Contains(string(b), `"would_apply":["deployment/web"]`) || strings.Contains(string(b), `"applied"`) {
		t.Errorf("dry run: %s", b)
	}
	a.DryRun = false
	a.Objects[0].Action = "created"
	b, _ = a.MarshalJSON()
	if !strings.Contains(string(b), `"applied":["deployment/web"]`) || !strings.Contains(string(b), `"action":"created"`) {
		t.Errorf("apply: %s", b)
	}
	if txt := a.Text(); txt != "deployment/web created\n" {
		t.Errorf("text %q", txt)
	}
}
