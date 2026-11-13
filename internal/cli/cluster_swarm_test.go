package cli

import (
	"github.com/spf13/cobra"
	"strconv"
	"strings"
	"testing"

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

func TestSwarmErr(t *testing.T) {
	for stderr, want := range map[string]string{
		"komando: docker not found":     "direct is not a Swarm manager (docker not found)",
		"komando: swarm worker":         "direct is a Swarm worker, not a manager",
		"komando: swarm inactive false": "direct is not a Swarm manager (swarm inactive)",
		"Error: No such service: nope":  "No such service: nope",
		"":                              "docker exited 1",
	} {
		e := swarmErr("direct", stderr, "", 1)
		if e.Message != want {
			t.Errorf("%q: %q, want %q", stderr, e.Message, want)
		}
	}
	if e := swarmErr("m", "Error: No such service: nope", "", 1); e.Exit != out.ExitNotFound {
		t.Errorf("a missing service is not found (3), got %d", e.Exit)
	}
}

func TestObjectRef(t *testing.T) {
	for in, want := range map[string]string{
		"deployment/api":      "deployment api",
		"deployment api":      "deployment api",
		"deployment.apps/api": "deployment.apps api",
		"svc web":             "svc web",
	} {
		typ, name, err := objectRef(strings.Fields(in))
		if err != nil || typ+" "+name != want {
			t.Errorf("%q: %q %q %v", in, typ, name, err)
		}
	}
	for _, bad := range []string{"deployment", "deployment/api web", "/api", "a/b/c"} {
		if _, _, err := objectRef(strings.Fields(bad)); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestSwarmKind(t *testing.T) {
	for in, want := range map[string]string{"svc": "service", "services": "service", "task": "task", "tasks": "task",
		"pods": "task", "nodes": "node", "stack": "stack", "deployment": ""} {
		if got := swarmKind(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
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
// number given as -n (the old count on events, logs, ls) is refused,
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
			cmd := newRoot(tcl)
			found, _, _ := cmd.Find(strings.Fields(strings.TrimPrefix(c.CommandPath(), "komando ")))
			if err := found.ParseFlags(args); err == nil || !strings.Contains(err.Error(), "is a count, but") {
				t.Errorf("%s %v: %v", c.CommandPath(), args, err)
			}
		}
	}
	if n != 21 { // 20, and the hidden `cluster info` synonym of cluster status
		t.Errorf("%d cluster commands have --namespace, want 21", n)
	}
	invHome(t)
	e := mainErr(t, "cluster", "ls", "x1", "pods", "-n", "50")
	if e.Code != "USAGE" || e.Exit != 2 || e.Message != "-n: 50 is a count, but -n is --namespace in cluster commands" ||
		e.Hint != "`--limit 50`, or `--namespace=50` for a namespace named 50" {
		t.Errorf("cluster ls -n 50: %+v", e)
	}
}

// clusterParse parses args for the command at path in a fresh tree; nil
// when the command has no flag args need.
func clusterParse(t *testing.T, path string, args []string) *cobra.Command {
	t.Helper()
	found, _, _ := newRoot(tcl).Find(strings.Fields(strings.TrimPrefix(path, "komando ")))
	if strings.HasPrefix(args[0], "-A") && found.Flags().Lookup("all-namespaces") == nil {
		return nil
	}
	if err := found.ParseFlags(args); err != nil {
		t.Errorf("%s %v: %v", path, args, err)
		return nil
	}
	return found
}

func TestSwarmRolloutState(t *testing.T) {
	for _, c := range []struct {
		state, msg, replicas string
		rollback             bool
		done, failed         bool
	}{
		{"completed", "update completed", "2/2", false, true, false},
		{"updating", "", "1/2", false, false, false},
		{"paused", "update paused due to failure", "1/2", false, false, true},
		{"rollback_started", "update rolled back due to failure", "1/2", false, false, true}, // a deploy that failed
		{"rollback_started", "manually requested rollback", "2/2", false, false, false},      // someone rolled back
		{"rollback_started", "manually requested rollback", "2/2", true, false, false},
		{"rollback_completed", "rollback completed", "2/2", true, true, false},
		{"rollback_completed", "rollback completed", "2/2", false, true, true}, // an automatic rollback ended a deploy
		{"rollback_paused", "", "1/2", true, false, true},
		{"", "", "3/3", false, true, false},
		{"", "", "0/3", false, false, false},
	} {
		done, failed := swarmRolloutState(c.state, c.msg, c.replicas, c.rollback)
		if done != c.done || failed != c.failed {
			t.Errorf("%+v: done=%v failed=%v", c, done, failed)
		}
	}
}

func TestSwarmMapping(t *testing.T) {
	ls := jsonLines(`{"ID":"abc","Name":"shop_web","Image":"nginx:1@sha256:x","Mode":"replicated","Replicas":"1/3","Ports":"*:80->80/tcp"}
{"ID":"def","Name":"shop_db","Image":"pg:16","Mode":"replicated","Replicas":"1/1","Ports":""}`)
	ins := jsonLines(`{"ID":"abcdef123","CreatedAt":"2026-01-01T00:00:00.5Z","UpdateStatus":{"State":"completed"}}`)
	rows := swarmServices(ls, ins)
	if len(rows) != 2 || rows[1]["name"] != "shop_web" || rows[1]["image"] != "nginx:1" || rows[1]["ready"] != "1/3" || rows[1]["update_state"] != "completed" || rows[1]["age"] == "" {
		t.Errorf("services: %v", rows)
	}
	tasks := swarmTasks(jsonLines(`{"Name":"shop_web.2","Image":"nginx:1","Node":"n1","DesiredState":"Ready","CurrentState":"Preparing 2 seconds ago","Error":""}
{"Name":"\\_ shop_web.2","Image":"nginx:1","Node":"n1","DesiredState":"Shutdown","CurrentState":"Failed 9 seconds ago","Error":"\"task: non-zero exit (1)\""}
{"Name":"shop_web.1","Image":"nginx:1","Node":"n1","DesiredState":"Running","CurrentState":"Running 5 minutes ago","Error":""}`))
	if tasks[1]["name"] != "shop_web.2" || tasks[1]["current"] != false || tasks[1]["state"] != "Failed" || tasks[1]["since"] != "9 seconds ago" || tasks[1]["error"] != "task: non-zero exit (1)" {
		t.Errorf("tasks: %v", tasks[1])
	}
	stuck := stuckTasks(tasks)
	if !strings.Contains(stuck, "shop_web.2 failed: task: non-zero exit (1)") || strings.Contains(stuck, "shop_web.1") {
		t.Errorf("stuck: %q", stuck)
	}
	nodes := swarmNodes(jsonLines(`{"Hostname":"m1","Status":"Ready","Availability":"Active","ManagerStatus":"Leader"}
{"Hostname":"w1","Status":"Down","Availability":"Drain","ManagerStatus":""}`))
	h := swarmHealth("m1", "28.0", nodes, ls, tasks)
	probs, _ := h["problems"].([]map[string]string)
	if h["healthy"] != false || h["nodes_ready"] != 1 || h["managers"] != 1 || len(probs) != 3 {
		t.Fatalf("health: %v", h)
	}
	if probs[2]["object"] != "service/shop_web" || !strings.Contains(probs[2]["problem"], "1 of 3 replicas running") {
		t.Errorf("service problem: %v", probs[2])
	}
}

func TestSwarmDescribe(t *testing.T) {
	ins := jsonLines(`{"ID":"x","CreatedAt":"2026-01-01T00:00:00Z","Spec":{"Name":"web","Mode":{"Replicated":{"Replicas":3}},"TaskTemplate":{"ContainerSpec":{"Image":"nginx:1@sha256:x","Args":["nginx","-g"]}}},"UpdateStatus":{"State":"paused","Message":"update paused"},"Endpoint":{"Ports":[{"Protocol":"tcp","TargetPort":80,"PublishedPort":8080}]}}`)[0]
	d := swarmService("m1", ins, "2/3", nil)
	sum := d["summary"].(map[string]any)
	if d["object"] != "service/web" || sum["image"] != "nginx:1" || sum["replicas"] != 3 || sum["mode"] != "replicated" || sum["ports"] != "8080->80/tcp" || sum["update_state"] != "paused" {
		t.Errorf("describe: %v", sum)
	}
	if txt := d.Text(); !strings.Contains(txt, "service/web") || !strings.Contains(txt, "update state: paused") {
		t.Errorf("text: %s", txt)
	}
}

func TestPickRollback(t *testing.T) {
	rs := func(rev int, img string, history string) map[string]any {
		ann := map[string]any{revisionKey: strconv.Itoa(rev)}
		if history != "" {
			ann["deployment.kubernetes.io/revision-history"] = history
		}
		return map[string]any{"metadata": map[string]any{"annotations": ann},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"image": img}}}}}}
	}
	// deploy good (1), restart (2, same image), deploy bad (3): go to 2
	sets := []map[string]any{rs(3, "bad", ""), rs(2, "good", ""), rs(1, "good", "")}
	if got, err := pickRollback(sets, 3); err != nil || rsRevision(got) != 2 {
		t.Errorf("first rollback: %v %v", got, err)
	}
	// after that rollback, 2 became 4 (history "2"); 3 is the bad one: do not go back to it
	sets = []map[string]any{rs(4, "good", "2"), rs(3, "bad", ""), rs(1, "good", "")}
	if _, err := pickRollback(sets, 4); err == nil || !strings.Contains(toErr(err).Message, "3 (rolled back from)") {
		t.Errorf("a second rollback must not bring the bad version back: %v", err)
	}
	// a newer deploy after the rollback: back to the good one
	sets = []map[string]any{rs(5, "v2", ""), rs(4, "good", "2"), rs(3, "bad", "")}
	if got, err := pickRollback(sets, 5); err != nil || rsRevision(got) != 4 {
		t.Errorf("rollback after a new deploy: %v %v", got, err)
	}
	if got := revisionList(sets); got != "3, 4, 5" {
		t.Errorf("revision list %q", got)
	}
}

func TestDiffObjectSecret(t *testing.T) {
	before := []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","resourceVersion":"1"},"data":{"a":"b25l","b":"eA=="}}`)
	after := []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","resourceVersion":"2"},"data":{"a":"dHdv","b":"eA==","c":"eQ=="}}`)
	c := diffObject(tcl, "secret/s", before, after)
	if c.Action != "change" {
		t.Fatalf("a changed Secret value is a change, got %s", c.Action)
	}
	if strings.Contains(c.Diff, "dHdv") || strings.Contains(c.Diff, "b25l") || !strings.Contains(c.Diff, "+  a: (hidden, changed)") || !strings.Contains(c.Diff, "+  c: (hidden, new)") {
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

func TestKubeListText(t *testing.T) {
	l := kubeList{"type": "Deployment", "namespace": "shop", "items": []map[string]any{{"name": "api", "ready": "2/2", "updated": 2, "available": 2, "age": "5m"}}}
	txt := l.Text()
	if !strings.HasPrefix(txt, "NAME  READY  UP-TO-DATE  AVAILABLE  AGE\napi   2/2    2           2          5m") {
		t.Errorf("deployments:\n%s", txt)
	}
	all := kubeList{"type": "Pod", "items": []map[string]any{{"name": "p", "namespace": "a", "ready": "1/1", "status": "Running", "restarts": 0, "age": "40s"}}}
	if !strings.HasPrefix(all.Text(), "NAMESPACE  NAME") {
		t.Errorf("every namespace adds the column:\n%s", all.Text())
	}
	if !strings.Contains((kubeList{"type": "Pod", "namespace": "x", "items": []map[string]any{}}).Text(), "no pods in namespace x yet") {
		t.Error("empty list")
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

func TestSinceParam(t *testing.T) {
	if q, err := sinceParam("10m"); err != nil || q.Get("sinceSeconds") != "600" {
		t.Errorf("10m: %v %v", q, err)
	}
	if q, err := sinceParam("2026-01-02T10:00:00Z"); err != nil || q.Get("sinceTime") != "2026-01-02T10:00:00Z" {
		t.Errorf("time: %v %v", q, err)
	}
	if _, err := sinceParam("yesterday-ish"); err == nil {
		t.Error("nonsense must be refused")
	}
}
