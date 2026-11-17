package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Docker Swarm through its manager: docker runs there over SSH and its
// answers are mapped into the same shapes the Kubernetes side prints
// (items[], healthy/problems, summary + tasks), not raw docker output.

// swarmPreamble makes sure the server is a Swarm manager before the real
// command runs, so a wrong target says so instead of a docker error.
const swarmPreamble = `command -v docker >/dev/null 2>&1 || { echo 'komando: docker not found' >&2; exit 127; }
komando_sw=$(docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}' 2>&1)
case "$komando_sw" in
"active true") ;;
"active false") echo 'komando: swarm worker' >&2; exit 64 ;;
inactive*|pending*|error*|locked*) echo "komando: swarm $komando_sw" >&2; exit 64 ;;
*) echo "$komando_sw" >&2; exit 1 ;;
esac
`

// swarmExec runs script on the manager and returns stdout. Failures come
// back as errors with an exit code that fits (not found, not a manager).
func swarmExec(cl *call, ctx context.Context, st *store.State, t clusterTarget, script string, stdin []byte) (string, error) {
	var res *sshx.RunResult
	err := withClient(cl, ctx, st, t.host, func(c *sshx.Client) error {
		var err error
		res, err = sshx.Run(ctx, c, sshx.RunRequest{Command: swarmPreamble + script, Stdin: stdin, Timeout: cmdTimeout(cl, st), MaxOutput: maxOutput(cl, st)})
		return err
	})
	if err != nil {
		return "", err
	}
	if res.TimedOut {
		return "", out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "docker on %s did not answer in time", t.host.Name)
	}
	if res.ExitCode != 0 {
		return res.Stdout, swarmErr(t.host.Name, res.Stderr, res.Stdout, res.ExitCode)
	}
	return res.Stdout, nil
}

// swarmErr explains a failed docker command on a would-be manager.
func swarmErr(host, stderr, stdout string, code int) *out.Error {
	msg := strings.TrimSpace(stderr)
	hint := "Swarm commands run on a manager: `komando exec " + host + " --read-only -- docker node ls` shows whether it is one"
	switch {
	case strings.Contains(msg, "komando: docker not found"):
		return out.Errf(out.ExitNotFound, "NOT_SWARM_MANAGER", hint, "%s is not a Swarm manager (docker not found)", host)
	case strings.Contains(msg, "komando: swarm worker"), strings.Contains(msg, "not a swarm manager"):
		return out.Errf(out.ExitNotFound, "NOT_SWARM_MANAGER", hint, "%s is a Swarm worker, not a manager", host)
	case strings.Contains(msg, "komando: swarm "):
		state := strings.TrimSpace(strings.TrimPrefix(msg[strings.Index(msg, "komando: swarm "):], "komando: swarm "))
		state, _, _ = strings.Cut(state, " ")
		return out.Errf(out.ExitNotFound, "NOT_SWARM_MANAGER", hint, "%s is not a Swarm manager (swarm %s)", host, state)
	}
	if msg == "" {
		msg = strings.TrimSpace(stdout)
	}
	e := dockerErr(msg, code)
	switch e.Code {
	case "DOCKER_ERROR":
		e.Code = "SWARM_ERROR"
	case "NOT_FOUND":
		e.Hint = "list what exists with `komando cluster list " + host + " services` (or tasks, nodes, stacks)"
	}
	return e
}

// jsonLines decodes docker's --format '{{json .}}' output.
func jsonLines(s string) []map[string]any {
	rows := []map[string]any{}
	for _, line := range strings.Split(s, "\n") {
		var m map[string]any
		if line = strings.TrimSpace(line); line != "" && json.Unmarshal([]byte(line), &m) == nil {
			rows = append(rows, m)
		}
	}
	return rows
}

// sections splits output written as parts separated by "--" lines.
func swarmSections(s string, n int) []string {
	parts := make([]string, n)
	i := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "--" && i < n-1 {
			i++
			continue
		}
		parts[i] += line + "\n"
	}
	return parts
}

// sinceAge is a docker timestamp as a kubectl age (40s, 5m, 3h).
func sinceAge(ts string) string {
	if ts == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		if t, err = time.Parse("2006-01-02 15:04:05 -0700 MST", ts); err != nil {
			return ""
		}
	}
	return humanAge(time.Since(t))
}

// shortImage drops the digest docker pins services to (busybox:1@sha256:...).
func shortImage(img string) string {
	img, _, _ = strings.Cut(img, "@")
	return img
}

// Swarm list commands.

func swarmFilter(selector string) string {
	if selector == "" {
		return ""
	}
	return " --filter " + sshx.Q("label="+selector)
}

// swarmList reads one kind of Swarm object as {host, type, count, items}.
func swarmList(cl *call, ctx context.Context, t clusterTarget, kind, selector string, limit int) (kubeList, error) {
	if selector != "" && kind != "service" && kind != "node" {
		return nil, out.Usage("on Swarm, --selector works for services and nodes")
	}
	st, err := loadState()
	if err != nil {
		return nil, err
	}
	f := swarmFilter(selector)
	var items []map[string]any
	switch kind {
	case "service":
		s, err := swarmExec(cl, ctx, st, t, "ids=$(docker service ls -q"+f+"); [ -z \"$ids\" ] && exit 0\n"+
			"docker service ls"+f+" --format '{{json .}}'; echo --; docker service inspect $ids --format '{{json .}}'", nil)
		if err != nil {
			return nil, err
		}
		p := swarmSections(s, 2)
		items = swarmServices(jsonLines(p[0]), jsonLines(p[1]))
	case "task":
		s, err := swarmExec(cl, ctx, st, t, "ids=$(docker service ls -q); [ -z \"$ids\" ] || docker service ps $ids --no-trunc --format '{{json .}}'", nil)
		if err != nil {
			return nil, err
		}
		items = swarmTasks(jsonLines(s))
	case "node":
		s, err := swarmExec(cl, ctx, st, t, "docker node ls"+f+" --format '{{json .}}'", nil)
		if err != nil {
			return nil, err
		}
		items = swarmNodes(jsonLines(s))
	case "stack":
		s, err := swarmExec(cl, ctx, st, t, "docker stack ls --format '{{json .}}'", nil)
		if err != nil {
			return nil, err
		}
		for _, r := range jsonLines(s) {
			n, _ := strconv.Atoi(str(r["Services"]))
			items = append(items, map[string]any{"name": str(r["Name"]), "services": n})
		}
	default:
		return nil, out.Usage("Swarm lists services, tasks, nodes or stacks")
	}
	if items == nil {
		items = []map[string]any{}
	}
	res := kubeList{"host": t.host.Name, "type": strings.ToUpper(kind[:1]) + kind[1:], "count": len(items), "items": items}
	if limit > 0 && len(items) > limit {
		res["items"], res["count"], res["truncated"] = items[:limit], limit, true
		cl.out.CutNoted()
	}
	return res, nil
}

// swarmServices joins `service ls` (running/desired) with `service inspect`
// (created time, update state) into one row per service.
func swarmServices(ls, inspect []map[string]any) []map[string]any {
	byID := map[string]map[string]any{}
	for _, s := range inspect {
		byID[str(s["ID"])] = s
	}
	rows := []map[string]any{}
	for _, l := range ls {
		row := map[string]any{"name": str(l["Name"]), "image": shortImage(str(l["Image"])), "ready": str(l["Replicas"]),
			"mode": str(l["Mode"]), "ports": str(l["Ports"])}
		for id, s := range byID {
			if id != "" && strings.HasPrefix(id, str(l["ID"])) {
				row["age"] = sinceAge(str(s["CreatedAt"]))
				if u, ok := s["UpdateStatus"].(map[string]any); ok {
					row["update_state"] = str(u["State"])
				}
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return str(rows[i]["name"]) < str(rows[j]["name"]) })
	return rows
}

// swarmTasks maps `service ps` rows. "Running 5 minutes ago" becomes
// state Running, since "5 minutes ago"; older tasks of a slot are marked.
func swarmTasks(ps []map[string]any) []map[string]any {
	rows := []map[string]any{}
	for _, p := range ps {
		name := str(p["Name"])
		old := strings.HasPrefix(name, `\_ `)
		name = strings.TrimPrefix(name, `\_ `)
		state, since, _ := strings.Cut(str(p["CurrentState"]), " ")
		svc := name
		if i := strings.LastIndex(name, "."); i > 0 {
			svc = name[:i]
		}
		rows = append(rows, map[string]any{"name": name, "id": str(p["ID"]), "service": svc, "image": shortImage(str(p["Image"])),
			"node": str(p["Node"]), "desired": str(p["DesiredState"]), "state": state, "since": since, "error": strings.Trim(str(p["Error"]), `"`),
			"ports": str(p["Ports"]), "current": !old})
	}
	return rows
}

func swarmNodes(ls []map[string]any) []map[string]any {
	rows := []map[string]any{}
	for _, n := range ls {
		rows = append(rows, map[string]any{"name": str(n["Hostname"]), "id": str(n["ID"]), "status": str(n["Status"]),
			"availability": str(n["Availability"]), "manager": str(n["ManagerStatus"]), "engine": str(n["EngineVersion"]), "self": n["Self"] == true})
	}
	return rows
}

// Swarm status.

func swarmStatus(cl *call, ctx context.Context, t clusterTarget) (statusData, error) {
	st, err := loadState()
	if err != nil {
		return nil, err
	}
	s, err := swarmExec(cl, ctx, st, t, `docker version --format '{{.Server.Version}}'; echo --
docker node ls --format '{{json .}}'; echo --
docker service ls --format '{{json .}}'; echo --
ids=$(docker service ls -q); [ -z "$ids" ] || docker service ps $ids --no-trunc --format '{{json .}}'`, nil)
	if err != nil {
		return nil, err
	}
	p := swarmSections(s, 4)
	return swarmHealth(t.host.Name, strings.TrimSpace(p[0]), swarmNodes(jsonLines(p[1])), jsonLines(p[2]), swarmTasks(jsonLines(p[3]))), nil
}

// swarmHealth sums up a Swarm like `cluster status` does a Kubernetes
// cluster: nodes that are down or drained, services short of replicas
// (with the error of a task that does not run).
func swarmHealth(host, version string, nodes, services, tasks []map[string]any) statusData {
	problems := []map[string]string{}
	problem := func(obj, why string) { problems = append(problems, map[string]string{"object": obj, "problem": why}) }
	ready, managers := 0, 0
	for _, n := range nodes {
		name := "node/" + str(n["name"])
		if str(n["manager"]) != "" {
			managers++
		}
		if str(n["status"]) == "Ready" {
			ready++
		} else {
			problem(name, strings.ToLower(cmp.Or(str(n["status"]), "unknown")))
		}
		if a := str(n["availability"]); a != "" && a != "Active" {
			problem(name, strings.ToLower(a))
		}
	}
	for _, sv := range services {
		name := str(sv["Name"])
		running, want, ok := strings.Cut(strings.Fields(str(sv["Replicas"]) + " ")[0], "/")
		r, _ := strconv.Atoi(running)
		w, _ := strconv.Atoi(want)
		if !ok || r >= w {
			continue
		}
		why := fmt.Sprintf("%d of %d replicas running", r, w)
		var mine []map[string]any
		for _, tk := range tasks {
			if tk["service"] == name {
				mine = append(mine, tk)
			}
		}
		if stuck := stuckTasks(mine); stuck != "" {
			why += "; " + stuck
		}
		problem("service/"+name, why)
	}
	return statusData{"host": host, "version": version, "nodes": len(nodes), "nodes_ready": ready, "managers": managers,
		"services": len(services), "healthy": len(problems) == 0, "problems": problems}
}

// Swarm describe, get and logs.

func swarmDescribe(cl *call, ctx context.Context, t clusterTarget, name string) (any, error) {
	st, err := loadState()
	if err != nil {
		return nil, err
	}
	q := sshx.Q(name)
	s, err := swarmExec(cl, ctx, st, t, "docker service inspect "+q+" --format '{{json .}}'; echo --; docker service ps "+q+
		" --no-trunc --format '{{json .}}'; echo --; docker service ls --filter "+sshx.Q("name="+name)+" --format '{{json .}}'", nil)
	if err != nil {
		return nil, err
	}
	p := swarmSections(s, 3)
	ins := jsonLines(p[0])
	if len(ins) == 0 {
		return nil, out.Errf(out.ExitNotFound, "NOT_FOUND", "list the services with `komando cluster list "+t.host.Name+" services`", "no service named %q", name).About("swarm_service")
	}
	ready := ""
	for _, l := range jsonLines(p[2]) {
		if str(l["Name"]) == name {
			ready = str(l["Replicas"])
		}
	}
	return swarmService(t.host.Name, ins[0], ready, swarmTasks(jsonLines(p[1]))), nil
}

// swarmService is `describe service`: the few things that tell its state,
// then its tasks with their errors.
func swarmService(host string, ins map[string]any, ready string, tasks []map[string]any) describeData {
	spec, _ := ins["Spec"].(map[string]any)
	tt, _ := spec["TaskTemplate"].(map[string]any)
	cs, _ := tt["ContainerSpec"].(map[string]any)
	mode, _ := spec["Mode"].(map[string]any)
	sum := map[string]any{"name": str(spec["Name"]), "image": shortImage(str(cs["Image"])), "ready": ready, "age": sinceAge(str(ins["CreatedAt"]))}
	if r, ok := mode["Replicated"].(map[string]any); ok {
		sum["mode"] = "replicated"
		if n, ok := r["Replicas"].(float64); ok {
			sum["replicas"] = int(n)
		}
	} else if _, ok := mode["Global"]; ok {
		sum["mode"] = "global"
	}
	if u, ok := ins["UpdateStatus"].(map[string]any); ok {
		sum["update_state"], sum["update_message"] = str(u["State"]), str(u["Message"])
	}
	if ep, ok := ins["Endpoint"].(map[string]any); ok {
		var ports []string
		pl, _ := ep["Ports"].([]any)
		for _, x := range pl {
			m, _ := x.(map[string]any)
			ports = append(ports, fmt.Sprintf("%v->%v/%v", scalarNum(m["PublishedPort"]), scalarNum(m["TargetPort"]), m["Protocol"]))
		}
		if len(ports) > 0 {
			sum["ports"] = strings.Join(ports, ",")
		}
	}
	if args, ok := cs["Args"].([]any); ok && len(args) > 0 {
		var a []string
		for _, x := range args {
			a = append(a, fmt.Sprint(x))
		}
		sum["args"] = strings.Join(a, " ")
	}
	return describeData{"host": host, "object": "service/" + str(spec["Name"]), "summary": sum, "tasks": tasks}
}

func scalarNum(v any) any {
	if f, ok := v.(float64); ok {
		return int64(f)
	}
	return v
}

// swarmGet is `cluster get` on Swarm: the object's full inspect JSON.
func swarmGet(cl *call, ctx context.Context, t clusterTarget, typ, name string) (any, error) {
	kind := swarmKind(typ)
	if kind == "" {
		if oneOf(strings.ToLower(typ), "network", "volume", "secret", "config") {
			kind = strings.ToLower(typ)
		} else {
			return nil, out.Usage("on Swarm, get works for services, tasks, nodes, networks, volumes, secrets and configs")
		}
	}
	if kind == "stack" {
		return nil, out.Usage("a stack is its services: `komando cluster list %s services -l com.docker.stack.namespace=%s`", t.host.Name, name)
	}
	st, err := loadState()
	if err != nil {
		return nil, err
	}
	line := "docker " + kind + " inspect " + sshx.Q(name) + " --format '{{json .}}'"
	if kind == "task" {
		line = "docker inspect --type task " + sshx.Q(name) + " --format '{{json .}}' 2>/dev/null || docker service ps " + sshx.Q(name) + " -q --no-trunc | head -1 | xargs -r docker inspect --type task --format '{{json .}}'"
	}
	s, err := swarmExec(cl, ctx, st, t, line, nil)
	if err != nil {
		return nil, err
	}
	rows := jsonLines(s)
	if len(rows) == 0 {
		return nil, out.Errf(out.ExitNotFound, "NOT_FOUND", "list what exists with `komando cluster list TARGET "+kind+"s`", "no %s named %q", kind, name).About("swarm_" + kind)
	}
	return rows[0], nil
}

// swarmLogsData is the logs of one Swarm service.
type swarmLogsData struct {
	Host   string `json:"host"`
	Object string `json:"object"`
	Logs   string `json:"logs"`
}

func (l swarmLogsData) Text() string { return l.Logs }

// swarmLogs reads a service's logs, or with follow prints new lines until
// Ctrl-C or --timeout, which both end it normally (exit 0).
func swarmLogs(cl *call, ctx context.Context, t clusterTarget, service string, limit int, since string, follow, timestamps bool) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	line := "docker service logs --no-trunc --raw --tail " + strconv.Itoa(limit)
	if timestamps {
		line += " --timestamps"
	}
	if since != "" {
		line += " --since " + sshx.Q(strings.TrimPrefix(since, "-"))
	}
	// the service must exist: docker service logs would wait forever
	line = "docker service inspect " + sshx.Q(service) + " --format '{{.ID}}' >/dev/null || exit 1\n" + line
	if !follow {
		s, err := swarmExec(cl, ctx, st, t, line+" "+sshx.Q(service)+" 2>&1", nil)
		if err != nil {
			return err
		}
		cl.out.Print("cluster.logs", swarmLogsData{Host: t.host.Name, Object: "service/" + service, Logs: s}, nil)
		return nil
	}
	if cl.flags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cl.flags.timeout)
		defer cancel()
	}
	showStatus(cl, statusLine{What: "following logs of service/" + service, Target: t.host.Name, Route: hostRoute(st, t.host),
		Protected: protectedHost(st, t.host), Tail: "Ctrl-C stops"})
	lines := 0
	var res *sshx.RunResult
	var buf lineBuffer // whole lines, so a split secret is still redacted
	show := func(text string) {
		if text == "" {
			return
		}
		if cl.out.Format == "text" {
			fmt.Fprint(cl.out.W, out.SafeText(cl.out.Redact(text)))
			return
		}
		cl.out.Event(map[string]any{"event": "output", "object": "service/" + service, "data": text})
	}
	err = withClient(cl, ctx, st, t.host, func(c *sshx.Client) error {
		var err error
		res, err = sshx.Run(ctx, c, sshx.RunRequest{Command: swarmPreamble + line + " -f " + sshx.Q(service) + " 2>&1", MaxOutput: 1 << 20,
			Stream: func(stream string, chunk []byte) {
				if stream != "stdout" {
					return
				}
				lines += strings.Count(string(chunk), "\n")
				show(buf.add(chunk))
			}})
		show(buf.flush())
		return err
	})
	if ctx.Err() != nil {
		err = nil // --timeout or Ctrl-C: the normal end of a follow
	} else if err == nil && res.ExitCode != 0 {
		err = swarmErr(t.host.Name, res.Stderr, res.Stdout, res.ExitCode)
	}
	if err != nil {
		return err
	}
	if cl.out.Format != "text" {
		cl.out.Print("cluster.logs", map[string]any{"host": t.host.Name, "object": "service/" + service, "lines": lines, "followed": true}, nil)
	}
	return nil
}

// Swarm changes.

// swarmDo runs a change on the manager after the safety checks: risky
// changes need --allow-dangerous, protected servers --yes. Under --dry-run
// it runs nothing and returns ran=false.
func swarmDo(cl *call, ctx context.Context, name string, t clusterTarget, line string, stdin []byte, risk driver.Risk, why string) (string, bool, error) {
	st, err := loadState()
	if err != nil {
		return "", false, err
	}
	if risk >= driver.RiskDestructive && !cl.dangerOK() {
		if cl.typed == nil {
			askTypes(cl, []string{t.host.Name}, "servers") // the whole cluster: its manager's name
		}
		if err := guardConns(cl, st, nil, driver.Verdict{Risk: risk, RuleIDs: []string{name}, Reasons: []string{why}}); err != nil {
			return "", false, err
		}
	}
	if err := guard(cl, st, []*store.Host{t.host}, line, true); err != nil {
		return "", false, err
	}
	if cl.flags.dryRun {
		return "", false, nil
	}
	s, err := swarmExec(cl, ctx, st, t, line, stdin)
	rec := map[string]any{"risk": risk.String()}
	if err != nil {
		rec["error"] = toErr(err).Code
	}
	audit(cl, st, name, []string{t.host.Name}, line, err == nil, rec)
	return s, true, err
}

// swarmInspect reads one field set of a service (and so checks it exists).
func swarmInspect(cl *call, ctx context.Context, t clusterTarget, service string) (map[string]any, error) {
	st, err := loadState()
	if err != nil {
		return nil, err
	}
	s, err := swarmExec(cl, ctx, st, t, "docker service inspect "+sshx.Q(service)+" --format '{{json .}}'", nil)
	if err != nil {
		return nil, err
	}
	rows := jsonLines(s)
	if len(rows) == 0 {
		return nil, out.Errf(out.ExitNotFound, "NOT_FOUND", "list services with `komando cluster list TARGET services`", "no service named %q", service).About("swarm_service")
	}
	return rows[0], nil
}

// serviceImage is the image of a service spec (current or PreviousSpec).
func serviceImage(spec any) string {
	m, _ := spec.(map[string]any)
	tt, _ := m["TaskTemplate"].(map[string]any)
	cs, _ := tt["ContainerSpec"].(map[string]any)
	return shortImage(str(cs["Image"]))
}

// serviceReplicas is the desired replica count, or -1 for a global service.
func serviceReplicas(spec any) int {
	m, _ := spec.(map[string]any)
	mode, _ := m["Mode"].(map[string]any)
	r, ok := mode["Replicated"].(map[string]any)
	if !ok {
		return -1
	}
	n, _ := r["Replicas"].(float64)
	return int(n)
}

// swarmChange makes a service change and with wait follows the rollout to
// its end, printing one answer for both. res is what the command reports.
func swarmChange(cl *call, ctx context.Context, name string, t clusterTarget, service, line string, wait, rollback bool, risk driver.Risk, res map[string]any) error {
	res["host"] = t.host.Name
	why := line
	if risk >= driver.RiskDestructive {
		why = "stops every copy of " + service + " (scale to 0)"
	}
	_, ran, err := swarmDo(cl, ctx, name, t, line, nil, risk, why)
	if err != nil {
		return err
	}
	if !ran {
		res["dry_run"], res["would_run"] = true, line
		cl.out.Print(name, res, nil)
		return nil
	}
	if !wait {
		cl.out.Print(name, res, nil)
		return nil
	}
	ro, werr := swarmWait(cl, ctx, t, service, rolloutWait(cl), rollback)
	if ro == nil {
		return werr
	}
	for k, v := range ro {
		if _, taken := res[k]; !taken { // scale's replicas stays the number asked for
			res[k] = v
		}
	}
	cl.out.Print(name, res, softErr(werr))
	return exitFor(werr)
}

// swarmWait polls a Swarm service until its update (or rollback) is done
// and all replicas run. It returns the last state it saw.
func swarmWait(cl *call, ctx context.Context, t clusterTarget, service string, wait time.Duration, rollback bool) (map[string]any, error) {
	st, err := loadState()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	q := sshx.Q(service)
	cmd := "docker service inspect " + q + " --format '{{json .UpdateStatus}}'; echo --; docker service ls --filter " + sshx.Q("name="+service) +
		" --format '{{json .}}'; echo --; docker service ps " + q + " --no-trunc --format '{{json .}}'"
	for {
		s, err := swarmExec(cl, ctx, st, t, cmd, nil)
		if err != nil {
			return nil, err
		}
		p := swarmSections(s, 3)
		var upd struct{ State, Message string }
		_ = json.Unmarshal([]byte(strings.TrimSpace(p[0])), &upd)
		replicas := ""
		for _, l := range jsonLines(p[1]) {
			if str(l["Name"]) == service {
				replicas = str(l["Replicas"])
			}
		}
		done, failed := swarmRolloutState(upd.State, upd.Message, replicas, rollback)
		res := map[string]any{"object": "service/" + service, "rolled_out": done, "update_state": upd.State, "replicas": replicas, "status": upd.Message}
		hint := "see the tasks with `komando cluster describe " + t.host.Name + " service/" + service + "`"
		if failed {
			why := upd.Message
			if stuck := stuckTasks(swarmTasks(jsonLines(p[2]))); stuck != "" {
				why += "; " + stuck
			}
			return res, out.Errf(out.ExitRemote, "ROLLOUT_FAILED", hint, "update %s: %s", upd.State, why)
		}
		if done || wait <= 0 {
			return res, nil
		}
		if time.Now().After(deadline) {
			why := ""
			if stuck := stuckTasks(swarmTasks(jsonLines(p[2]))); stuck != "" {
				why = "; " + stuck
			}
			return res, out.Errf(out.ExitTimeout, "ROLLOUT_TIMEOUT", hint, "not rolled out after %s (replicas %s)%s", wait, replicas, why)
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// swarmRolloutState reads a service's UpdateStatus and replica count.
// A rollback is the failure of a deploy, but the goal of a rollback that
// komando (or a person: "manually requested rollback") started.
func swarmRolloutState(state, msg, replicas string, rollback bool) (done, failed bool) {
	running, want, _ := strings.Cut(strings.Fields(replicas + " ")[0], "/")
	full := running != "" && running == want
	manual := rollback || strings.Contains(msg, "manually requested")
	switch state {
	case "paused", "rollback_paused":
		return false, true
	case "rollback_started":
		return false, !manual
	case "rollback_completed":
		return full, !manual
	case "", "completed":
		return full, false
	}
	return false, false // updating
}

// stuckTasks names the slots whose newest task does not run, with the
// last error seen in that slot (Swarm retries, so the newest task is often
// just Preparing again).
func stuckTasks(tasks []map[string]any) string {
	var parts []string
	seen := map[string]bool{}
	for i, tk := range tasks { // newest first within a slot
		slot := str(tk["name"])
		if seen[slot] {
			continue
		}
		seen[slot] = true
		if tk["state"] == "Running" || tk["desired"] == "Shutdown" {
			continue
		}
		why := strings.ToLower(str(tk["state"]))
		for _, older := range tasks[i:] {
			if older["name"] == slot && str(older["error"]) != "" {
				why = strings.ToLower(str(older["state"])) + ": " + str(older["error"])
				break
			}
		}
		if len(parts) == 3 {
			parts = append(parts, "...")
			break
		}
		parts = append(parts, "task "+slot+" "+why+" (image "+str(tk["image"])+")")
	}
	return strings.Join(parts, "; ")
}

// swarmStackExists fails with not found (3) when no service belongs to stack.
func swarmStackExists(cl *call, ctx context.Context, t clusterTarget, stack string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	s, err := swarmExec(cl, ctx, st, t, "docker stack services -q "+sshx.Q(stack)+" 2>/dev/null; true", nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(s) == "" {
		return out.Errf(out.ExitNotFound, "NOT_FOUND", "list the stacks with `komando cluster list "+t.host.Name+" stacks`", "no stack named %q", stack).About("swarm_stack")
	}
	return nil
}
