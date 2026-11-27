package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Q8 (Audit, 2026-11-26): in format 3 a swarm is a service whose Manager
// is a server. A command given the service's name works on that server,
// so each guard of the server applies as if the server had been named.

// addSwarm adds the server name and, through its swarm tag, the swarm
// service name-swarm (the tag is removed by the C cluster row).
func addSwarm(t *testing.T, name string, flags ...string) {
	t.Helper()
	mustRun(t, append([]string{"host", "add", name, "deploy@" + closedAddr(t), "--tag", "swarm"}, flags...)...)
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if c := st.Conns[name+"-swarm"]; c == nil || c.Kind != "swarm" || c.Manager != name || c.ManagerID != st.Hosts[name].Rec.ID {
		t.Fatalf("no swarm service for %s: %+v", name, c)
	}
}

func codeOf(e *out.Error) string {
	if e == nil {
		return ""
	}
	return e.Code
}

// sameThroughManager runs args with TARGET as the swarm service's name and
// as its manager's, wants the same answer from both, and returns it.
func sameThroughManager(t *testing.T, host string, args ...string) (map[string]any, *out.Error) {
	t.Helper()
	run := func(target string) (string, map[string]any, *out.Error) {
		a := slices.Clone(args)
		for i := range a {
			if a[i] == "TARGET" {
				a[i] = target
			}
		}
		resetApproval()
		d, e := invRun(t, a...)
		if m, ok := d["_meta"].(map[string]any); ok {
			delete(m, "duration_ms")
		}
		return asJSON(d), d, e
	}
	hj, hd, he := run(host)
	sj, _, se := run(host + "-swarm")
	if hj != sj || codeOf(he) != codeOf(se) {
		t.Fatalf("%v\nthrough the service: %s %+v\nthrough the manager: %s %+v", args, sj, se, hj, he)
	}
	return hd, he
}

// A change on a swarm whose manager is protected stops as a change on that
// server does.
func TestSwarmServiceProtectedThroughManager(t *testing.T) {
	invHome(t)
	addSwarm(t, "swarm1", "--protected")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	d, e := sameThroughManager(t, "swarm1", "cluster", "run", "TARGET", "--write", "--dry-run", "--", "service", "scale", "web=3")
	if !strings.Contains(asJSON(d)+codeOf(e), "protected") {
		t.Fatalf("a change through a protected manager: %s %+v", asJSON(d), e)
	}
}

// What an AI agent reads through a swarm is hidden as personal data when
// its manager holds personal data (a masking conn reaches its data
// through the manager); another swarm's is not.
func TestSwarmServicePersonalThroughManager(t *testing.T) {
	invHome(t)
	addSwarm(t, "swarm1")
	addSwarm(t, "swarm2")
	mustRun(t, "conn", "add", "pg", "postgres://u@10.9.9.9:5432/app", "--via", "swarm1", "--option", "mask_personal=on")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	for target, want := range map[string]bool{"swarm1-swarm": true, "swarm1": true, "swarm2-swarm": false} {
		resetApproval()
		if _, e := invRun(t, "cluster", "run", target, "--dry-run", "--", "service", "ls"); e != nil || tcl.out.Personal != want {
			t.Errorf("%s: personal data hidden %v, want %v (%+v)", target, tcl.out.Personal, want, e)
		}
	}
}

// A read and a change through a swarm service get the tier, the stops and
// the approvals the manager gets.
func TestSwarmServiceTierThroughManager(t *testing.T) {
	invHome(t)
	addSwarm(t, "swarm1")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	sameThroughManager(t, "swarm1", "cluster", "run", "TARGET", "--dry-run", "--", "service", "ls")
	d, e := sameThroughManager(t, "swarm1", "cluster", "run", "TARGET", "--write", "--dry-run", "--", "service", "rm", "web")
	if e == nil && !strings.Contains(asJSON(d), "would_") {
		t.Fatalf("a change through the manager names nothing it would need: %s", asJSON(d))
	}
}

// Selectors pick a swarm once, by its manager; the next-step hints know
// a manager by its service, not by a tag.
func TestSwarmServiceFound(t *testing.T) {
	invHome(t)
	addSwarm(t, "swarm1")
	mustRun(t, "host", "add", "web1", "deploy@"+closedAddr(t))
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	ts, err := resolveClusters(tcl, st, "swarm1-swarm,swarm1")
	if err != nil || len(ts) != 1 || ts[0].host == nil || ts[0].host.Name != "swarm1" {
		t.Fatalf("resolveClusters: %+v %v", ts, err)
	}
	if !swarmManager(st, "all", st.Hosts["swarm1"]) || swarmManager(st, "all", st.Hosts["web1"]) {
		t.Fatal("swarmManager does not follow the swarm service")
	}
	for name, want := range map[string][]string{"swarm1": {"server", "swarm"}, "web1": {"server"}, "swarm1-swarm": {"swarm"}} {
		if got := itemKinds(st, "", name); !slices.Equal(got, want) {
			t.Errorf("itemKinds(%s) = %v, want %v", name, got, want)
		}
	}
	mustRun(t, "list")
}

// A swarm service whose manager is gone stops with a plain error, never
// on another server.
func TestSwarmServiceManagerGone(t *testing.T) {
	invHome(t)
	addSwarm(t, "swarm1")
	if err := store.Update(store.Save(), func(s *store.State) error { delete(s.Hosts, "swarm1"); return nil }); err != nil {
		t.Fatal(err)
	}
	e := wantCode(t, "SWARM_MANAGER_NOT_FOUND", "cluster", "run", "swarm1-swarm", "--dry-run", "--", "service", "ls")
	if !strings.Contains(e.Message, "swarm1") {
		t.Fatalf("message %q does not name the manager", e.Message)
	}
}

// The C cluster row gives a swarm its own add path (moveType("cluster")).
// That row removes the conversion of the swarm tag in the store
// (store/format3_swarm.go) and the --tag swarm line of swarmForm.
func TestSwarmTagGoesWithClusterRow(t *testing.T) {
	newRoot(tcl)
	if !slices.Contains(movedTypes, "cluster") {
		return // the C cluster row has not landed
	}
	invHome(t)
	for _, cmd := range swarmForm(tcl).build(nil, formAnswers{"name": "s1", "address": "10.0.0.1", "user": "root"}) {
		if slices.Contains(cmd, "swarm") && slices.Contains(cmd, "--tag") {
			t.Errorf("the C cluster row landed: remove --tag swarm from swarmForm (%v)", cmd)
		}
	}
	mustRun(t, "host", "add", "s1", "root@10.0.0.1", "--tag", "swarm")
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range st.Conns {
		if c.Kind == "swarm" {
			t.Errorf("the C cluster row landed: remove the swarm tag conversion in store/format3_swarm.go (%s)", c.Name)
		}
	}
}
