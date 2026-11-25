package cli

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// testRound tests every target of sel once, in parallel.
func testRound(cl *call, ctx context.Context, st *store.State, sel selection) []targetTest {
	var res []targetTest
	for _, o := range fanout(cl, allowWindows(ctx), st, sel.Hosts, testHost) {
		r := targetTest{Host: o.Host.Name, Kind: "host"}
		if o.Err != nil {
			r.Error = fixTestError(st, o.Host.Name, toErr(o.Err))
		} else {
			d := o.Value.(testResult)
			d.Host = o.Host.Name
			r.OK, r.LatencyMS, r.Detail = true, d.LatencyMS, d
		}
		res = append(res, r)
	}
	res = append(res, testConns(cl, ctx, st, sel.Conns)...)
	for _, v := range sel.Vpns {
		res = append(res, vpnTest(cl, ctx, st, v))
	}
	// by name, like `komando list`: not all servers before all conns
	sort.SliceStable(res, func(i, j int) bool { return res[i].Host < res[j].Host })
	return res
}

// waitInterval is the pause between two rounds of `test --wait`.
var waitInterval = 5 * time.Second

// noWaitFor says whether waiting cannot help with this error: a changed
// host key may be an attack, retrying a refused login can get the address
// banned (fail2ban), and a VPN login or a local key or secret does not
// change by itself.
func noWaitFor(code string) bool {
	for _, p := range []string{"HOSTKEY_", "AUTH_FAILED", "VPN_LOGIN", "KEY_", "SECRET_", "VAULT_", "PROTECTED_", "POLICY_"} {
		if strings.HasPrefix(code, p) {
			return true
		}
	}
	return false
}

// waitForTargets tests the targets of sel that did not pass again, every
// waitInterval, until they all pass, only errors waiting cannot help are
// left, or the deadline. It returns the last result of every target, in
// the order of res (by name).
func waitForTargets(cl *call, ctx context.Context, st *store.State, sel selection, res []targetTest, deadline time.Time) []targetTest {
	for {
		pending := waitPending(sel, res)
		if len(pending.Hosts)+len(pending.Conns)+len(pending.Vpns) == 0 {
			return res
		}
		left := time.Until(deadline)
		if left <= 0 {
			return res
		}
		if cl.interactive() {
			fmt.Fprintf(cl.out.Err, "Waiting for %d of %d targets, %s left\n", len(pending.Hosts)+len(pending.Conns)+len(pending.Vpns), len(res), left.Round(time.Second))
		}
		select {
		case <-ctx.Done():
			return res
		case <-time.After(min(waitInterval, left)):
		}
		if time.Until(deadline) <= 0 {
			return res // no round cut short: the last error is the real one
		}
		rctx, cancel := context.WithDeadline(ctx, deadline)
		again := testRound(cl, rctx, st, pending)
		cancel()
		byName := map[string]targetTest{}
		for _, r := range again {
			byName[r.Kind+"/"+r.Host] = r
		}
		for i, r := range res {
			if n, ok := byName[r.Kind+"/"+r.Host]; ok {
				res[i] = n
			}
		}
	}
}

// waitPending is the part of sel that did not pass yet and may still.
func waitPending(sel selection, res []targetTest) selection {
	retry := map[string]bool{}
	for _, r := range res {
		if !r.OK && (r.Error == nil || !noWaitFor(r.Error.Code)) {
			retry[r.Host] = true
		}
	}
	var p selection
	for _, h := range sel.Hosts {
		if retry[h.Name] {
			p.Hosts = append(p.Hosts, h)
		}
	}
	for _, c := range sel.Conns {
		if retry[c.Name] {
			p.Conns = append(p.Conns, c)
		}
	}
	for _, v := range sel.Vpns {
		if retry[v.Name] {
			p.Vpns = append(p.Vpns, v)
		}
	}
	return p
}

// testRoundKeeping is testRound with the person step: when a person runs
// test at a terminal, a server that only a person can log in to (a code,
// a typed password) gets one kept session, which the person answers once
// and an agent's later commands reuse. Without a person at a terminal
// nothing is asked, and such a server fails with the hint that names test.
func testRoundKeeping(cl *call, ctx context.Context, st *store.State, sel selection) []targetTest {
	if !cl.interactive() || cl.dryRun() || len(sel.Hosts) == 0 {
		return testRound(cl, ctx, st, sel)
	}
	asker := sshx.Asker
	sshx.Asker = nil // the session's own login asks, not each test
	res := testRound(cl, ctx, st, sel)
	sshx.Asker = asker
	var kept selection
	byName := map[string]*store.Host{}
	for _, h := range sel.Hosts {
		byName[h.Name] = h
	}
	failed := map[string]*out.Error{}
	for _, r := range res {
		if h := byName[r.Host]; h != nil && r.Kind == "host" && sshx.NeedsPersonStep(r.Error) {
			if err := keepSession(cl, st, h); err != nil {
				failed[r.Host] = toErr(err)
				continue
			}
			kept.Hosts = append(kept.Hosts, h)
		}
	}
	if len(kept.Hosts) > 0 {
		if st2, err := loadState(); err == nil {
			again := testRound(cl, ctx, st2, kept)
			for i, r := range res {
				for _, a := range again {
					if a.Host == r.Host {
						res[i] = a
					}
				}
			}
		}
	}
	for i, r := range res {
		if e := failed[r.Host]; e != nil {
			res[i].Error = e
		}
	}
	return res
}

// keepSession keeps a session for h, answered by the person at this
// terminal, unless one is already kept.
func keepSession(cl *call, st *store.State, h *store.Host) error {
	if l := sshx.HeldFor(st, h); l != nil && heldAlive(l) {
		return nil
	}
	keep, _ := time.ParseDuration(st.Settings.LoginFor)
	if keep <= 0 {
		keep = 8 * time.Hour
	}
	_, err := keepLogin(cl, st, h, keep)
	return err
}

// endSessions is `test --end`: it ends the kept sessions of the servers
// named, or every kept session when none is named (a top-level test only).
func endSessions(cl *call, args []string, only string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	var names []string
	switch {
	case len(args) > 0:
		sel, err := resolveSelection(cl, st, args[0])
		if err != nil {
			if st.Logins[args[0]] == nil { // a server removed since still ends
				return err
			}
			names = []string{args[0]}
			break
		}
		for _, h := range keepOnly(sel, "host").Hosts {
			names = append(names, h.Name)
		}
	case only != "":
		return out.Usage("komando %s test --end needs the server to end", only).WithHint("komando " + only + " test NAME --end")
	default:
		names = slices.Sorted(maps.Keys(st.Logins))
	}
	// ending a kept session changes how komando reaches that server: the
	// change-tier guard, as for any change there (a protected server needs
	// --yes). A server removed since has no inventory entry to guard.
	var hosts []*store.Host
	for _, n := range names {
		if h := st.Hosts[n]; h != nil {
			hosts = append(hosts, h)
		}
	}
	if err := Guard(cl, st, hosts, "", true); err != nil {
		return err
	}
	if cl.dryRun() {
		cl.out.Print("test.end", testEndData{Ended: names}, nil)
		return nil
	}
	data := testEndData{Ended: []string{}}
	for _, n := range names {
		l := st.Logins[n]
		if l == nil {
			continue
		}
		if heldAlive(l) {
			data.Ended = append(data.Ended, n)
		}
		endLogin(l)
	}
	if err := store.UpdateRuntime(cl.storeWrite(), func(s *store.State) error {
		for _, n := range names {
			delete(s.Logins, n)
		}
		return nil
	}); err != nil {
		return err
	}
	if len(data.Ended) > 0 {
		audit(cl, st, "test.end", data.Ended, "", true, nil)
	}
	cl.out.Print("test.end", data, nil)
	return nil
}

type testEndData struct {
	Ended []string `json:"ended"`
}

func (d testEndData) Text() string {
	if len(d.Ended) == 0 {
		return "no kept sessions, so nothing ended (`komando status` lists them)\n"
	}
	var sb strings.Builder
	for _, n := range d.Ended {
		sb.WriteString("ended the kept session of " + term.CleanText(n) + "\n")
	}
	return sb.String()
}
