package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// testRound tests every target of sel once, in parallel.
func testRound(ctx context.Context, st *store.State, sel selection) []targetTest {
	var res []targetTest
	for _, o := range fanout(ctx, st, sel.Hosts, testHost) {
		r := targetTest{Name: o.Host.Name, Kind: "host"}
		if o.Err != nil {
			r.Error = fixTestError(st, o.Host.Name, toErr(o.Err))
		} else {
			d := o.Value.(testResult)
			d.Host = o.Host.Name
			r.OK, r.LatencyMS, r.Detail = true, d.LatencyMS, d
		}
		res = append(res, r)
	}
	res = append(res, testConns(ctx, st, sel.Conns)...)
	for _, v := range sel.Vpns {
		res = append(res, vpnTest(ctx, st, v))
	}
	for i := range res {
		res[i].Host = res[i].Name
	}
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
// sel's order.
func waitForTargets(ctx context.Context, st *store.State, sel selection, res []targetTest, deadline time.Time) []targetTest {
	for {
		pending := waitPending(sel, res)
		if len(pending.Hosts)+len(pending.Conns)+len(pending.Vpns) == 0 {
			return res
		}
		left := time.Until(deadline)
		if left <= 0 {
			return res
		}
		if interactive() {
			fmt.Fprintf(os.Stderr, "waiting for %d of %d target(s), %s left\n", len(pending.Hosts)+len(pending.Conns)+len(pending.Vpns), len(res), left.Round(time.Second))
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
		again := testRound(rctx, st, pending)
		cancel()
		byName := map[string]targetTest{}
		for _, r := range again {
			byName[r.Kind+"/"+r.Name] = r
		}
		for i, r := range res {
			if n, ok := byName[r.Kind+"/"+r.Name]; ok {
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
			retry[r.Name] = true
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
