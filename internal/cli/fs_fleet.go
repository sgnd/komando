package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// fs replace and fs restore on a TARGET: the same edit on every server it
// picks, one result per server, like fs rm and exec.

// fsFleetData is the result: one fsChange per server, with its host, ok
// and, when it failed there, its error.
type fsFleetData struct {
	Results []fsChange   `json:"results"`
	Summary fleetSummary `json:"summary"`
}

// Text is each server's change; with several servers each starts with
// its name, and a failed one says why.
func (d fsFleetData) TextFor(p *out.Printer) string {
	var b strings.Builder
	many := len(d.Results) > 1
	for _, r := range d.Results {
		if e, ok := r["error"].(*out.Error); ok {
			if many {
				fmt.Fprintf(&b, "%s: failed: %s (%s)\n", r["host"], e.Message, e.Code)
				if e.Hint != "" {
					b.WriteString("  Hint: " + e.Hint + "\n")
				}
			}
			continue
		}
		t := r.TextFor(p)
		if many {
			t = fmt.Sprint(r["host"]) + ": " + t
		}
		b.WriteString(t)
	}
	return b.String()
}

// runFsFleet runs edit on every server of hosts (in parallel, as exec
// does), then prints the results and audits name with path.
func runFsFleet(cl *call, ctx context.Context, st *store.State, name, path string, hosts []*store.Host, edit func(ctx context.Context, c *sshx.Client) (fsChange, error)) (fsFleetData, error) {
	res := fanout(cl, ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) { return edit(ctx, c) })
	data := fsFleetData{Results: []fsChange{}}
	worst := 0
	var fails []hostFail
	for _, r := range res {
		row := fsChange{}
		if v, ok := r.Value.(fsChange); ok {
			for k, x := range v {
				row[k] = x
			}
		}
		row["host"], row["ok"] = r.Host.Name, r.Err == nil
		if r.Err != nil {
			e := toErr(r.Err)
			row["error"] = e
			worst = worse(worst, e.Exit)
			fails = append(fails, hostFail{host: r.Host.Name, reason: failReason(0, e), err: e})
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, r.Host.Name)
		} else {
			data.Summary.OK++
		}
		data.Results = append(data.Results, row)
	}
	data.Summary.Total = len(res)
	audit(cl, st, name, hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"path": path})
	return data, finishFleet(cl, name, data, runSummary{fleetSummary: data.Summary}, worst, fails)
}

// changedWithBackup is how many servers fs replace changed with a backup
// kept (they can be undone with fs restore).
func (d fsFleetData) changedWithBackup() int {
	n := 0
	for _, r := range d.Results {
		if r["changed"] == true && r["backup"] != nil {
			n++
		}
	}
	return n
}
