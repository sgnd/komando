package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Read commands (status, ls, events, helm ls) work on every cluster a
// selector picks (@prod, kind:k8s, all): one row per cluster in
// data.results, read at the same time. With one cluster the output is
// that cluster alone, not a list. Commands that change a cluster stay
// one cluster at a time.

// clusterRead is what a read command does on one cluster of each engine;
// a nil func means that engine has no such view, and swarmNo says why.
type clusterRead struct {
	kube    func(ctx context.Context, t clusterTarget, k *kube.Client) (any, error)
	swarm   func(ctx context.Context, t clusterTarget) (any, error)
	swarmNo string
}

type clusterRow struct {
	Cluster string     `json:"cluster"`
	Engine  string     `json:"engine"` // k8s | swarm
	OK      bool       `json:"ok"`
	Data    any        `json:"data,omitempty"`
	Error   *out.Error `json:"error,omitempty"`
}

type clusterSummary struct {
	Total          int      `json:"total"`
	OK             int      `json:"ok"`
	Failed         int      `json:"failed"`
	FailedClusters []string `json:"failed_clusters,omitempty"`
}

type clusterMany struct {
	Results []clusterRow   `json:"results"`
	Summary clusterSummary `json:"summary"`
}

// Text is one block per cluster, each in its own view.
func (m clusterMany) Text() string {
	var b strings.Builder
	for _, r := range m.Results {
		state := "ok"
		if !r.OK {
			state = "failed"
		}
		fmt.Fprintf(&b, "● %s (%s)  %s\n", r.Cluster, r.Engine, state)
		switch {
		case r.Error != nil:
			b.WriteString(block(r.Error.Code + ": " + r.Error.Message))
			if r.Error.Hint != "" {
				b.WriteString(block("Hint: " + r.Error.Hint))
			}
		case r.Data != nil:
			if t, ok := r.Data.(out.Texter); ok {
				b.WriteString(block(t.Text()))
			} else if j, err := json.MarshalIndent(r.Data, "", "  "); err == nil {
				b.WriteString(block(string(j)))
			}
		}
	}
	fmt.Fprintf(&b, "\n%d ok, %d failed\n", m.Summary.OK, m.Summary.Failed)
	return b.String()
}

// block indents s under a cluster's line, ending in one newline.
func block(s string) string {
	if s = strings.TrimRight(s, "\n"); s == "" {
		return ""
	}
	return indentText(s+"\n", "  ")
}

func (t clusterTarget) name() string {
	if t.conn != nil {
		return t.conn.Name
	}
	return t.host.Name
}

func (t clusterTarget) engine() string {
	if t.conn != nil {
		return "k8s"
	}
	return "swarm"
}

// resolveClusters is resolveCluster for read commands: every Kubernetes
// conn and Swarm manager the selector picks, in its order.
func resolveClusters(st *store.State, expr string) ([]clusterTarget, error) {
	sel, err := resolveSelection(st, expr)
	if err != nil {
		return nil, err
	}
	var ts []clusterTarget
	for _, c := range sel.Conns {
		if connFamily(c) == "cluster" {
			ts = append(ts, clusterTarget{conn: c})
		} else {
			out.P.Skip(out.Skipped{Name: c.Name, Kind: c.Kind, Reason: useFor(nil, c)})
		}
	}
	for _, h := range sel.Hosts {
		if len(sel.Hosts) == 1 && len(ts) == 0 || swarmManager(expr, h) {
			ts = append(ts, clusterTarget{host: h})
		} else {
			out.P.Skip(out.Skipped{Name: h.Name, Kind: "host", Reason: "a server: name it, or tag it swarm (`komando host edit " + h.Name + " --add-tag swarm`), to read it as a Swarm manager"})
		}
	}
	if len(ts) == 0 {
		return nil, noMatch(expr, "clusters (a k8s conn, or a Swarm manager server)", sel)
	}
	return ts, nil
}

// swarmManager: a server a selector of several targets picks (all,
// @group) is read as a Swarm manager only when it is tagged swarm or named
// in the selector itself; otherwise every web server in @prod would be
// asked for a swarm it does not run.
func swarmManager(expr string, h *store.Host) bool {
	if slices.Contains(h.Tags, "swarm") {
		return true
	}
	for _, part := range strings.Split(expr, ",") {
		if strings.TrimSpace(part) == h.Name {
			return true
		}
	}
	return false
}

// readClusters runs r on each cluster. One cluster prints its own
// result; several print a row each and fail softly when some fail.
func readClusters(ctx context.Context, name string, st *store.State, ts []clusterTarget, r clusterRead) error {
	if len(ts) == 1 {
		t := ts[0]
		if t.host != nil {
			if r.swarm == nil {
				return out.Usage("%s", r.swarmNo)
			}
			res, err := r.swarm(ctx, t)
			if err != nil {
				return err
			}
			out.P.Print(name, res, nil)
			return nil
		}
		return withKube(ctx, name, t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
			return r.kube(ctx, t, k)
		})
	}
	rows := make([]clusterRow, len(ts))
	sem := make(chan struct{}, max(1, parallelism(st)))
	var wg sync.WaitGroup
	for i, t := range ts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rows[i] = readOne(ctx, st, t, r)
		}()
	}
	wg.Wait()
	m := clusterMany{Results: rows, Summary: clusterSummary{Total: len(rows)}}
	worst := 0
	for _, row := range rows {
		if row.OK {
			m.Summary.OK++
			continue
		}
		m.Summary.Failed++
		m.Summary.FailedClusters = append(m.Summary.FailedClusters, row.Cluster)
		worst = worse(worst, row.Error.Exit)
	}
	var soft *out.Error
	if m.Summary.Failed > 0 {
		soft = &out.Error{Code: "PARTIAL_FAILURE", Exit: worst,
			Message: failedOf(m.Summary.Failed, m.Summary.Total) + ": " + strings.Join(m.Summary.FailedClusters, ", "),
			Hint:    "see each cluster's error in data.results"}
	}
	out.P.Print(name, m, soft)
	if soft != nil {
		return exitCode(worst)
	}
	return nil
}

// readOne is one cluster's row of readClusters.
func readOne(ctx context.Context, st *store.State, t clusterTarget, r clusterRead) clusterRow {
	row := clusterRow{Cluster: t.name(), Engine: t.engine()}
	ctx, cancel := kubeDeadline(ctx, st)
	defer cancel()
	var v any
	var err error
	switch {
	case t.host != nil && r.swarm == nil:
		err = out.Usage("%s", r.swarmNo)
	case t.host != nil:
		v, err = r.swarm(ctx, t)
	default:
		var k *kube.Client
		var done func()
		k, done, err = kubeClient(ctx, st, t.conn)
		if errors.Is(err, errDryRunStopped) {
			row.OK, row.Data = true, map[string]any{"dry_run": true}
			return row
		}
		if err == nil {
			v, err = r.kube(ctx, t, k)
			done()
		}
		if err != nil {
			err = kubeErr(err)
		}
	}
	if err != nil {
		row.Error = toErr(err)
		return row
	}
	row.OK, row.Data = true, v
	return row
}
