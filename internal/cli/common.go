package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func loadState() (*store.State, error) { return store.Load() }

func dur(flag time.Duration, setting string, def time.Duration) time.Duration {
	if flag > 0 {
		return flag
	}
	if d, err := time.ParseDuration(setting); err == nil && d > 0 {
		return d
	}
	return def
}

func cmdTimeout(st *store.State) time.Duration {
	return dur(g.timeout, st.Settings.DefaultTimeout, 5*time.Minute)
}

func sshOpts(st *store.State) sshx.Options {
	p := g.hostKeyPolicy
	if p == "" {
		p = st.Settings.HostKeyPolicy
	}
	return sshx.Options{ConnectTimeout: dur(g.connectTimeout, st.Settings.ConnectTimeout, 15*time.Second), HostKeyPolicy: p}
}

func maxOutput(st *store.State) int {
	if g.maxOutput > 0 {
		return g.maxOutput
	}
	return st.Settings.MaxOutputBytes
}

func parallelism(st *store.State) int {
	if g.parallel > 0 {
		return g.parallel
	}
	return st.Settings.Parallel
}

// resolveTargets expands a selector expression into hosts (sorted, unique).
func resolveTargets(st *store.State, expr string) ([]*store.Host, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, out.Usage("empty target")
	}
	include := map[string]*store.Host{}
	exclude := map[string]bool{}
	for _, raw := range strings.Split(expr, ",") {
		sel := strings.TrimSpace(raw)
		if sel == "" {
			continue
		}
		neg := strings.HasPrefix(sel, "!")
		sel = strings.TrimPrefix(sel, "!")
		matched, err := matchSelector(st, sel)
		if err != nil {
			return nil, err
		}
		for _, h := range matched {
			if neg {
				exclude[h.Name] = true
			} else {
				include[h.Name] = h
			}
		}
	}
	var hosts []*store.Host
	for n, h := range include {
		if !exclude[n] {
			hosts = append(hosts, h)
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	if len(hosts) == 0 {
		return nil, out.Errf(out.ExitNotFound, "TARGET_EMPTY", "run `komando host list` to see hosts, groups and tags", "target %q matched no hosts", expr)
	}
	return hosts, nil
}

func matchSelector(st *store.State, sel string) ([]*store.Host, error) {
	var res []*store.Host
	each := func(f func(h *store.Host) bool) []*store.Host {
		for _, h := range st.SortedHosts() {
			if f(h) {
				res = append(res, h)
			}
		}
		return res
	}
	switch {
	case sel == "all" || sel == "*":
		return each(func(*store.Host) bool { return true }), nil
	case strings.HasPrefix(sel, "@"):
		g := sel[1:]
		return each(func(h *store.Host) bool { return h.InGroup(g) }), nil
	case strings.HasPrefix(sel, "tag:"):
		t := sel[4:]
		return each(func(h *store.Host) bool { return h.HasTag(t) }), nil
	case strings.HasPrefix(sel, "label:"):
		k, v, _ := strings.Cut(sel[6:], "=")
		return each(func(h *store.Host) bool { return h.Labels[k] == v }), nil
	case strings.ContainsAny(sel, "*?["):
		return each(func(h *store.Host) bool { ok, _ := path.Match(sel, h.Name); return ok }), nil
	}
	if h, ok := st.Hosts[sel]; ok {
		return []*store.Host{h}, nil
	}
	if strings.Contains(sel, "@") {
		h, err := sshx.ParseAdhoc(sel)
		if err == nil {
			return []*store.Host{h}, nil
		}
	}
	return nil, out.NotFound("host", sel)
}

// singleHost resolves a selector that must match exactly one host.
func singleHost(st *store.State, expr string) (*store.Host, error) {
	hs, err := resolveTargets(st, expr)
	if err != nil {
		return nil, err
	}
	if len(hs) != 1 {
		return nil, out.Usage("target %q matched %d hosts; this command needs exactly one", expr, len(hs))
	}
	return hs[0], nil
}

func toErr(err error) *out.Error {
	if err == nil {
		return nil
	}
	var e *out.Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &out.Error{Code: "TIMEOUT", Message: err.Error(), Exit: out.ExitTimeout}
	}
	if errors.Is(err, context.Canceled) {
		return &out.Error{Code: "CANCELLED", Message: "interrupted", Exit: out.ExitError}
	}
	return &out.Error{Code: "REMOTE_ERROR", Message: err.Error(), Exit: out.ExitError}
}

type outcome struct {
	Host  *store.Host
	Value any
	Err   error
}

// fanout dials each host (parallel, bounded) and runs fn on it.
func fanout(ctx context.Context, st *store.State, hosts []*store.Host, fn func(ctx context.Context, c *sshx.Client) (any, error)) []outcome {
	res := make([]outcome, len(hosts))
	sem := make(chan struct{}, max(1, parallelism(st)))
	var wg sync.WaitGroup
	opts := sshOpts(st)
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h *store.Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res[i].Host = h
			c, err := sshx.Dial(ctx, st, h, opts)
			if err != nil {
				res[i].Err = err
				return
			}
			defer c.Close()
			res[i].Value, res[i].Err = fn(ctx, c)
		}(i, h)
	}
	wg.Wait()
	return res
}

func withClient(ctx context.Context, st *store.State, h *store.Host, fn func(c *sshx.Client) error) error {
	c, err := sshx.Dial(ctx, st, h, sshOpts(st))
	if err != nil {
		return err
	}
	defer c.Close()
	return fn(c)
}

// guard enforces the safety policy before anything mutating runs.
func guard(st *store.State, hosts []*store.Host, command string, mutating bool) error {
	if command != "" {
		if hits := policy.Check(command, st.Settings.ExtraDenyPattern); len(hits) > 0 && !g.allowDangerous {
			ids := make([]string, len(hits))
			reasons := make([]string, len(hits))
			for i, h := range hits {
				ids[i], reasons[i] = h.ID, h.Reason
			}
			return out.Errf(out.ExitPolicy, "POLICY_BLOCKED",
				"if this is truly intended, confirm with the user and re-run with --allow-dangerous (try --dry-run first)",
				"command matches destructive rules [%s]: %s", strings.Join(ids, ","), strings.Join(reasons, "; "))
		}
	}
	if mutating && !g.yes {
		var prot []string
		for _, h := range hosts {
			if h.Protected {
				prot = append(prot, h.Name)
			}
		}
		if len(prot) > 0 {
			return out.Errf(out.ExitPolicy, "PROTECTED_HOST",
				"protected hosts require explicit confirmation: re-run with --yes after verifying intent",
				"mutating action targets protected host(s): %s", strings.Join(prot, ", "))
		}
	}
	return nil
}

func hostNames(hs []*store.Host) []string {
	n := make([]string, len(hs))
	for i, h := range hs {
		n[i] = h.Name
	}
	return n
}

// audit appends one JSON line per action to $KOMANDO_HOME/audit.jsonl.
func audit(st *store.State, command string, hosts []string, remote string, ok bool, extra map[string]any) {
	if st != nil && !st.Settings.Audit {
		return
	}
	rec := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"command": command,
		"hosts":   hosts,
		"ok":      ok,
		"dry_run": g.dryRun,
		"actor":   actor(),
	}
	if remote != "" {
		rec["remote"] = remote
	}
	for k, v := range extra {
		rec[k] = v
	}
	b, _ := json.Marshal(rec)
	f, err := os.OpenFile(store.Path("audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

func actor() string {
	if a := os.Getenv("KOMANDO_ACTOR"); a != "" {
		return a
	}
	return os.Getenv("USER")
}

// fleetSummary is attached to every multi-host result.
type fleetSummary struct {
	Total       int      `json:"total"`
	OK          int      `json:"ok"`
	Failed      int      `json:"failed"`
	FailedHosts []string `json:"failed_hosts,omitempty"`
}

// finish prints a multi-host result and converts failures into an exit code.
func finish(command string, data any, sum fleetSummary, worstExit int) error {
	var soft *out.Error
	if sum.Failed > 0 {
		soft = &out.Error{Code: "PARTIAL_FAILURE", Message: fmt.Sprintf("%d of %d host(s) failed: %s", sum.Failed, sum.Total, strings.Join(sum.FailedHosts, ", ")),
			Hint: "see the per-host results (data.results) for exit codes and stderr", Exit: worstExit}
		if sum.Total == 1 {
			soft.Code = "FAILED"
			soft.Message = "host " + sum.FailedHosts[0] + " failed"
		}
	}
	out.P.Print(command, data, soft)
	if soft != nil {
		return exitCode(worstExit)
	}
	return nil
}

func worse(a, b int) int {
	rank := func(x int) int {
		switch x {
		case out.ExitConnect:
			return 5
		case out.ExitTimeout:
			return 4
		case out.ExitRemote:
			return 3
		case 0:
			return 0
		}
		return 2
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func readStdinIfPiped() ([]byte, error) {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice != 0 {
		return nil, nil
	}
	b, err := io.ReadAll(os.Stdin)
	return b, err
}

func parseKV(pairs []string) (map[string]string, error) {
	m := map[string]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, out.Usage("expected KEY=VALUE, got %q", p)
		}
		m[k] = v
	}
	return m, nil
}

func parseDur(s string) (time.Duration, error) { return time.ParseDuration(s) }

func checkRegex(s string) error {
	_, err := regexp.Compile(s)
	return err
}
