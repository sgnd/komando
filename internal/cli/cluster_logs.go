package cli

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

// maxLogPods caps how many pods one `cluster logs` reads at once.
const maxLogPods = 20

func clusterLogsCmd() *cobra.Command {
	var ns, container, since, selector string
	var limit int
	var previous, follow, timestamps bool
	c := &cobra.Command{
		Use:   "logs TARGET [POD|TYPE/NAME]",
		Short: "Logs of a pod, a workload, a label (-l) or a Swarm service",
		Long: `Name a pod, a workload (deploy/api, statefulset/db, svc/web: all its pods)
or pick pods by label with -l. Lines from several pods start with [pod].
-f keeps reading until Ctrl-C or --timeout (both end it normally); it follows
the pods that exist when it starts. --since takes a duration back from now
(10m, 2h) or a time (2026-01-02T10:00:00Z).`,
		Example: `  komando cluster logs prod-k8s api-7d9f-x2 --namespace shop --since 10m
  komando cluster logs prod-k8s deploy/api --namespace shop -f
  komando cluster logs prod-k8s -l app=api --namespace shop --limit 50
  komando cluster logs swarm1 service/web -f`,
		Args: cobra.RangeArgs(1, 2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if len(args) == 1 && selector == "" {
				return out.Usage("name a pod or TYPE/NAME, or pick pods with -l")
			}
			sinceQ, err := sinceParam(since)
			if err != nil {
				return err
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(cl, st, args[0])
			if err != nil {
				return err
			}
			if t.host != nil {
				if err := noNamespace(t, ns); err != nil {
					return err
				}
				if len(args) == 1 {
					return out.Usage("on Swarm, name the service")
				}
				svc := args[1]
				if typ, n, ok := strings.Cut(args[1], "/"); ok {
					if swarmKind(typ) != "service" {
						return out.Usage("on Swarm, logs are read per service (service/NAME)")
					}
					svc = n
				}
				return swarmLogs(cl, cmd.Context(), t, svc, limit, since, follow, timestamps)
			}
			if follow && !cl.flags.dryRun {
				what := "following logs"
				if len(args) == 2 {
					what += " of " + args[1]
				} else if selector != "" {
					what += " of -l " + selector
				}
				showStatus(cl, statusLine{What: what, Target: t.conn.Name, Route: connRoute(st, t.conn), Protected: protectedConn(st, t.conn), Tail: "Ctrl-C stops"})
			}
			return withKube(cl, ownTimeLimit(cmd.Context(), follow), "cluster.logs", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				space := cmp.Or(ns, k.Namespace)
				ref := selector
				if len(args) == 2 {
					ref = args[1]
				}
				pods, err := logPods(ctx, k, space, ref, selector)
				if err != nil {
					return nil, err
				}
				q := url.Values{}
				if limit > 0 { // --limit 0 is every line
					q.Set("tailLines", strconv.Itoa(limit))
				}
				if timestamps {
					q.Set("timestamps", "true")
				}
				if follow && !flagChanged(cmd, "limit") {
					q.Set("tailLines", "10") // like tail -f: a little context, then new lines
				}
				if container != "" {
					q.Set("container", container)
				}
				if previous {
					q.Set("previous", "true")
				}
				for k, v := range sinceQ {
					q[k] = v
				}
				if follow {
					return followPods(cl, ctx, k, space, pods, q)
				}
				res := logText{Namespace: space, Pods: pods}
				if len(args) == 2 && strings.Contains(args[1], "/") || selector != "" {
					res.Object = ref
				}
				return readLogs(cl, ctx, k, res, q, container, limit, timestamps)
			})
		}),
	}
	nsFlags(c, &ns, nil, &limitOpt{&limit, 200, "the most lines per pod (the last ones)"})
	flagAlias(c, "tail", "limit") // kubectl's word: a permanent synonym
	clusterLogFlags(c.Flags(), &container, &since, &selector, &previous, &timestamps, &follow)
	return c
}

// readLogs reads the logs of res.Pods once (no -f): the text, and in JSON
// each line with its time and container.
func readLogs(cl *call, ctx context.Context, k *kube.Client, res logText, q url.Values, container string, limit int, timestamps bool) (any, error) {
	pods, space := res.Pods, res.Namespace
	if len(pods) == 1 {
		res.Pod = pods[0]
	}
	// JSON gets each line on its own, with its time: ask the
	// API for times, and keep them in logs only when asked
	lined := cl.out.Format != "text"
	if lined {
		q.Set("timestamps", "true")
		res.Lines = []logLine{}
	}
	many := len(pods) > 1
	var sb strings.Builder
	for _, p := range pods {
		b, err := k.Do(ctx, "GET", podLogPath(space, p), q, nil, "")
		if err != nil {
			if many {
				fmt.Fprintf(&sb, "[%s] (no logs: %v)\n", p, err)
				if lined {
					res.Lines = append(res.Lines, logLine{Pod: p, Container: container, Text: fmt.Sprintf("(no logs: %v)", err)})
				}
				continue
			}
			return nil, err
		}
		text := string(b)
		if lined {
			var ls []logLine
			ls, text = splitLogLines(text, p, logContainer(ctx, k, space, p, container), timestamps)
			res.Lines = append(res.Lines, ls...)
			if limit > 0 && len(ls) >= limit {
				res.Truncated = true // the pod may have older lines
				cl.out.CutNoted()
			}
		}
		if !many {
			res.Logs = text
			return res, nil
		}
		for _, line := range strings.SplitAfter(text, "\n") {
			if line != "" {
				sb.WriteString("[" + p + "] " + out.NoCR(line)) // no \r back over the name
			}
		}
	}
	res.Logs = sb.String()
	return res, nil
}

// splitLogLines splits what the API sent with timestamps=true into lines
// with their times, and gives back the text as the user asked for it:
// with the times only under --timestamps.
func splitLogLines(raw, pod, container string, timestamps bool) ([]logLine, string) {
	if raw == "" {
		return nil, ""
	}
	var lines []logLine
	var b strings.Builder
	for _, line := range strings.SplitAfter(raw, "\n") {
		if line == "" {
			continue
		}
		body := strings.TrimSuffix(line, "\n")
		at, text := "", body
		if ts, rest, ok := strings.Cut(body, " "); ok {
			if _, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				at, text = ts, rest
			}
		}
		lines = append(lines, logLine{LoggedAt: at, Pod: pod, Container: container, Text: text})
		if timestamps {
			b.WriteString(line)
		} else {
			b.WriteString(text + line[len(body):])
		}
	}
	return lines, b.String()
}

// logContainer is the container whose logs were read: the one named with
// -c, else the pod's only container ("" when that cannot be read).
func logContainer(ctx context.Context, k *kube.Client, space, pod, named string) string {
	if named != "" {
		return named
	}
	var o map[string]any
	if k.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(space)+"/pods/"+url.PathEscape(pod), nil, &o) != nil {
		return ""
	}
	spec, _ := o["spec"].(map[string]any)
	if cs, _ := spec["containers"].([]any); len(cs) == 1 {
		c, _ := cs[0].(map[string]any)
		return str(c["name"])
	}
	return ""
}

// clusterLogFlags are cluster logs' own flags.
func clusterLogFlags(f *pflag.FlagSet, container, since, selector *string, previous, timestamps, follow *bool) {
	f.StringVarP(container, "container", "c", "", "container in the pod")
	f.StringVar(since, "since", "", "only newer than this: 10m, 2h, or a time like 2026-01-02T10:00:00Z")
	f.BoolVar(previous, "previous", false, "the previous run of a restarted container")
	f.BoolVar(timestamps, "timestamps", false, "start each line with its time")
	f.BoolVarP(follow, "follow", "f", false, "keep reading new lines (Ctrl-C or --timeout stops)")
	f.StringVarP(selector, "selector", "l", "", "read every pod with these labels, like app=api")
}

// sinceParam turns --since into the API's sinceSeconds or sinceTime.
func sinceParam(since string) (url.Values, error) {
	if since == "" {
		return nil, nil
	}
	if d, err := time.ParseDuration(strings.TrimPrefix(since, "-")); err == nil {
		return url.Values{"sinceSeconds": {strconv.Itoa(max(1, int(d.Seconds())))}}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, since, time.Local); err == nil {
			return url.Values{"sinceTime": {t.UTC().Format(time.RFC3339)}}, nil
		}
	}
	return nil, out.Usage("--since takes a duration like 10m or 2h, or a time like 2026-01-02T10:00:00Z")
}

func podLogPath(space, pod string) string {
	return "/api/v1/namespaces/" + url.PathEscape(space) + "/pods/" + url.PathEscape(pod) + "/log"
}

// logPods turns what the user named into pod names: a pod, a workload or
// service (its selector), or a label selector.
func logPods(ctx context.Context, k *kube.Client, space, ref, selector string) ([]string, error) {
	if selector == "" {
		typ, name, isRef := strings.Cut(ref, "/")
		if !isRef {
			return []string{ref}, nil // a pod name
		}
		r, err := resource(ctx, k, typ)
		if err != nil {
			return nil, err
		}
		if r.KindName() == "Pod" {
			return []string{name}, nil
		}
		var o map[string]any
		if err := k.Get(ctx, r.ObjectPath(space, name), nil, &o); err != nil {
			return nil, err
		}
		o["kind"] = r.KindName()
		if selector = matchLabels(o); selector == "" {
			return nil, out.Usage("%s has no pod selector", ref)
		}
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := k.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(space)+"/pods", url.Values{"labelSelector": {selector}}, &list); err != nil {
		return nil, err
	}
	var pods []string
	for _, p := range list.Items {
		pods = append(pods, str(p["metadata"].(map[string]any)["name"]))
	}
	if len(pods) == 0 {
		return nil, out.Errf(out.ExitNotFound, "K8S_NOT_FOUND", "check the labels with `komando cluster list TARGET pods --namespace "+space+"`", "no pods match %s in namespace %s", selector, space).About("k8s_pod")
	}
	if len(pods) > maxLogPods {
		return nil, out.Usage("%d pods match; narrow it to %d or fewer (a tighter -l, or one workload)", len(pods), maxLogPods)
	}
	return pods, nil
}

// followPods streams new lines from every pod until the context ends
// (Ctrl-C or --timeout) or all streams close. Lines are printed as they
// come: plain "[pod] line" for a person, output events in JSON.
func followPods(cl *call, ctx context.Context, k *kube.Client, space string, pods []string, q url.Values) (any, error) {
	if cl.flags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cl.flags.timeout)
		defer cancel()
	}
	prefix := func(pod string) string {
		if len(pods) > 1 {
			return "[" + pod + "] "
		}
		return ""
	}
	lines, err := streamPods(ctx, k, space, pods, q, func(pod, line string) { printLogLine(cl, pod, prefix(pod), line) })
	if err != nil {
		return nil, err
	}
	return map[string]any{"namespace": space, "pods": pods, "lines": lines, "followed": true}, nil
}

// streamPods follows the logs of pods at once and calls emit with each
// line as it comes, one call at a time, until the context ends or every
// stream closes. A pod whose stream does not open is noted, as when logs
// are read without -f, while the others go on; when none opens, that is
// the error. It returns only after every stream stopped, so no line comes
// after the result.
func streamPods(ctx context.Context, k *kube.Client, space string, pods []string, q url.Values, emit func(pod, line string)) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	q.Set("follow", "true")
	var mu sync.Mutex
	var wg sync.WaitGroup
	lines, opened := 0, 0
	var failed error
	for _, p := range pods {
		body, err := k.Stream(ctx, podLogPath(space, p), q)
		if err != nil {
			if failed == nil {
				failed = err
			}
			if len(pods) > 1 && ctx.Err() == nil {
				mu.Lock()
				emit(p, fmt.Sprintf("(no logs: %v)", err))
				mu.Unlock()
			}
			continue
		}
		opened++
		wg.Add(1)
		go func(pod string, body io.ReadCloser) {
			defer wg.Done()
			defer body.Close()
			sc := bufio.NewScanner(body)
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				mu.Lock()
				lines++
				emit(pod, sc.Text())
				mu.Unlock()
			}
		}(p, body)
	}
	if opened == 0 {
		return 0, failed
	}
	wg.Wait()
	return lines, nil
}

// printLogLine prints one followed log line at once: the line for a
// person, an output event in JSON.
func printLogLine(cl *call, pod, prefix, line string) {
	if cl.out.Format == "text" {
		if prefix != "" {
			line = out.NoCR(line) // no \r back over the pod's name
		}
		fmt.Println(out.SafeText(cl.out.Redact(prefix + line)))
		return
	}
	cl.out.Event(map[string]any{"event": "output", "pod": pod, "data": line + "\n"})
}
