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
  komando cluster logs swarm-manager service/web -f`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			t, err := resolveCluster(st, args[0])
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
				return swarmLogs(cmd.Context(), t, svc, limit, since, follow, timestamps)
			}
			if follow && !g.dryRun {
				what := "following logs"
				if len(args) == 2 {
					what += " of " + args[1]
				} else if selector != "" {
					what += " of -l " + selector
				}
				showStatus(statusLine{What: what, Target: t.conn.Name, Route: connRoute(st, t.conn), Protected: protectedConn(st, t.conn), Tail: "Ctrl-C stops"})
			}
			return withKube(ownTimeLimit(cmd.Context(), follow), "cluster.logs", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				space := cmp.Or(ns, k.Namespace)
				ref := selector
				if len(args) == 2 {
					ref = args[1]
				}
				pods, err := logPods(ctx, k, space, ref, selector)
				if err != nil {
					return nil, err
				}
				q := url.Values{"tailLines": {strconv.Itoa(limit)}}
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
					return followPods(ctx, k, space, pods, q)
				}
				res := logText{Namespace: space, Pods: pods}
				if len(args) == 2 && strings.Contains(args[1], "/") || selector != "" {
					res.Object = ref
				}
				if len(pods) == 1 {
					res.Pod = pods[0]
				}
				many := len(pods) > 1
				var sb strings.Builder
				for _, p := range pods {
					b, err := k.Do(ctx, "GET", podLogPath(space, p), q, nil, "")
					if err != nil {
						if many {
							fmt.Fprintf(&sb, "[%s] (no logs: %v)\n", p, err)
							continue
						}
						return nil, err
					}
					if !many {
						res.Logs = string(b)
						return res, nil
					}
					for _, line := range strings.SplitAfter(string(b), "\n") {
						if line != "" {
							sb.WriteString("[" + p + "] " + line)
						}
					}
				}
				res.Logs = sb.String()
				return res, nil
			})
		},
	}
	nsFlags(c, &ns, nil, &limitOpt{&limit, 200, "the most lines per pod (the last ones)"})
	flagAlias(c, "tail", "limit") // kubectl's word: a permanent synonym
	c.Flags().StringVarP(&container, "container", "c", "", "container in the pod")
	c.Flags().StringVar(&since, "since", "", "only newer than this: 10m, 2h, or a time like 2026-01-02T10:00:00Z")
	c.Flags().BoolVar(&previous, "previous", false, "the previous run of a restarted container")
	c.Flags().BoolVar(&timestamps, "timestamps", false, "start each line with its time")
	c.Flags().BoolVarP(&follow, "follow", "f", false, "keep reading new lines (Ctrl-C or --timeout stops)")
	c.Flags().StringVarP(&selector, "selector", "l", "", "read every pod with these labels, e.g. app=api")
	return c
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
		return nil, out.Errf(out.ExitNotFound, "K8S_NOT_FOUND", "check the labels with `komando cluster ls TARGET pods --namespace "+space+"`", "no pods match %s in namespace %s", selector, space)
	}
	if len(pods) > maxLogPods {
		return nil, out.Usage("%d pods match; narrow it to %d or fewer (a tighter -l, or one workload)", len(pods), maxLogPods)
	}
	return pods, nil
}

// followPods streams new lines from every pod until the context ends
// (Ctrl-C or --timeout) or all streams close. Lines are printed as they
// come: plain "[pod] line" for a person, output events in JSON.
func followPods(ctx context.Context, k *kube.Client, space string, pods []string, q url.Values) (any, error) {
	if g.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.timeout)
		defer cancel()
	}
	prefix := func(pod string) string {
		if len(pods) > 1 {
			return "[" + pod + "] "
		}
		return ""
	}
	lines, err := streamPods(ctx, k, space, pods, q, func(pod, line string) { printLogLine(pod, prefix(pod), line) })
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
func printLogLine(pod, prefix, line string) {
	if out.P.Format == "text" {
		fmt.Println(out.SafeText(out.P.Redact(prefix + line)))
		return
	}
	out.P.Event(map[string]any{"event": "output", "pod": pod, "data": line + "\n"})
}
