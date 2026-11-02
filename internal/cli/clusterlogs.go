package cli

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// maxLogPods caps how many pods one `cluster logs` reads at once.
const maxLogPods = 20

func clusterLogsCmd() *cobra.Command {
	var ns, container, since, selector string
	var limit int
	var previous, follow bool
	c := &cobra.Command{
		Use:   "logs TARGET [POD|TYPE/NAME]",
		Short: "Logs of a pod, of every pod of a workload or label (-l), or of a Swarm service; -f follows",
		Long: `Name a pod, a workload (deploy/api, statefulset/db, svc/web: all its pods)
or pick pods by label with -l. Lines from several pods start with [pod].
-f keeps reading until Ctrl-C or --timeout; it follows the pods that exist
when it starts.`,
		Example: `  komando cluster logs prod-k8s api-7d9f-x2 --namespace shop --since 10m
  komando cluster logs prod-k8s deploy/api --namespace shop -f
  komando cluster logs prod-k8s -l app=api --namespace shop -n 50
  komando cluster logs swarm-manager web -f`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && selector == "" {
				return out.Usage("name a pod or TYPE/NAME, or pick pods with -l")
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
				if len(args) == 1 {
					return out.Usage("on Swarm, name the service")
				}
				_, svc, _ := strings.Cut(args[1], "/")
				if svc == "" {
					svc = args[1]
				}
				c := "docker service logs --no-trunc --timestamps --tail " + strconv.Itoa(limit)
				if since != "" {
					c += " --since " + sshx.Q(since)
				}
				if follow {
					return followLogs(cmd.Context(), t.host.Name, c+" -f "+sshx.Q(svc)+" 2>&1", false)
				}
				return runOne(cmd.Context(), "cluster.logs", t.host.Name, c+" "+sshx.Q(svc)+" 2>&1", false, false)
			}
			return withKube(cmd.Context(), "cluster.logs", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				space := firstNonEmpty(ns, k.Namespace)
				ref := selector
				if len(args) == 2 {
					ref = args[1]
				}
				pods, err := logPods(ctx, k, space, ref, selector)
				if err != nil {
					return nil, err
				}
				q := url.Values{"timestamps": {"true"}, "tailLines": {strconv.Itoa(limit)}}
				if follow && !cmd.Flags().Changed("limit") {
					q.Set("tailLines", "10") // like tail -f: a little context, then new lines
				}
				if container != "" {
					q.Set("container", container)
				}
				if previous {
					q.Set("previous", "true")
				}
				if since != "" {
					d, err := time.ParseDuration(strings.TrimPrefix(since, "-"))
					if err != nil {
						return nil, out.Usage("--since takes a duration like 10m or 2h")
					}
					q.Set("sinceSeconds", strconv.Itoa(int(d.Seconds())))
				}
				if follow {
					return followPods(ctx, k, space, pods, q)
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
						return logText{Pod: p, Namespace: space, Logs: string(b)}, nil
					}
					for _, line := range strings.SplitAfter(string(b), "\n") {
						if line != "" {
							sb.WriteString("[" + p + "] " + line)
						}
					}
				}
				return logText{Pod: ref, Namespace: space, Logs: sb.String(), Pods: pods}, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	c.Flags().StringVarP(&container, "container", "c", "", "container in the pod")
	c.Flags().StringVar(&since, "since", "", "only newer than this, e.g. 10m")
	c.Flags().IntVarP(&limit, "limit", "n", 200, "max lines per pod (from the end)")
	c.Flags().BoolVar(&previous, "previous", false, "the previous run of a restarted container")
	c.Flags().BoolVarP(&follow, "follow", "f", false, "keep reading new lines (Ctrl-C or --timeout stops)")
	c.Flags().StringVarP(&selector, "selector", "l", "", "read every pod with these labels, e.g. app=api")
	return c
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
		r, err := k.Resource(ctx, typ)
		if err != nil {
			return nil, out.Usage("%v", err)
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
	q.Set("follow", "true")
	var mu sync.Mutex
	var wg sync.WaitGroup
	lines := 0
	for _, p := range pods {
		body, err := k.Stream(ctx, podLogPath(space, p), q)
		if err != nil {
			return nil, err
		}
		wg.Add(1)
		go func(pod string) {
			defer wg.Done()
			defer body.Close()
			sc := bufio.NewScanner(body)
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				mu.Lock()
				lines++
				if out.P.Format == "text" {
					line := sc.Text()
					if len(pods) > 1 {
						line = "[" + pod + "] " + line
					}
					fmt.Println(out.P.Redact(line))
				} else {
					out.P.Event(map[string]any{"event": "output", "pod": pod, "data": sc.Text() + "\n"})
				}
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return map[string]any{"namespace": space, "pods": pods, "lines": lines, "followed": true}, nil
}
