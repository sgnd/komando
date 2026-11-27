package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

// maxLogPods caps how many pods one `cluster logs` reads at once.
const maxLogPods = 20

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
		return nil, out.Errf(out.ExitNotFound, "K8S_POD_NOT_FOUND", "check the labels with `komando cluster list TARGET pods --namespace "+space+"`", "no pods match %s in namespace %s", selector, space)
	}
	if len(pods) > maxLogPods {
		return nil, out.Usage("%d pods match; narrow it to %d or fewer (a tighter -l, or one workload)", len(pods), maxLogPods)
	}
	return pods, nil
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

// printLogLine prints one followed log line at once to the call's stdout:
// the line for a person, an output event in JSON. Lines of pods (and of
// clusters) followed at the same time never run into each other.
func printLogLine(cl *call, pod, prefix, line string) {
	cl.liveMu.Lock()
	defer cl.liveMu.Unlock()
	if cl.out.Format == "text" {
		if prefix != "" {
			line = out.NoCR(line) // no \r back over the pod's name
		}
		fmt.Fprintln(cl.out.W, out.SafeText(cl.out.Redact(prefix+line)))
		return
	}
	cl.out.Event(map[string]any{"event": "output", "pod": pod, "data": line + "\n"})
}
