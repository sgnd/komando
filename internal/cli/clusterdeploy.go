package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// The deploy cycle: put out a new image, watch the rollout, and go back.
// Kubernetes is called through its API; Swarm runs docker on the manager.

const revisionKey = "deployment.kubernetes.io/revision"

// rolloutState reads whether a workload finished rolling out. failed is
// set when Kubernetes gave up (progressDeadlineSeconds passed).
func rolloutState(kind string, o map[string]any) (done bool, msg string, failed bool) {
	m, _ := o["metadata"].(map[string]any)
	spec, _ := o["spec"].(map[string]any)
	st, _ := o["status"].(map[string]any)
	num := func(v any) int { f, _ := v.(float64); return int(f) }
	if num(st["observedGeneration"]) < num(m["generation"]) {
		return false, "waiting for the controller to see the change", false
	}
	switch kind {
	case "Deployment":
		for _, c := range conditions(st) {
			if c["type"] == "Progressing" && c["reason"] == "ProgressDeadlineExceeded" {
				return false, str(c["message"]), true
			}
		}
		want := 1
		if r, ok := spec["replicas"]; ok {
			want = num(r)
		}
		upd, avail, total := num(st["updatedReplicas"]), num(st["availableReplicas"]), num(st["replicas"])
		switch {
		case upd < want:
			return false, fmt.Sprintf("%d of %d replicas updated", upd, want), false
		case total > upd:
			return false, fmt.Sprintf("%d old replicas still running", total-upd), false
		case avail < upd:
			return false, fmt.Sprintf("%d of %d updated replicas available", avail, upd), false
		}
		return true, fmt.Sprintf("%d of %d replicas updated and available", upd, want), false
	case "StatefulSet":
		want := num(spec["replicas"])
		if str(st["updateRevision"]) != "" && st["updateRevision"] != st["currentRevision"] {
			return false, fmt.Sprintf("%d of %d replicas updated", num(st["updatedReplicas"]), want), false
		}
		if num(st["readyReplicas"]) < want {
			return false, fmt.Sprintf("%d of %d replicas ready", num(st["readyReplicas"]), want), false
		}
		return true, fmt.Sprintf("%d replicas ready", want), false
	case "DaemonSet":
		want := num(st["desiredNumberScheduled"])
		if num(st["updatedNumberScheduled"]) < want || num(st["numberAvailable"]) < want {
			return false, fmt.Sprintf("%d of %d pods updated, %d available", num(st["updatedNumberScheduled"]), want, num(st["numberAvailable"])), false
		}
		return true, fmt.Sprintf("%d pods updated and available", want), false
	}
	return true, "", false
}

// waitRollout polls a workload until it is rolled out, fails, or the time
// is up.
func waitRollout(ctx context.Context, k *kube.Client, r kube.ResourceType, space, name string, wait time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(wait)
	for {
		var o map[string]any
		if err := k.Get(ctx, r.ObjectPath(space, name), nil, &o); err != nil {
			return nil, err
		}
		done, msg, failed := rolloutState(r.KindName(), o)
		res := map[string]any{"object": strings.ToLower(r.KindName()) + "/" + name, "namespace": space, "rolled_out": done, "status": msg}
		if failed {
			return res, out.Errf(out.ExitRemote, "ROLLOUT_FAILED", "see why with `komando cluster describe` and go back with `komando cluster rollback`", "%s", msg)
		}
		if done || wait <= 0 {
			return res, nil
		}
		if time.Now().After(deadline) {
			return res, out.Errf(out.ExitTimeout, "ROLLOUT_TIMEOUT", "check `komando cluster describe` for stuck pods; `komando cluster rollback` goes back", "not rolled out after %s: %s", wait, msg)
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// swarmWait polls a Swarm service until its update is finished and all
// replicas run. It returns the last state it saw.
func swarmWait(ctx context.Context, t clusterTarget, service string, wait time.Duration) (map[string]any, error) {
	st, err := loadState()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	cmd := `docker service inspect ` + sshx.Q(service) + ` --format '{{json .UpdateStatus}}' && docker service ls --filter ` + sshx.Q("name="+service) + ` --format '{{.Name}} {{.Replicas}}'`
	for {
		var outText string
		err := withClient(ctx, st, t.host, func(c *sshx.Client) error {
			var code int
			var err error
			outText, code, err = sshx.Output(ctx, c, cmd, 30*time.Second)
			if err == nil && code != 0 {
				err = out.Errf(out.ExitRemote, "SWARM_ERROR", "", "%s", outText)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.TrimSpace(outText), "\n")
		var upd struct {
			State   string `json:"State"`
			Message string `json:"Message"`
		}
		_ = json.Unmarshal([]byte(lines[0]), &upd)
		replicas := ""
		for _, l := range lines[1:] {
			if f := strings.Fields(l); len(f) == 2 && f[0] == service {
				replicas = f[1]
			}
		}
		running, want, _ := strings.Cut(strings.Fields(replicas + " ")[0], "/")
		done := (upd.State == "" || upd.State == "completed" || upd.State == "rollback_completed") && running == want && running != ""
		res := map[string]any{"object": "service/" + service, "rolled_out": done, "update_state": upd.State, "replicas": replicas, "status": upd.Message}
		if strings.HasPrefix(upd.State, "rollback") && upd.State != "rollback_completed" || upd.State == "paused" {
			return res, out.Errf(out.ExitRemote, "ROLLOUT_FAILED", "see the tasks with `komando cluster describe TARGET service "+service+"`", "update %s: %s", upd.State, upd.Message)
		}
		if done || wait <= 0 {
			return res, nil
		}
		if time.Now().After(deadline) {
			return res, out.Errf(out.ExitTimeout, "ROLLOUT_TIMEOUT", "see the tasks with `komando cluster describe TARGET service "+service+"`", "not rolled out after %s (replicas %s)", wait, replicas)
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// swarmChange runs a service change on the manager and, with wait, follows
// the rollout, printing one answer for both.
func swarmChange(ctx context.Context, name string, t clusterTarget, service, line string, wait bool) error {
	if !wait {
		return runOne(ctx, name, t.host.Name, line, false, true)
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	if err := guard(st, []*store.Host{t.host}, line, true); err != nil {
		return err
	}
	if g.dryRun {
		out.P.Print(name, map[string]any{"host": t.host.Name, "would_run": line, "wait": true}, nil)
		return nil
	}
	var outText string
	var code int
	err = withClient(ctx, st, t.host, func(c *sshx.Client) error {
		outText, code, err = sshx.Output(ctx, c, line+" 2>&1", 2*time.Minute)
		return err
	})
	audit(st, name, []string{t.host.Name}, line, err == nil && code == 0, nil)
	if err != nil {
		return err
	}
	if code != 0 {
		return out.Errf(out.ExitRemote, "SWARM_ERROR", "", "%s", strings.TrimSpace(outText))
	}
	res, werr := swarmWait(ctx, t, service, rolloutWait())
	if res == nil {
		return werr
	}
	res["host"] = t.host.Name
	out.P.Print(name, res, softErr(werr))
	return exitFor(werr)
}

func rolloutWait() time.Duration {
	if g.timeout > 0 {
		return g.timeout
	}
	return 5 * time.Minute
}

func clusterDeployCmd() *cobra.Command {
	var ns, image, container string
	var wait bool
	c := &cobra.Command{
		Use:   "deploy TARGET TYPE/NAME --image IMAGE",
		Short: "Put out a new image (rolling); --wait follows the rollout to the end",
		Long: `Sets the image of a deployment, statefulset or daemonset (Kubernetes) or a
service (Swarm). With several containers, name one with --container (or
write --image NAME=IMAGE). --wait stays until every replica runs the new
image, the rollout fails, or --timeout (default 5m) passes; go back with
` + "`komando cluster rollback`" + `.`,
		Example: `  komando cluster deploy prod deployment/api --image ghcr.io/acme/api:1.4.3 --namespace shop --wait
  komando cluster deploy swarm1 service/web --image nginx:1.27 --wait`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if image == "" {
				return out.Usage("give the new image with --image")
			}
			if n, img, ok := strings.Cut(image, "="); ok && !strings.Contains(n, "/") && !strings.Contains(n, ":") {
				container, image = n, img
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			typ, name, err := splitRef(args[1])
			if err != nil {
				return err
			}
			if t.host != nil {
				if !strings.HasPrefix(typ, "service") {
					return out.Usage("on Swarm, deploy works on services (service/NAME)")
				}
				line := "docker service update --with-registry-auth --detach --image " + sshx.Q(image) + " " + sshx.Q(name)
				return swarmChange(cmd.Context(), "cluster.deploy", t, name, line, wait)
			}
			return withKube(cmd.Context(), "cluster.deploy", t, driver.RiskWrite, map[string]any{"object": args[1], "image": image}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := k.Resource(ctx, typ)
				if err != nil {
					return nil, out.Usage("%v", err)
				}
				if !oneOf(r.KindName(), "Deployment", "StatefulSet", "DaemonSet") {
					return nil, out.Usage("deploy works on deployments, statefulsets and daemonsets")
				}
				space := firstNonEmpty(ns, k.Namespace)
				var o map[string]any
				if err := k.Get(ctx, r.ObjectPath(space, name), nil, &o); err != nil {
					return nil, err
				}
				target, old, err := pickContainer(o, container)
				if err != nil {
					return nil, err
				}
				patch := fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":%q,"image":%q}]}}}}`, target, image)
				q := url.Values{}
				if g.dryRun {
					q.Set("dryRun", "All")
				}
				if _, err := k.Do(ctx, "PATCH", r.ObjectPath(space, name), q, []byte(patch), "application/strategic-merge-patch+json"); err != nil {
					return nil, err
				}
				res := map[string]any{"conn": t.conn.Name, "object": args[1], "namespace": space, "container": target,
					"image": image, "previous_image": old, "dry_run": g.dryRun}
				if wait && !g.dryRun {
					ro, err := waitRollout(ctx, k, r, space, name, rolloutWait())
					res["rollout"] = ro
					if err != nil {
						return res, err
					}
				}
				return res, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	c.Flags().StringVar(&image, "image", "", "the new image, e.g. ghcr.io/acme/api:1.4.3 (or CONTAINER=IMAGE)")
	c.Flags().StringVar(&container, "container", "", "which container gets the image (needed when there are several)")
	c.Flags().BoolVar(&wait, "wait", false, "wait until the rollout finishes (or fails; --timeout, default 5m)")
	return c
}

// pickContainer finds the container to change: the named one, or the only
// one. It also returns that container's current image.
func pickContainer(o map[string]any, name string) (string, string, error) {
	spec, _ := o["spec"].(map[string]any)
	tpl, _ := spec["template"].(map[string]any)
	pspec, _ := tpl["spec"].(map[string]any)
	cs, _ := pspec["containers"].([]any)
	var names []string
	for _, c := range cs {
		m, _ := c.(map[string]any)
		n := str(m["name"])
		names = append(names, n)
		if n == name || (name == "" && len(cs) == 1) {
			return n, str(m["image"]), nil
		}
	}
	if name == "" {
		return "", "", out.Usage("it has %d containers (%s); pick one with --container", len(cs), strings.Join(names, ", "))
	}
	return "", "", out.Errf(out.ExitNotFound, "CONTAINER_NOT_FOUND", "its containers: "+strings.Join(names, ", "), "no container %q", name)
}

// softErr turns err into the envelope's error while the data still prints.
func softErr(err error) *out.Error {
	if err == nil {
		return nil
	}
	return toErr(err)
}

func exitFor(err error) error {
	if err == nil {
		return nil
	}
	return exitCode(toErr(err).Exit)
}

// replicaSets returns the revisions of a Deployment, newest first.
func replicaSets(ctx context.Context, k *kube.Client, space string, d map[string]any) ([]map[string]any, error) {
	m, _ := d["metadata"].(map[string]any)
	uid := str(m["uid"])
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := k.Get(ctx, "/apis/apps/v1/namespaces/"+url.PathEscape(space)+"/replicasets", url.Values{"labelSelector": {matchLabels(d)}}, &list); err != nil {
		return nil, err
	}
	var owned []map[string]any
	for _, rs := range list.Items {
		rm, _ := rs["metadata"].(map[string]any)
		refs, _ := rm["ownerReferences"].([]any)
		for _, r := range refs {
			if str(r.(map[string]any)["uid"]) == uid {
				owned = append(owned, rs)
			}
		}
	}
	rev := func(rs map[string]any) int {
		a, _ := rs["metadata"].(map[string]any)["annotations"].(map[string]any)
		n, _ := strconv.Atoi(str(a[revisionKey]))
		return n
	}
	sort.Slice(owned, func(i, j int) bool { return rev(owned[i]) > rev(owned[j]) })
	return owned, nil
}

func rsRevision(rs map[string]any) int {
	a, _ := rs["metadata"].(map[string]any)["annotations"].(map[string]any)
	n, _ := strconv.Atoi(str(a[revisionKey]))
	return n
}

func rsImages(rs map[string]any) []string {
	spec, _ := rs["spec"].(map[string]any)
	tpl, _ := spec["template"].(map[string]any)
	ps, _ := tpl["spec"].(map[string]any)
	cs, _ := ps["containers"].([]any)
	var imgs []string
	for _, c := range cs {
		imgs = append(imgs, str(c.(map[string]any)["image"]))
	}
	return imgs
}

func clusterHistoryCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:     "history TARGET deployment/NAME",
		Short:   "Revisions of a deployment, newest first, with their images (for rollback --to)",
		Example: "  komando cluster history prod deployment/api --namespace shop",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			typ, name, err := splitRef(args[1])
			if err != nil {
				return err
			}
			if t.host != nil {
				return out.Usage("Swarm keeps one previous version; `komando cluster rollback TARGET service/NAME` goes back to it")
			}
			return withKube(cmd.Context(), "cluster.history", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := k.Resource(ctx, typ)
				if err != nil {
					return nil, out.Usage("%v", err)
				}
				if r.KindName() != "Deployment" {
					return nil, out.Usage("history works on deployments; for others use `komando cluster run TARGET -- rollout history ...`")
				}
				space := firstNonEmpty(ns, k.Namespace)
				var d map[string]any
				if err := k.Get(ctx, r.ObjectPath(space, name), nil, &d); err != nil {
					return nil, err
				}
				sets, err := replicaSets(ctx, k, space, d)
				if err != nil {
					return nil, err
				}
				current := str(d["metadata"].(map[string]any)["annotations"].(map[string]any)[revisionKey])
				rows := []map[string]any{}
				for _, rs := range sets {
					rm := rs["metadata"].(map[string]any)
					rows = append(rows, map[string]any{"revision": rsRevision(rs), "images": rsImages(rs),
						"current": strconv.Itoa(rsRevision(rs)) == current, "age": age(str(rm["creationTimestamp"]))})
				}
				return map[string]any{"conn": t.conn.Name, "object": args[1], "namespace": space, "revisions": rows}, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	return c
}

func clusterRollbackCmd() *cobra.Command {
	var ns string
	var to int
	var wait bool
	c := &cobra.Command{
		Use:   "rollback TARGET TYPE/NAME",
		Short: "Go back to the previous version (or --to REVISION, see `cluster history`)",
		Example: `  komando cluster rollback prod deployment/api --namespace shop --wait
  komando cluster rollback prod deployment/api --to 3 --namespace shop
  komando cluster rollback swarm1 service/web`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			typ, name, err := splitRef(args[1])
			if err != nil {
				return err
			}
			if t.host != nil {
				if to != 0 {
					return out.Usage("Swarm keeps only the previous version; leave out --to")
				}
				return swarmChange(cmd.Context(), "cluster.rollback", t, name, "docker service rollback --detach "+sshx.Q(name), wait)
			}
			return withKube(cmd.Context(), "cluster.rollback", t, driver.RiskWrite, map[string]any{"object": args[1], "to": to}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := k.Resource(ctx, typ)
				if err != nil {
					return nil, out.Usage("%v", err)
				}
				if r.KindName() != "Deployment" {
					return nil, out.Usage("rollback works on deployments; for others use `komando cluster run TARGET --write -- rollout undo ...`")
				}
				space := firstNonEmpty(ns, k.Namespace)
				var d map[string]any
				if err := k.Get(ctx, r.ObjectPath(space, name), nil, &d); err != nil {
					return nil, err
				}
				sets, err := replicaSets(ctx, k, space, d)
				if err != nil {
					return nil, err
				}
				var target map[string]any
				switch {
				case to > 0:
					for _, rs := range sets {
						if rsRevision(rs) == to {
							target = rs
						}
					}
				case len(sets) > 1:
					target = sets[1] // sets[0] is the current revision
				}
				if target == nil {
					return nil, out.Errf(out.ExitNotFound, "REVISION_NOT_FOUND", "see the revisions with `komando cluster history`", "no revision to go back to")
				}
				// the old template, without the hash label the controller adds
				tpl := target["spec"].(map[string]any)["template"].(map[string]any)
				if md, ok := tpl["metadata"].(map[string]any); ok {
					if l, ok := md["labels"].(map[string]any); ok {
						delete(l, "pod-template-hash")
					}
				}
				body, _ := json.Marshal([]map[string]any{{"op": "replace", "path": "/spec/template", "value": tpl}})
				q := url.Values{}
				if g.dryRun {
					q.Set("dryRun", "All")
				}
				if _, err := k.Do(ctx, "PATCH", r.ObjectPath(space, name), q, body, "application/json-patch+json"); err != nil {
					return nil, err
				}
				res := map[string]any{"conn": t.conn.Name, "object": args[1], "namespace": space,
					"to_revision": rsRevision(target), "images": rsImages(target), "dry_run": g.dryRun}
				if wait && !g.dryRun {
					ro, err := waitRollout(ctx, k, r, space, name, rolloutWait())
					res["rollout"] = ro
					if err != nil {
						return res, err
					}
				}
				return res, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	c.Flags().IntVar(&to, "to", 0, "the revision to go back to (default: the previous one)")
	c.Flags().BoolVar(&wait, "wait", false, "wait until the rollback finishes (--timeout, default 5m)")
	return c
}
