package cli

import (
	"cmp"
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

// stuckFor is how long pods may sit in ImagePullBackOff, CrashLoopBackOff
// and the like before a waiting rollout gives up early.
const stuckFor = 3 * time.Minute

// waitRollout polls a workload until it is rolled out, fails, or the time
// is up. A failure or timeout names the pods that are stuck and why.
func waitRollout(ctx context.Context, k *kube.Client, r kube.ResourceType, space, name string, wait time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(wait)
	var stuckSince time.Time
	for {
		var o map[string]any
		if err := k.Get(ctx, r.ObjectPath(space, name), nil, &o); err != nil {
			return nil, err
		}
		o["kind"] = r.KindName()
		done, msg, failed := rolloutState(r.KindName(), o)
		res := map[string]any{"object": kindRef(r, name), "namespace": space, "rolled_out": done, "status": msg}
		if done || (wait <= 0 && !failed) {
			return res, nil
		}
		stuck := stuckPods(ctx, k, space, o)
		if len(stuck) > 0 {
			res["stuck_pods"] = stuck
		}
		hint := "see why with `komando cluster describe TARGET " + kindRef(r, name) + "`; `komando cluster rollback` goes back"
		switch {
		case failed:
			return res, out.Errf(out.ExitRemote, "ROLLOUT_FAILED", hint, "%s%s", msg, stuckText(stuck))
		case len(stuck) == 0:
			stuckSince = time.Time{}
		case stuckSince.IsZero():
			stuckSince = time.Now()
		case time.Since(stuckSince) > stuckFor:
			return res, out.Errf(out.ExitRemote, "ROLLOUT_FAILED", hint, "pods stuck for %s%s", humanAge(time.Since(stuckSince)), stuckText(stuck))
		}
		if time.Now().After(deadline) {
			return res, out.Errf(out.ExitTimeout, "ROLLOUT_TIMEOUT", hint, "not rolled out after %s: %s%s", wait, msg, stuckText(stuck))
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// stuckReasons are container states a rollout does not get out of alone.
var stuckReasons = []string{"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "CrashLoopBackOff", "CreateContainerConfigError", "CreateContainerError", "RunContainerError", "ErrImageNeverPull"}

// stuckPods lists the workload's pods whose containers wait for one of
// stuckReasons: pod, container, reason, image.
func stuckPods(ctx context.Context, k *kube.Client, space string, o map[string]any) []map[string]any {
	sel := matchLabels(o)
	if sel == "" {
		return nil
	}
	var pods struct {
		Items []map[string]any `json:"items"`
	}
	if k.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(space)+"/pods", url.Values{"labelSelector": {sel}}, &pods) != nil {
		return nil
	}
	var stuck []map[string]any
	for _, p := range pods.Items {
		for _, c := range containerStates(p) {
			if oneOf(str(c["reason"]), stuckReasons...) {
				stuck = append(stuck, map[string]any{"pod": str(p["metadata"].(map[string]any)["name"]), "container": c["name"],
					"reason": c["reason"], "image": c["image"], "message": c["message"]})
			}
		}
	}
	return stuck
}

func stuckText(stuck []map[string]any) string {
	var parts []string
	for i, s := range stuck {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("and %d more", len(stuck)-3))
			break
		}
		parts = append(parts, fmt.Sprintf("pod %s: %s (image %s)", s["pod"], s["reason"], s["image"]))
	}
	if len(parts) == 0 {
		return ""
	}
	return "; " + strings.Join(parts, "; ")
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
		Short: "Roll out a new image",
		Long: `Sets the image of a deployment, statefulset or daemonset (Kubernetes) or a
service (Swarm). With several containers, name one with --container (or
write --image NAME=IMAGE). --wait stays until every replica runs the new
image, the rollout fails, or --timeout (default 5m) passes; go back with
` + "`komando cluster rollback`" + `.`,
		Example: `  komando cluster deploy prod-k8s deployment/api --image ghcr.io/acme/api:1.4.3 --namespace shop --wait
  komando cluster deploy swarm1 service/web --image nginx:1.27 --wait`,
		Args: refArgs(1, 0),
		RunE: func(cmd *cobra.Command, args []string) (rerr error) {
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
			typ, name, err := objectRef(args[1:])
			if err != nil {
				return err
			}
			if t.host != nil {
				if err := noNamespace(t, ns); err != nil {
					return err
				}
				if swarmKind(typ) != "service" {
					return out.Usage("on Swarm, deploy works on services (service/NAME)")
				}
				ins, err := swarmInspect(cmd.Context(), t, name)
				if err != nil {
					return err
				}
				line := "docker service update --with-registry-auth --detach --image " + sshx.Q(image) + " " + sshx.Q(name)
				defer rollbackNote(&rerr, args[0], "service/"+name, "")
				return swarmChange(cmd.Context(), "cluster.deploy", t, name, line, wait, false, driver.RiskWrite,
					map[string]any{"object": "service/" + name, "image": image, "previous_image": serviceImage(ins["Spec"])})
			}
			defer rollbackNote(&rerr, args[0], typ+"/"+name, ns)
			return withKube(ownTimeLimit(cmd.Context(), wait), "cluster.deploy", t, driver.RiskWrite, map[string]any{"object": typ + "/" + name, "image": image}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, typ)
				if err != nil {
					return nil, err
				}
				if !oneOf(r.KindName(), "Deployment", "StatefulSet", "DaemonSet") {
					return nil, out.Usage("deploy works on deployments, statefulsets and daemonsets")
				}
				space := cmp.Or(ns, k.Namespace)
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
				res := map[string]any{"conn": t.conn.Name, "object": kindRef(r, name), "namespace": space, "container": target,
					"image": image, "previous_image": old, "dry_run": g.dryRun}
				if old == image {
					res["unchanged"] = true
				}
				return withRollout(ctx, k, r, space, name, wait, res)
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	c.Flags().StringVar(&image, "image", "", "the new image, like ghcr.io/acme/api:1.4.3 (or CONTAINER=IMAGE)")
	c.Flags().StringVarP(&container, "container", "c", "", "which container gets the image (needed when there are several)")
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
	return "", "", out.Errf(out.ExitNotFound, "CONTAINER_NOT_FOUND", "its containers: "+strings.Join(names, ", "), "no container named %q", name)
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
	var limit int
	c := &cobra.Command{
		Use:     "history TARGET TYPE/NAME",
		Short:   "Revisions of a deployment, newest first, with their images",
		Example: "  komando cluster history prod-k8s deployment/api --namespace shop",
		Args:    refArgs(1, 0),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			typ, name, err := objectRef(args[1:])
			if err != nil {
				return err
			}
			if t.host != nil {
				return out.Usage("Swarm keeps one previous version; `komando cluster rollback TARGET service/NAME` goes back to it")
			}
			return withKube(cmd.Context(), "cluster.history", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, typ)
				if err != nil {
					return nil, err
				}
				if r.KindName() != "Deployment" {
					return nil, out.Usage("history works on deployments; for others use `komando cluster run TARGET -- rollout history ...`")
				}
				space := cmp.Or(ns, k.Namespace)
				var d map[string]any
				if err := k.Get(ctx, r.ObjectPath(space, name), nil, &d); err != nil {
					return nil, err
				}
				sets, err := replicaSets(ctx, k, space, d)
				if err != nil {
					return nil, err
				}
				current := deployRevision(d)
				rows := []map[string]any{}
				for _, rs := range sets {
					rm := rs["metadata"].(map[string]any)
					rows = append(rows, map[string]any{"revision": rsRevision(rs), "images": rsImages(rs),
						"current": rsRevision(rs) == current, "age": age(str(rm["creationTimestamp"]))})
				}
				return historyData{"conn": t.conn.Name, "object": kindRef(r, name), "namespace": space, "revisions": cutRows(rows, limit)}, nil
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	clusterLimitFlag(c, &limit, 0, "revisions, newest first")
	return c
}

type historyData map[string]any

func (h historyData) Text() string {
	rows, _ := h["revisions"].([]map[string]any)
	var cells [][]string
	for _, r := range rows {
		cur := ""
		if r["current"] == true {
			cur = "*"
		}
		cells = append(cells, []string{fmt.Sprint(r["revision"]), cur, cluCell(r["images"]), str(r["age"])})
	}
	if len(cells) == 0 {
		return noneYet("revisions", "")
	}
	return textTable([]string{"revision", "current", "images", "age"}, cells)
}

func deployRevision(d map[string]any) int {
	m, _ := d["metadata"].(map[string]any)
	a, _ := m["annotations"].(map[string]any)
	n, _ := strconv.Atoi(str(a[revisionKey]))
	return n
}

// pickRollback chooses where a rollback without --revision goes: the newest
// earlier revision with other images than the current one. When the
// current revision is itself a rollback, the revision it replaced is the
// one that went wrong, so it is skipped too (go there with --to).
func pickRollback(sets []map[string]any, current int) (map[string]any, error) {
	var cur map[string]any
	for _, rs := range sets {
		if rsRevision(rs) == current {
			cur = rs
		}
	}
	rolledBack := 0 // the revision the current one replaced, when it was a rollback
	if cur != nil {
		a, _ := cur["metadata"].(map[string]any)["annotations"].(map[string]any)
		if str(a["deployment.kubernetes.io/revision-history"]) != "" {
			for _, rs := range sets {
				if n := rsRevision(rs); n < current && n > rolledBack {
					rolledBack = n
				}
			}
		}
	}
	var skipped []string
	for _, rs := range sets { // newest first
		n := rsRevision(rs)
		switch {
		case n >= current:
		case cur != nil && strings.Join(rsImages(rs), ",") == strings.Join(rsImages(cur), ","):
			skipped = append(skipped, fmt.Sprintf("%d (same images)", n))
		case n == rolledBack:
			skipped = append(skipped, fmt.Sprintf("%d (rolled back from)", n))
		default:
			return rs, nil
		}
	}
	msg := "no earlier revision to go back to"
	if len(skipped) > 0 {
		msg += "; skipped " + strings.Join(skipped, ", ") + ": pick one with --to"
	}
	return nil, out.Errf(out.ExitNotFound, "REVISION_NOT_FOUND", "see the revisions with `komando cluster history TARGET TYPE/NAME`", "%s", msg)
}

func revisionList(sets []map[string]any) string {
	var n []int
	for _, rs := range sets {
		n = append(n, rsRevision(rs))
	}
	sort.Ints(n)
	var s []string
	for _, x := range n {
		s = append(s, strconv.Itoa(x))
	}
	return strings.Join(s, ", ")
}

func clusterRollbackCmd() *cobra.Command {
	var ns string
	var to int
	var wait bool
	c := &cobra.Command{
		Use:   "rollback TARGET TYPE/NAME",
		Short: "Go back to an earlier version of a workload",
		Long: `Without --revision, a deployment goes back to the newest earlier revision that runs
other images than now. After a rollback, the revision it replaced (the broken
one) is skipped, so a second rollback does not bring it back; --revision picks any
revision. A Swarm service goes back to its previous version.`,
		Example: `  komando cluster rollback prod-k8s deployment/api --namespace shop --wait
  komando cluster rollback prod-k8s deployment/api --revision 3 --namespace shop
  komando cluster rollback swarm1 service/web`,
		Args: refArgs(1, 0),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			typ, name, err := objectRef(args[1:])
			if err != nil {
				return err
			}
			if t.host != nil {
				if err := noNamespace(t, ns); err != nil {
					return err
				}
				if to != 0 {
					return out.Usage("Swarm keeps only the previous version; leave out --to")
				}
				if swarmKind(typ) != "service" {
					return out.Usage("on Swarm, rollback works on services (service/NAME)")
				}
				ins, err := swarmInspect(cmd.Context(), t, name)
				if err != nil {
					return err
				}
				if ins["PreviousSpec"] == nil {
					return out.Errf(out.ExitNotFound, "REVISION_NOT_FOUND", "see what was deployed with `komando cluster describe TARGET service/"+name+"`", "service %s has no previous version to go back to", name)
				}
				return swarmChange(cmd.Context(), "cluster.rollback", t, name, "docker service rollback --detach "+sshx.Q(name), wait, true, driver.RiskWrite,
					map[string]any{"object": "service/" + name, "images": []string{serviceImage(ins["PreviousSpec"])}, "previous_image": serviceImage(ins["Spec"])})
			}
			return withKube(ownTimeLimit(cmd.Context(), wait), "cluster.rollback", t, driver.RiskWrite, map[string]any{"object": typ + "/" + name, "to": to}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, typ)
				if err != nil {
					return nil, err
				}
				if r.KindName() != "Deployment" {
					return nil, out.Usage("rollback works on deployments; for others use `komando cluster run TARGET --write -- rollout undo ...`")
				}
				space := cmp.Or(ns, k.Namespace)
				var d map[string]any
				if err := k.Get(ctx, r.ObjectPath(space, name), nil, &d); err != nil {
					return nil, err
				}
				sets, err := replicaSets(ctx, k, space, d)
				if err != nil {
					return nil, err
				}
				current := deployRevision(d)
				var target map[string]any
				if to > 0 {
					for _, rs := range sets {
						if rsRevision(rs) == to {
							target = rs
						}
					}
					if target == nil {
						return nil, out.Errf(out.ExitNotFound, "REVISION_NOT_FOUND", "see the revisions with `komando cluster history TARGET TYPE/NAME`",
							"revision %d not found; revisions: %s", to, revisionList(sets))
					}
				} else if target, err = pickRollback(sets, current); err != nil {
					return nil, err
				}
				res := map[string]any{"conn": t.conn.Name, "object": kindRef(r, name), "namespace": space,
					"from_revision": current, "to_revision": rsRevision(target), "images": rsImages(target), "dry_run": g.dryRun}
				if rsRevision(target) == current {
					res["unchanged"] = true
					return res, nil
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
				return withRollout(ctx, k, r, space, name, wait, res)
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	rollbackFlags(c, &to, &wait)
	return c
}

// rollbackFlags are cluster rollback's own flags.
func rollbackFlags(c *cobra.Command, to *int, wait *bool) {
	c.Flags().IntVar(to, "revision", 0, "the revision to go back to (default: the previous one with other images)")
	flagAlias(c, "to-revision", "revision") // kubectl's word: a permanent synonym
	c.Flags().BoolVar(wait, "wait", false, "wait until the rollback finishes (--timeout, default 5m)")
}

// rollbackNote prints, for a person, how to undo a deploy that went
// through (text mode only; JSON already carries previous_image).
func rollbackNote(err *error, target, obj, ns string) {
	if *err != nil || g.dryRun {
		return
	}
	n := ""
	if ns != "" {
		n = " --namespace " + argQ(ns)
	}
	textNote("To go back to the previous image: komando cluster rollback %s %s%s", argQ(target), argQ(obj), n)
}
