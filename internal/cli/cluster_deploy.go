package cli

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
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
		hint := "see why with `komando cluster kubernetes raw NAME -- describe " + kindRef(r, name) + "`; `-- rollout undo` goes back"
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

func rolloutWait(cl *call) time.Duration {
	if cl.flags.timeout > 0 {
		return cl.flags.timeout
	}
	return 5 * time.Minute
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
	return nil, out.Errf(out.ExitNotFound, "REVISION_NOT_FOUND", "see the revisions with `komando cluster kubernetes raw NAME -- rollout history TYPE/NAME`", "%s", msg)
}
