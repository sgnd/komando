package cli

import (
	"cmp"
	"fmt"
	"strings"
)

func nodeReady(n map[string]any) string {
	st, _ := n["status"].(map[string]any)
	conds, _ := st["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" {
			if m["status"] == "True" {
				return "Ready"
			}
			return "NotReady"
		}
	}
	return "Unknown"
}

// summarize turns an object into one row: name, namespace, age and the few
// fields that tell its state, per kind.
func summarize(kind string, o map[string]any) map[string]any {
	m, _ := o["metadata"].(map[string]any)
	spec, _ := o["spec"].(map[string]any)
	st, _ := o["status"].(map[string]any)
	row := map[string]any{"name": m["name"], "age": age(fmt.Sprint(m["creationTimestamp"]))}
	if ns, ok := m["namespace"]; ok {
		row["namespace"] = ns
	}
	num := func(v any) int { f, _ := v.(float64); return int(f) }
	switch kind {
	case "Pod":
		row["status"] = st["phase"]
		cs, _ := st["containerStatuses"].([]any)
		ready, restarts := 0, 0
		for _, c := range cs {
			cm, _ := c.(map[string]any)
			if cm["ready"] == true {
				ready++
			}
			restarts += num(cm["restartCount"])
			if w, ok := cm["state"].(map[string]any)["waiting"].(map[string]any); ok {
				row["status"] = w["reason"]
			}
		}
		row["ready"] = fmt.Sprintf("%d/%d", ready, len(cs))
		row["restarts"] = restarts
		row["node"] = spec["nodeName"]
	case "Deployment", "StatefulSet", "ReplicaSet":
		row["ready"] = fmt.Sprintf("%d/%d", num(st["readyReplicas"]), num(spec["replicas"]))
		row["updated"] = num(st["updatedReplicas"])
		row["available"] = num(st["availableReplicas"])
	case "DaemonSet":
		row["ready"] = fmt.Sprintf("%d/%d", num(st["numberReady"]), num(st["desiredNumberScheduled"]))
	case "Service":
		row["type"], row["cluster_ip"] = spec["type"], spec["clusterIP"]
		var ports []string
		pl, _ := spec["ports"].([]any)
		for _, p := range pl {
			pm, _ := p.(map[string]any)
			ports = append(ports, fmt.Sprintf("%d/%s", num(pm["port"]), pm["protocol"]))
		}
		row["ports"] = strings.Join(ports, ",")
	case "Node":
		row["status"] = nodeReady(o)
		ni, _ := st["nodeInfo"].(map[string]any)
		row["version"] = ni["kubeletVersion"]
	case "Secret":
		row["type"] = o["type"]
		data, _ := o["data"].(map[string]any)
		row["keys"] = len(data)
	case "ConfigMap":
		data, _ := o["data"].(map[string]any)
		row["keys"] = len(data)
	case "Namespace":
		row["status"] = st["phase"]
	case "Ingress":
		var hosts []string
		rules, _ := spec["rules"].([]any)
		for _, r := range rules {
			if h, _ := r.(map[string]any)["host"].(string); h != "" {
				hosts = append(hosts, h)
			}
		}
		row["hosts"] = strings.Join(hosts, ",")
		row["class"] = spec["ingressClassName"]
		lb, _ := st["loadBalancer"].(map[string]any)
		var addrs []string
		ing, _ := lb["ingress"].([]any)
		for _, i := range ing {
			im, _ := i.(map[string]any)
			addrs = append(addrs, cmp.Or(str(im["ip"]), str(im["hostname"])))
		}
		row["address"] = strings.Join(addrs, ",")
	case "PersistentVolumeClaim":
		row["status"] = st["phase"]
		row["volume"] = spec["volumeName"]
		row["storage_class"] = spec["storageClassName"]
		if c, ok := st["capacity"].(map[string]any); ok {
			row["capacity"] = c["storage"]
		}
	case "PersistentVolume":
		row["status"] = st["phase"]
		if c, ok := spec["capacity"].(map[string]any); ok {
			row["capacity"] = c["storage"]
		}
		if ref, ok := spec["claimRef"].(map[string]any); ok {
			row["claim"] = fmt.Sprint(ref["namespace"], "/", ref["name"])
		}
		row["reclaim"] = spec["persistentVolumeReclaimPolicy"]
	case "Job":
		want := 1
		if c, ok := spec["completions"]; ok {
			want = num(c)
		}
		row["completions"] = fmt.Sprintf("%d/%d", num(st["succeeded"]), want)
		row["active"], row["failed"] = num(st["active"]), num(st["failed"])
		row["status"] = jobState(st)
	case "CronJob":
		row["schedule"], row["suspended"] = spec["schedule"], spec["suspend"] == true
		row["last_schedule"] = age(str(st["lastScheduleTime"]))
		active, _ := st["active"].([]any)
		row["active"] = len(active)
	case "HorizontalPodAutoscaler":
		row["min"], row["max"] = num(spec["minReplicas"]), num(spec["maxReplicas"])
		row["current"], row["desired"] = num(st["currentReplicas"]), num(st["desiredReplicas"])
		if ref, ok := spec["scaleTargetRef"].(map[string]any); ok {
			row["target"] = strings.ToLower(fmt.Sprint(ref["kind"])) + "/" + fmt.Sprint(ref["name"])
		}
	case "Event":
		for k, v := range eventRow(o) {
			row[k] = v
		}
	}
	return row
}

// jobState reads a Job's conditions: complete, failed or running.
func jobState(st map[string]any) string {
	conds, _ := st["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["status"] == "True" && (m["type"] == "Complete" || m["type"] == "Failed") {
			return strings.ToLower(fmt.Sprint(m["type"]))
		}
	}
	return "running"
}

// eventRow is the useful part of an Event: what happened to which object,
// how often, and when last.
func eventRow(o map[string]any) map[string]any {
	inv, _ := o["involvedObject"].(map[string]any)
	last := cmp.Or(str(o["lastTimestamp"]), str(o["eventTime"]), str(o["firstTimestamp"]))
	if m, ok := o["metadata"].(map[string]any); ok && last == "" {
		last = str(m["creationTimestamp"])
	}
	count, _ := o["count"].(float64)
	return map[string]any{
		"type": o["type"], "reason": o["reason"], "message": o["message"], "count": int(count),
		"object": strings.ToLower(str(inv["kind"])) + "/" + str(inv["name"]), "last": last, "last_age": age(last),
	}
}
