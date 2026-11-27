package cli

import (
	"fmt"
	"sort"
	"strings"
)

// -o text for the cluster commands: kubectl-like tables, not YAML dumps.

// listColumns are the table columns per kind: header and item key.
var listColumns = map[string][][2]string{
	"Pod":                     {{"name", "name"}, {"ready", "ready"}, {"status", "status"}, {"restarts", "restarts"}, {"age", "age"}, {"node", "node"}},
	"Deployment":              {{"name", "name"}, {"ready", "ready"}, {"up-to-date", "updated"}, {"available", "available"}, {"age", "age"}},
	"StatefulSet":             {{"name", "name"}, {"ready", "ready"}, {"age", "age"}},
	"ReplicaSet":              {{"name", "name"}, {"ready", "ready"}, {"age", "age"}},
	"DaemonSet":               {{"name", "name"}, {"ready", "ready"}, {"age", "age"}},
	"Service":                 {{"name", "name"}, {"type", "type"}, {"cluster-ip", "cluster_ip"}, {"ports", "ports"}, {"age", "age"}},
	"Node":                    {{"name", "name"}, {"status", "status"}, {"version", "version"}, {"age", "age"}},
	"Secret":                  {{"name", "name"}, {"type", "type"}, {"keys", "keys"}, {"age", "age"}},
	"ConfigMap":               {{"name", "name"}, {"keys", "keys"}, {"age", "age"}},
	"Namespace":               {{"name", "name"}, {"status", "status"}, {"age", "age"}},
	"Ingress":                 {{"name", "name"}, {"class", "class"}, {"hosts", "hosts"}, {"address", "address"}, {"age", "age"}},
	"PersistentVolumeClaim":   {{"name", "name"}, {"status", "status"}, {"volume", "volume"}, {"capacity", "capacity"}, {"storageclass", "storage_class"}, {"age", "age"}},
	"PersistentVolume":        {{"name", "name"}, {"capacity", "capacity"}, {"reclaim", "reclaim"}, {"status", "status"}, {"claim", "claim"}, {"age", "age"}},
	"Job":                     {{"name", "name"}, {"status", "status"}, {"completions", "completions"}, {"age", "age"}},
	"CronJob":                 {{"name", "name"}, {"schedule", "schedule"}, {"suspend", "suspended"}, {"active", "active"}, {"last-schedule", "last_schedule"}, {"age", "age"}},
	"HorizontalPodAutoscaler": {{"name", "name"}, {"target", "target"}, {"min", "min"}, {"max", "max"}, {"current", "current"}, {"age", "age"}},
	"Event":                   {{"last", "last_age"}, {"type", "type"}, {"reason", "reason"}, {"object", "object"}, {"message", "message"}},
	// Swarm
	"Service@swarm": {{"name", "name"}, {"mode", "mode"}, {"ready", "ready"}, {"image", "image"}, {"ports", "ports"}, {"age", "age"}},
	"Task":          {{"name", "name"}, {"image", "image"}, {"node", "node"}, {"desired", "desired"}, {"state", "state"}, {"since", "since"}, {"error", "error"}},
	"Node@swarm":    {{"name", "name"}, {"status", "status"}, {"availability", "availability"}, {"manager", "manager"}, {"engine", "engine"}},
	"Stack":         {{"name", "name"}, {"services", "services"}},
}

// tableOf lays out rows of maps under the given columns.
func tableOf(cols [][2]string, items []map[string]any) string {
	headers := make([]string, len(cols))
	for i, c := range cols {
		headers[i] = c[0]
	}
	rows := make([][]string, 0, len(items))
	for _, it := range items {
		row := make([]string, len(cols))
		for i, c := range cols {
			row[i] = cluCell(it[c[1]])
		}
		rows = append(rows, row)
	}
	return textTable(headers, rows)
}

func cluCell(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.ReplaceAll(x, "\n", " ")
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprint(int64(x))
		}
	case []string:
		return strings.Join(x, ",")
	case []any:
		var p []string
		for _, e := range x {
			p = append(p, fmt.Sprint(e))
		}
		return strings.Join(p, ",")
	}
	return fmt.Sprint(v)
}

// describeData is `describe`: a summary, then tables of what the
// object has (containers, pods, tasks, conditions, events).
type describeData map[string]any

func (d describeData) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", str(d["object"]))
	if sum, ok := d["summary"].(map[string]any); ok {
		keys := make([]string, 0, len(sum))
		for k := range sum {
			if k != "name" && sum[k] != nil && cluCell(sum[k]) != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s: %s\n", strings.ReplaceAll(k, "_", " "), cluCell(sum[k]))
		}
	}
	section := func(title string, cols [][2]string, key string) {
		rows, _ := d[key].([]map[string]any)
		if len(rows) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		b.WriteString(indentText(tableOf(cols, rows), "  "))
	}
	section("Containers", [][2]string{{"name", "name"}, {"image", "image"}, {"ready", "ready"}, {"restarts", "restarts"}, {"state", "state"}, {"reason", "reason"}, {"ports", "ports"}}, "containers")
	section("Endpoints", [][2]string{{"pod", "pod"}, {"address", "ip"}, {"ready", "ready"}}, "endpoints")
	section("Pods", listColumns["Pod"], "pods")
	section("Tasks", listColumns["Task"], "tasks")
	section("Conditions", [][2]string{{"type", "type"}, {"status", "status"}, {"reason", "reason"}, {"message", "message"}}, "conditions")
	section("Events", listColumns["Event"], "events")
	return b.String()
}

func indentText(s, prefix string) string {
	lines := strings.SplitAfter(s, "\n")
	var b strings.Builder
	for _, l := range lines {
		if l != "" {
			b.WriteString(prefix + l)
		}
	}
	return b.String()
}
