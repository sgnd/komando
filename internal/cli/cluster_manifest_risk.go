package cli

import (
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sgnd/komando/internal/driver"
)

// rightsKinds are the kinds that hand out rights in a cluster: who may do
// what (RBAC), a token that never runs out, and the hooks and extension
// servers that see or change every request.
var rightsKinds = map[string]string{
	"clusterrolebinding":             "gives rights in the whole cluster",
	"rolebinding":                    "gives rights in a namespace",
	"clusterrole":                    "sets what a role may do in the whole cluster",
	"role":                           "sets what a role may do",
	"mutatingwebhookconfiguration":   "changes every object sent to the cluster",
	"validatingwebhookconfiguration": "sees every object sent to the cluster",
	"apiservice":                     "puts another server behind the cluster's API",
}

// manifestEscalates says why objects in a manifest give more rights than
// the change itself: "" when none does. `cluster run -- create
// clusterrolebinding ...` and `-- run --privileged` need
// --allow-dangerous (classifyKubectl); the same objects in a file need it
// too. It looks at what the file says, anywhere in an object, so a pod
// template inside a Deployment, a CronJob, a List or a custom kind counts.
func manifestEscalates(docs []kubeDoc) string {
	for _, d := range docs {
		var o any
		if json.Unmarshal(d.JSON, &o) != nil {
			return strings.ToLower(d.Kind) + "/" + d.Name + " could not be read"
		}
		if why := objectEscalates(o); why != "" {
			return why
		}
	}
	return ""
}

func objectEscalates(v any) string {
	switch x := v.(type) {
	case []any:
		for _, c := range x {
			if why := objectEscalates(c); why != "" {
				return why
			}
		}
	case map[string]any:
		kind, _ := x["kind"].(string)
		ref := strings.ToLower(kind) + "/" + meta(x, "name")
		if why, ok := rightsKinds[strings.ToLower(kind)]; ok && x["apiVersion"] != nil {
			return ref + " " + why
		}
		if strings.EqualFold(kind, "Secret") && str(x["type"]) == "kubernetes.io/service-account-token" {
			return ref + " makes a service account token that never runs out"
		}
		if why := podEscapes(x); why != "" {
			return why
		}
		for _, c := range x {
			if why := objectEscalates(c); why != "" {
				return why
			}
		}
	}
	return ""
}

// podEscapes: fields of a pod spec, a container or a volume that hand the
// pod its node (the kubectl form of docker's runEscapesHost).
func podEscapes(m map[string]any) string {
	for _, k := range []string{"hostPID", "hostNetwork", "hostIPC"} {
		if on(m[k]) {
			return "a pod with " + k + " shares its node's processes or network"
		}
	}
	if p, ok := m["hostPath"]; ok && p != nil {
		return "a hostPath volume opens a folder of the node"
	}
	if sc, ok := m["securityContext"].(map[string]any); ok {
		if on(sc["privileged"]) {
			return "a privileged container has its node's rights"
		}
		if caps, ok := sc["capabilities"].(map[string]any); ok {
			if add, isList := caps["add"].([]any); caps["add"] != nil && (!isList || len(add) > 0) {
				return "a container with added capabilities has more rights on its node"
			}
		}
		if pm := str(sc["procMount"]); pm != "" && !strings.EqualFold(pm, "Default") {
			return "a container with an unmasked /proc sees its node"
		}
	}
	return ""
}

// on: a YAML true. A string "true" is not a boolean to the cluster, but
// komando does not guess what a server makes of it: it counts.
func on(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "true")
	}
	return false
}

// kubectlFileRisk raises the rating of a kubectl command that sends a
// manifest (-f) whose objects give out rights or escape to a node. The
// files are read here once and kept for the run (readManifest), so what
// was rated is what is sent. A file that cannot be read or parsed leaves
// the rating alone: the run stops on it with its own message.
func kubectlFileRisk(cl *call, args []string, risk driver.Risk) (driver.Risk, string) {
	if risk >= driver.RiskDestructive || risk == driver.RiskRead {
		return risk, ""
	}
	a, err := parseKargs(args)
	if err != nil {
		return risk, ""
	}
	for _, f := range a.vals["filename"] {
		b, err := readManifest(cl, f, a.bools["recursive"])
		if err != nil {
			continue
		}
		docs, err := splitYAML(b)
		if err != nil {
			continue
		}
		if why := manifestEscalates(docs); why != "" {
			return driver.RiskDestructive, why
		}
	}
	return risk, ""
}

// composeEscapes says why a compose file handed to `docker stack deploy`
// gives a service its server: "" when it does not. It is the file form of
// runEscapesHost. A file komando cannot read as YAML is left to docker,
// which refuses it.
func composeEscapes(file []byte) string {
	var c struct {
		Services map[string]map[string]any `yaml:"services"`
		Volumes  map[string]map[string]any `yaml:"volumes"`
	}
	if yaml.Unmarshal(file, &c) != nil {
		return ""
	}
	for name, v := range c.Volumes {
		opts, _ := v["driver_opts"].(map[string]any)
		if d := str(opts["device"]); strings.Contains(d, "$") || strings.HasPrefix(d, "/") && hostPathEscapes(d, false) {
			return "volume " + name + " is the server folder " + d
		}
	}
	for name, s := range c.Services {
		pre := "service " + name + " "
		if on(s["privileged"]) {
			return pre + "is privileged"
		}
		for _, k := range []string{"cap_add", "devices", "device_cgroup_rules", "security_opt", "volumes_from"} {
			if l, isList := s[k].([]any); s[k] != nil && (!isList || len(l) > 0) {
				return pre + "sets " + k
			}
		}
		for _, k := range []string{"pid", "ipc", "userns_mode", "uts", "cgroup", "network_mode"} {
			if v := strings.ToLower(str(s[k])); v == "host" || strings.HasPrefix(v, "container:") || strings.HasPrefix(v, "service:") || strings.Contains(v, "$") {
				return pre + "shares the server's " + k
			}
		}
		vols, _ := s["volumes"].([]any)
		for _, v := range vols {
			src, ro := "", false
			switch x := v.(type) {
			case string:
				var rest string
				src, rest, _ = strings.Cut(x, ":")
				if k := strings.LastIndex(rest, ":"); k >= 0 {
					for _, o := range strings.Split(rest[k+1:], ",") {
						ro = ro || o == "ro" || o == "readonly"
					}
				}
			case map[string]any:
				src, ro = str(x["source"]), on(x["read_only"])
			}
			// a path of the server (or one only the manager's
			// environment knows) that hands over the server
			if strings.Contains(src, "$") || strings.HasPrefix(src, "~") || strings.HasPrefix(src, ".") ||
				strings.HasPrefix(src, "/") && hostPathEscapes(src, ro) {
				return pre + "mounts the server folder " + src
			}
		}
	}
	return ""
}
