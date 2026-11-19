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
	"mutatingadmissionpolicy":        "changes every object sent to the cluster",
	"mutatingadmissionpolicybinding": "changes every object sent to the cluster",
	"apiservice":                     "puts another server behind the cluster's API",
}

// controllerKinds are kinds a controller in the cluster turns into
// anything, with its own (usually full) rights: a Helm chart, a Git
// repository's manifests. Keyed by API group and kind, in lower case,
// since other groups use the same kind names.
var controllerKinds = map[string]string{
	"helm.cattle.io/helmchart":                  "installs a Helm chart with k3s's own rights",
	"helm.cattle.io/helmchartconfig":            "changes a Helm chart k3s installs with its own rights",
	"argoproj.io/application":                   "makes Argo CD install anything, with its rights",
	"argoproj.io/applicationset":                "makes Argo CD install anything, with its rights",
	"argoproj.io/appproject":                    "sets what Argo CD may install",
	"kustomize.toolkit.fluxcd.io/kustomization": "makes Flux install anything, with its rights",
	"helm.toolkit.fluxcd.io/helmrelease":        "makes Flux install a Helm chart, with its rights",
	"argoproj.io/workflow":                      "runs pods as any service account it names",
	"argoproj.io/cronworkflow":                  "runs pods as any service account it names",
	"argoproj.io/workflowtemplate":              "runs pods as any service account it names",
	"argoproj.io/clusterworkflowtemplate":       "runs pods as any service account it names",
}

// manifestEscalates says why objects in a manifest give more rights than
// the change itself: "" when none does. `cluster run -- create
// clusterrolebinding ...` and `-- run --privileged` need
// --allow-dangerous (classifyKubectl); the same objects in a file need it
// too. It looks at what the file says, anywhere in an object, so a pod
// template inside a Deployment, a CronJob, a List or a custom kind counts.
func manifestEscalates(docs []kubeDoc) string { return manifestEscalatesIn(docs, "") }

// manifestEscalatesIn is manifestEscalates for objects that name no
// namespace of their own going to ns (kubectl's -n).
func manifestEscalatesIn(docs []kubeDoc, ns string) string {
	for _, d := range docs {
		var o any
		if json.Unmarshal(d.JSON, &o) != nil {
			return strings.ToLower(d.Kind) + "/" + d.Name + " could not be read"
		}
		if why := objectEscalates(o, ns); why != "" {
			return why
		}
	}
	return ""
}

func objectEscalates(v any, defNS string) string {
	switch x := v.(type) {
	case []any:
		for _, c := range x {
			if why := objectEscalates(c, defNS); why != "" {
				return why
			}
		}
	case map[string]any:
		kind, _ := x["kind"].(string)
		ref := strings.ToLower(kind) + "/" + meta(x, "name")
		if why, ok := rightsKinds[strings.ToLower(kind)]; ok && x["apiVersion"] != nil {
			return ref + " " + why
		}
		group, _, _ := strings.Cut(strings.ToLower(str(x["apiVersion"])), "/")
		if why, ok := controllerKinds[group+"/"+strings.ToLower(kind)]; ok {
			return ref + " " + why
		}
		ns := meta(x, "namespace")
		if ns == "" {
			ns = defNS
		}
		if strings.EqualFold(kind, "ConfigMap") && meta(x, "name") == "aws-auth" && (ns == "kube-system" || ns == "") {
			return ref + " sets who may sign in to an EKS cluster, and with what rights"
		}
		if ns == "kube-system" {
			if sa := podAccount(x); sa != "" {
				return ref + " runs as " + sa + ", one of the cluster's own service accounts in kube-system"
			}
		}
		if strings.EqualFold(kind, "Secret") && str(x["type"]) == "kubernetes.io/service-account-token" {
			return ref + " makes a service account token that never runs out"
		}
		if why := podEscapes(x); why != "" {
			return why
		}
		for _, c := range x {
			if why := objectEscalates(c, defNS); why != "" {
				return why
			}
		}
	}
	return ""
}

// podAccount finds a pod spec in v that names a service account other
// than default: "" when there is none.
func podAccount(v any) string {
	switch x := v.(type) {
	case []any:
		for _, c := range x {
			if sa := podAccount(c); sa != "" {
				return sa
			}
		}
	case map[string]any:
		if x["containers"] != nil {
			for _, k := range []string{"serviceAccountName", "serviceAccount"} {
				if sa := str(x[k]); sa != "" && sa != "default" {
					return sa
				}
			}
		}
		for _, c := range x {
			if sa := podAccount(c); sa != "" {
				return sa
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
	// a volume source is a map ({path: ...}); a ConfigMap value or a
	// schema property that happens to be called hostPath is not one
	if p, ok := m["hostPath"].(map[string]any); ok && p["path"] != nil {
		return "a hostPath volume opens a folder of the node"
	}
	if p, ok := m["local"].(map[string]any); ok && p["path"] != nil && m["capacity"] != nil {
		return "a local PersistentVolume opens a folder of the node"
	}
	if labels, ok := m["labels"].(map[string]any); ok {
		for k, v := range labels {
			if psaPrivileged(k, str(v)) {
				return "the label pod-security.kubernetes.io/enforce=privileged lets a namespace run privileged pods"
			}
		}
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
		if wo, ok := sc["windowsOptions"].(map[string]any); ok && on(wo["hostProcess"]) {
			return "a hostProcess container runs on its Windows node"
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
// was rated is what is sent. A file that cannot be read or parsed leaves
// the rating alone: readManifest keeps that answer too, so the run stops
// on the same error, even when the file appears in the meantime.
func kubectlFileRisk(cl *call, args []string, risk driver.Risk) (driver.Risk, string) {
	if risk >= driver.RiskDestructive || risk == driver.RiskRead {
		return risk, ""
	}
	a, err := parseKargs(args)
	if err != nil {
		return risk, "" // the run says what is wrong with the words
	}
	ns := ""
	if n := a.vals["namespace"]; len(n) > 0 {
		ns = n[len(n)-1]
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
		if why := manifestEscalatesIn(docs, ns); why != "" {
			return driver.RiskDestructive, why
		}
	}
	return risk, ""
}

// composeEscapes says why a compose file handed to `docker stack deploy`
// gives a service its server: "" when it does not. It is the file form of
// runEscapesHost. A file komando cannot read as YAML counts: docker may
// read it another way.
func composeEscapes(file []byte) string {
	var c struct {
		Include  any                       `yaml:"include"`
		Services map[string]map[string]any `yaml:"services"`
		Volumes  map[string]map[string]any `yaml:"volumes"`
		Networks map[string]map[string]any `yaml:"networks"`
		Configs  map[string]map[string]any `yaml:"configs"`
		Secrets  map[string]map[string]any `yaml:"secrets"`
	}
	if err := yaml.Unmarshal(file, &c); err != nil {
		return "komando cannot read it as YAML (" + firstLine(err.Error()) + "), so it cannot check what the services get"
	}
	if c.Include != nil {
		return "it includes other compose files (include:), which komando does not check"
	}
	for name, n := range c.Networks {
		if strings.EqualFold(name, "host") && n["external"] != nil || strings.EqualFold(str(n["name"]), "host") {
			return "network " + name + " is the server's own network"
		}
		if ext, ok := n["external"].(map[string]any); ok && strings.EqualFold(str(ext["name"]), "host") {
			return "network " + name + " is the server's own network"
		}
	}
	// a config or secret made from a file: docker reads that file on the
	// manager and hands it to the service
	for kind, set := range map[string]map[string]map[string]any{"config": c.Configs, "secret": c.Secrets} {
		for name, v := range set {
			if f := str(v["file"]); strings.Contains(f, "$") || strings.HasPrefix(f, "~") || strings.HasPrefix(f, "/") && hostPathEscapes(f, true) {
				return kind + " " + name + " is the server file " + f
			}
		}
	}
	for name, v := range c.Volumes {
		opts, _ := v["driver_opts"].(map[string]any)
		if d := str(opts["device"]); strings.Contains(d, "$") || strings.HasPrefix(d, "/") && hostPathEscapes(d, false) {
			return "volume " + name + " is the server folder " + d
		}
	}
	for name, s := range c.Services {
		pre := "service " + name + " "
		if on(s["privileged"]) || strings.Contains(str(s["privileged"]), "$") {
			return pre + "is privileged (or leaves it to a variable)"
		}
		if ext, ok := s["extends"].(map[string]any); ok && ext["file"] != nil {
			return pre + "extends a service in another file (" + str(ext["file"]) + "), which komando does not check"
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
		if s["env_file"] != nil {
			for _, f := range composeStrings(s["env_file"]) {
				if strings.Contains(f, "$") || strings.HasPrefix(f, "~") || strings.HasPrefix(f, "/") && hostPathEscapes(f, true) {
					return pre + "reads the server file " + f
				}
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

// composeStrings reads a YAML value that is one string, a list of strings, or
// a list of {path: ...} maps (env_file's forms).
func composeStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var all []string
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				all = append(all, str(m["path"]))
			} else {
				all = append(all, str(e))
			}
		}
		return all
	}
	return nil
}
