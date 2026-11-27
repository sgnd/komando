package capability

// cluster: Kubernetes, Nomad and Docker Swarm. raw (today's cluster run)
// does what the removed get, logs, apply, scale, helm and the rest did;
// Kubernetes also keeps exec, shell and tunnel.

// swarm: today a Swarm is a server tagged swarm, and its stored data moves
// with the format-3 migration (E1). Until its entry kind is on main only raw
// is built, and it runs on the manager server (today's cluster run); the
// other swarm leaves are built in a later head of row C483, after E1.
var clusterProviders = []provider{
	{name: "kubernetes", connect: []Option{credentialOpt}, url: "k8s://api.cluster.example:6443", entry: "prod-k8s",
		rawExample: "get pods -A -o wide", writeExample: "rollout undo deployment/api -n shop"},
	{name: "nomad", state: New, connect: []Option{credentialOpt}},
	{name: "swarm", state: New, connect: []Option{credentialOpt}},
}

var rawCarries = join(
	idsOf("cluster", "apply", "deploy", "describe", "events", "get", "history", "list", "logs", "restart",
		"rm", "rollback", "scale", "status"),
	idsOf("cluster.helm", "history", "list", "status", "values"),
)

// kubeStops run before every Kubernetes verb: the kubeconfig login program
// is checked each time.
var kubeStops = []string{"guardKubePlugin", "guardCloudLogin"}

// namespaceOpt and containerOpt are the flags of the pod commands: the
// namespace is the cluster entry's own unless one is given.
var (
	namespaceOpt = Option{Name: "namespace", Short: "n", Kind: String, Help: "Kubernetes namespace (default: the context's, else default)"}
	containerOpt = Option{Name: "container", Short: "c", Kind: String, Help: "container in the pod"}
)

var clusterLeaves = each(clusterProviders, func(p provider) []Leaf {
	out := conns("cluster", "cluster.add").leaves(p)
	cmd := "  komando cluster " + p.name + " "
	if p.name == "kubernetes" {
		for i, l := range out {
			if l.Verb == "add" {
				out[i].Example = cmd + "add " + p.entry + " " + p.url + " --credential prod-kubeconfig --via web1\n" +
					cmd + "add " + p.entry + " " + p.url + " --credential prod-kubeconfig --dry-run"
			}
		}
	}
	raw := Leaf{
		Key:  Key{Type: "cluster", Provider: p.name, Verb: "raw"},
		Args: []Arg{{Name: "NAME"}, {Name: "COMMAND", Many: true, Dash: true}}, Options: []Option{writeOpt},
		Output: TargetData, State: p.state, Today: []string{"cluster.run"}, Carries: rawCarries,
	}
	switch p.name {
	case "kubernetes":
		raw.Short = "Run one kubectl command and show the result"
		raw.Example = cmd + "raw " + p.entry + " -- " + p.rawExample + "\n" + cmd + "raw " + p.entry + " --write -- " + p.writeExample + " --dry-run"
	case "swarm":
		raw.State = Built
		raw.Short = "Run one docker command on a Swarm manager and show the result"
		raw.Example = cmd + "raw swarm1 -- service ls\n" + cmd + "raw swarm1 -- service ps web\n" +
			cmd + "raw swarm1 --write -- service scale web=3 --dry-run"
	}
	out = append(out, raw)
	if p.name == "kubernetes" {
		key := func(area, verb string) Key { return Key{Type: "cluster", Provider: p.name, Area: area, Verb: verb} }
		out = append(out,
			Leaf{Key: key("", "exec"), Output: TargetData, Stops: []string{"refuseEncodedSecret"}, Today: []string{"cluster.exec"},
				Args:    []Arg{{Name: "NAME"}, {Name: "POD"}, {Name: "COMMAND", Many: true, Dash: true}},
				Options: []Option{namespaceOpt, containerOpt, readOnlyOpt},
				Short:   "Run a command in a pod, checked by the policy",
				Example: cmd + "exec " + p.entry + " deploy/api --namespace shop --read-only -- cat /app/config.yml\n" +
					cmd + "exec " + p.entry + " api-7d9f-x2 -c api --namespace shop -- php artisan cache:clear"},
			Leaf{Key: key("", "shell"), Today: []string{"cluster.shell"},
				Args:    []Arg{{Name: "NAME"}, {Name: "POD"}, {Name: "COMMAND", Many: true, Optional: true, Dash: true}},
				Options: []Option{namespaceOpt, containerOpt},
				Short:   "Open a shell in a pod, like kubectl exec",
				Example: cmd + "shell " + p.entry + " deploy/api --namespace shop\n" +
					cmd + "shell " + p.entry + " api-7d9f-x2 -c api -- /bin/ash"},
			// forward exists, on 127.0.0.1 only; tunnel list and stop are new code
			Leaf{Key: key("tunnel", "start"), Today: []string{"cluster.forward"},
				Args:    []Arg{{Name: "NAME"}, {Name: "OBJECT"}, {Name: "PORTS"}},
				Options: []Option{namespaceOpt},
				Short:   "Reach a pod or service port from this computer (127.0.0.1) until Ctrl-C",
				Example: cmd + "tunnel start " + p.entry + " svc/api 8080:80 --namespace shop\n" +
					cmd + "tunnel start " + p.entry + " deploy/db 15432:5432 --namespace shop\n" +
					cmd + "tunnel start " + p.entry + " svc/api :80 --namespace shop   # any free local port"},
			Leaf{Key: key("tunnel", "list"), State: New, LocalRead: true, Synonyms: []string{"ls"}},
			Leaf{Key: key("tunnel", "stop"), Args: []Arg{{Name: "ID"}}, State: New},
		)
		for i := range out {
			out[i].Stops = append(out[i].Stops, kubeStops...)
		}
	}
	return out
})
