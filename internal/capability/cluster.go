package capability

// cluster: Kubernetes, Nomad and Docker Swarm. raw (today's cluster run)
// does what the removed get, logs, apply, scale, helm and the rest did;
// Kubernetes also keeps exec, shell and tunnel.

var clusterProviders = []provider{
	{name: "kubernetes", connect: []Option{credentialOpt}},
	{name: "nomad", state: New, connect: []Option{credentialOpt}},
	{name: "swarm", connect: []Option{credentialOpt}}, // today a server tagged swarm; its stored data moves at the cut
}

var rawCarries = join(
	idsOf("cluster", "apply", "deploy", "describe", "events", "get", "history", "list", "logs", "restart",
		"rm", "rollback", "scale", "status"),
	idsOf("cluster.helm", "history", "list", "status", "values"),
)

// kubeStops run before every Kubernetes verb: the kubeconfig login program
// is checked each time.
var kubeStops = []string{"guardKubePlugin", "guardCloudLogin"}

var clusterLeaves = each(clusterProviders, func(p provider) []Leaf {
	out := append(conns("cluster", "cluster.add").leaves(p), Leaf{
		Key:  Key{Type: "cluster", Provider: p.name, Verb: "raw"},
		Args: []Arg{{Name: "NAME"}, {Name: "COMMAND", Many: true}}, Options: []Option{writeOpt},
		Output: TargetData, State: p.state, Today: []string{"cluster.run"}, Carries: rawCarries,
	})
	if p.name == "kubernetes" {
		key := func(area, verb string) Key { return Key{Type: "cluster", Provider: p.name, Area: area, Verb: verb} }
		out = append(out,
			Leaf{Key: key("", "exec"), Args: selectorAndCommand, Options: []Option{readOnlyOpt}, Output: TargetData,
				Stops: []string{"refuseEncodedSecret"}, Today: []string{"cluster.exec"}},
			Leaf{Key: key("", "shell"), Args: oneName, Today: []string{"cluster.shell"}},
			// forward exists; tunnel list and stop are new code
			Leaf{Key: key("tunnel", "start"), Args: oneName,
				Options: []Option{{Name: "bind", Kind: String, Default: "127.0.0.1", Help: "the local address to listen on"}},
				Today:   []string{"cluster.forward"}},
			Leaf{Key: key("tunnel", "list"), State: New, LocalRead: true, Synonyms: []string{"ls"}},
			Leaf{Key: key("tunnel", "stop"), Args: []Arg{{Name: "ID"}}, State: New},
		)
		for i := range out {
			out[i].Stops = append(out[i].Stops, kubeStops...)
		}
	}
	return out
})
