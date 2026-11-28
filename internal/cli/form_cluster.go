package cli

import (
	"cmp"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/store"
)

// Kubernetes and Docker Swarm.

// clusterForms: a Kubernetes cluster comes from the kubeconfig file kubectl
// already uses (`import kubeconfig`), never from a typed URL: a k8s conn
// logs in with a whole kubeconfig kept in the vault, which conn add cannot
// take. A Docker Swarm is reached through its manager server.
func clusterForms() []formKind {
	return []formKind{
		{"Kubernetes", "from your kubeconfig file (EKS, GKE, AKS, k3s, DigitalOcean ...)", kubeconfigForm},
		{"Docker Swarm", "a manager server of the swarm, added as a server", swarmForm},
	}
}

const kubeconfigDefault = "~/.kube/config"

// kubeconfigSteps is how each cloud makes the file.
const kubeconfigSteps = "AWS: aws eks update-kubeconfig --name CLUSTER. Google: gcloud container clusters get-credentials CLUSTER. " +
	"Azure: az aks get-credentials -g GROUP -n CLUSTER. DigitalOcean: Download Config File on the cluster's page. " +
	"k3s: copy /etc/rancher/k3s/k3s.yaml from the server."

func kubeconfigForm(_ *call) formSpec {
	return formSpec{title: "Add Kubernetes clusters", qs: []formQ{
		{key: "file", label: "File", ask: "Where is your kubeconfig file?",
			help:    "The file kubectl uses. Every cluster in it is added, named after its context. No file yet? " + kubeconfigSteps,
			example: "~/Downloads/prod-kubeconfig.yaml",
			def: func(*store.State, formAnswers) string {
				if formFileProblem(kubeconfigDefault) == "" {
					return kubeconfigDefault
				}
				return ""
			},
			check: func(_ *store.State, _ formAnswers, v string) string { return kubeconfigProblem(v) }},
		{key: "protected", label: "Production", ask: "Can a mistake on these clusters hurt real users or real data?",
			help: "Production: komando asks you before every change, and an AI agent needs your yes in a window. " +
				"A cluster already in your list keeps its own setting.",
			def: func(*store.State, formAnswers) string { return "yes" },
			choices: func(*store.State, formAnswers) []pickRow {
				return []pickRow{{label: "Yes, protect them", detail: "komando asks you before every change", value: "yes"},
					{label: "No", detail: "test clusters, or only mine", value: "no"}}
			}},
		formGroupQ(),
		formMore(formYesNoQ("overwrite", "Replace", "Replace clusters you added before under the same name?",
			"For a kubeconfig with new logins. Without it, a name komando knows already is left as it is.", "no",
			"the new login replaces the old one", "keep the ones you have")),
	}, build: kubeconfigBuild}
}

// kubeconfigProblem checks the file is there and is a kubeconfig with at
// least one cluster komando can add.
func kubeconfigProblem(v string) string {
	if p := formFileProblem(v); p != "" {
		if v == kubeconfigDefault {
			return "there is no " + v + " on this computer. " + kubeconfigSteps
		}
		return p
	}
	if len(kubeconfigNames(v)) == 0 {
		return "komando finds no cluster it can add in this file; is it a kubeconfig (the file kubectl uses)?"
	}
	return ""
}

// kubeconfigNames are the names `import kubeconfig` gives the file's
// contexts (importKubeconfig): sorted, each one that has a server.
func kubeconfigNames(path string) []string {
	cfg, err := kube.Load(os.ReadFile, kubeconfigPaths(path)...)
	if err != nil {
		return nil
	}
	conns, _ := kubeconfigConnNames(cfg.ContextNames())
	var names []string
	for _, n := range sortedContexts(cfg) {
		x, err := cfg.Resolve(n)
		if err != nil {
			continue
		}
		if u, err := url.Parse(x.Cluster.Server); err != nil || u.Host == "" {
			continue
		}
		names = append(names, conns[n])
	}
	return names
}

// kubeconfigBuild imports the file, protects what it adds when asked, and
// ends with komando test, which only checks that the port of each cluster
// answers (it does not log in).
func kubeconfigBuild(st *store.State, a formAnswers) [][]string {
	file := cmp.Or(a["file"], kubeconfigDefault)
	args := []string{"import", "kubeconfig"}
	if file != kubeconfigDefault {
		args = append(args, formAbs(file))
	}
	if a["group"] != "" {
		args = append(args, "-g", a["group"])
	}
	if a["overwrite"] == "yes" {
		args = append(args, "--overwrite")
	}
	cmds := [][]string{args}
	names := kubeconfigNames(file)
	sure := 0
	for _, n := range names {
		if !kubeconfigAddsAs(st, n, a["overwrite"] == "yes") {
			continue
		}
		sure++
		if a["protected"] == "yes" {
			cmds = append(cmds, []string{"conn", "edit", n, "--protected"})
		}
	}
	target := "kind:k8s"
	switch {
	case a["group"] != "":
		target = "@" + a["group"]
	case len(names) > 0 && len(names) <= 5 && sure == len(names): // else a name may be another cluster's
		target = strings.Join(names, ",")
	}
	return append(cmds, []string{"test", target})
}

// kubeconfigAddsAs: the import adds the cluster named name under that very
// name, so conn edit protects it and nothing else. Only a name komando
// does not know yet is sure (or, with --overwrite, a conn of that name the
// import replaces): for a taken name the import skips the cluster or
// renames it (prod-2), and so does a name whose name-kubeconfig secret
// exists already (vetImportConns). Those are left as they are.
func kubeconfigAddsAs(st *store.State, name string, overwrite bool) bool {
	if st == nil {
		return false
	}
	kind, existing, taken := st.FindName(name)
	switch {
	case taken:
		c := st.Conns[name]
		return overwrite && kind == "conn" && existing == name && c != nil && !c.Protected
	case overwrite:
		return true
	}
	return !slices.Contains(secretNames(), name+"-kubeconfig")
}

// swarmForm is the server form for a swarm manager.
func swarmForm(cl *call) formSpec {
	sp := serverForm(cl)
	sp.title = "Add a Docker Swarm"
	sp.qs[0] = formNameQ("host", "swarm manager", "swarm1")
	sp.qs[1].ask = "What is the address of a manager server of the swarm?"
	sp.qs[1].help = "A server where docker node ls works. Its IP address or host name, from your hosting panel."
	build := sp.build
	sp.build = func(st *store.State, a formAnswers) [][]string {
		cmds := build(st, a)
		// removed by the C cluster row: the store makes the swarm service of a
		// server with this tag (store/format3_swarm.go)
		cmds[0] = append(cmds[0], "--tag", "swarm")
		return cmds
	}
	return sp
}

// The cluster commands: what a typed command asks for when it is missing.

var (
	clusterTargetArg = formArg{ask: "Which cluster?", pick: "cluster", free: true,
		help: "A Kubernetes cluster from your list. For a Docker Swarm, type its manager server's name. @group reaches several."}
	clusterPodArg = formArg{ask: "Which pod or workload?", example: "deployment/api or api-7d9f8c6b5-x2k4q",
		help: "A pod's name, or a kind and name like deployment/api (komando picks one of its pods)."}
)

func init() {
	addFormHints(clusterChangeHints())
}

// clusterChangeHints are the questions of the cluster kubernetes commands with a pod or a cluster to run on.
func clusterChangeHints() map[string]formHint {
	t := clusterTargetArg
	return map[string]formHint{
		"cluster kubernetes exec": {args: []formArg{t, clusterPodArg, {ask: "Which command should run in the pod?", example: "env"}},
			flags: []formFlag{{name: "read-only", ask: "Does the command only look, changing nothing?"}}},
		"cluster kubernetes shell": {args: []formArg{t, clusterPodArg, {ask: "A command instead of a shell? (leave empty for the usual shell)", example: "bash",
			help: "Empty: the usual shell of the container."}}},
		"cluster kubernetes tunnel start": {args: []formArg{t, {ask: "Which pod or service?", example: "service/web",
			help: "A kind and name, like service/web or deployment/api."},
			{ask: "Which port of it?", label: "Port", def: "80", example: "80 or 9000:80",
				help: "The port it listens on. LOCAL:REMOTE picks the port on this computer too; you then open 127.0.0.1:LOCAL."}}},
		"cluster kubernetes raw": {args: []formArg{t, {ask: "Which kubectl or docker command? (without kubectl or docker in front)",
			example: "get pods -o wide", help: "It runs as the cluster's own tool would run it."}},
			flags: []formFlag{{name: "write", ask: "Does it change the cluster?",
				help: "No: komando refuses a command that would change something."}}},
	}
}

// Next: lines for the cluster commands, and the questions of `komando
// cluster kubernetes ...`: the inventory verbs of the table and raw, exec,
// shell and tunnel start, which are today's cluster kubernetes raw, exec, shell and
// forward.
func init() {
	// raw, exec, shell and tunnel start are in clusterChangeHints.
	addFormHints(inventoryHints("cluster", "kubernetes", "cluster", "Clusters", "Kubernetes"))
	addFormHints(map[string]formHint{"cluster swarm raw": {
		args: []formArg{{ask: "Which Swarm manager server?", pick: "server", help: "A server that is a Swarm manager."},
			{ask: "Which docker command? (without docker in front)", example: "service ls", help: "It runs as docker would run it on the manager."}},
		flags: []formFlag{{name: "write", ask: "Does it change the Swarm?",
			help: "No: komando refuses a command that would change something."}}}})
}
