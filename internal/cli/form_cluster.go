package cli

import (
	"cmp"
	"net/url"
	"os"
	"slices"
	"sort"
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

func kubeconfigForm() formSpec {
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
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{{label: "Yes, protect them", detail: "komando asks you before every change", value: "yes"},
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
	b, err := os.ReadFile(expandHome(path))
	if err != nil {
		return nil
	}
	cfg, err := kube.Parse(b)
	if err != nil {
		return nil
	}
	contexts := cfg.ContextNames()
	sort.Strings(contexts)
	p := newPlan()
	var names []string
	for _, n := range contexts {
		x, err := cfg.Resolve(n)
		if err != nil {
			continue
		}
		if u, err := url.Parse(x.Cluster.Server); err != nil || u.Host == "" {
			continue
		}
		name := p.name(n)
		p.Conns = append(p.Conns, &store.Conn{Name: name})
		names = append(names, name)
	}
	return names
}

// kubeconfigBuild imports the file, protects what it adds when asked, and
// ends with cluster status, which logs in to each cluster (komando test
// only checks that its port answers).
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
	return append(cmds, []string{"cluster", "status", target})
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

// swarmForm is the server form for a swarm manager, ending with cluster
// status (which logs in and asks docker) instead of a plain test.
func swarmForm() formSpec {
	sp := serverForm()
	sp.title = "Add a Docker Swarm"
	sp.qs[0] = formNameQ("host", "swarm manager", "swarm1")
	sp.qs[1].ask = "What is the address of a manager server of the swarm?"
	sp.qs[1].help = "A server where docker node ls works. Its IP address or host name, from your hosting panel."
	build := sp.build
	sp.build = func(st *store.State, a formAnswers) [][]string {
		cmds := build(st, a)
		status := []string{"cluster", "status", a["name"]}
		if a["code"] == "yes" { // komando login first, then look
			return append(cmds, status)
		}
		return append(cmds[:len(cmds)-1], status)
	}
	return sp
}

// The cluster commands, asked from a menu task.

var (
	clusterTargetArg = formArg{ask: "Which cluster?", pick: "cluster", free: true,
		help: "A Kubernetes cluster from your list. For a Docker Swarm, type its manager server's name. @group reaches several."}
	clusterRefArg = formArg{ask: "Which workload?", example: "deployment/api",
		help: "Its kind and name, like deployment/api or statefulset/db. komando cluster ls shows them."}
	clusterTypeArg = formArg{ask: "What kind of object?", example: "deployment",
		help: "pod, deployment, service, node, ingress, configmap ... On a Swarm: service, task, node, stack."}
	clusterNameArg = formArg{ask: "Its name?", example: "api",
		help: "komando cluster ls shows the names."}
	clusterPodArg = formArg{ask: "Which pod or workload?", example: "deployment/api or api-7d9f8c6b5-x2k4q",
		help: "A pod's name, or a kind and name like deployment/api (komando picks one of its pods)."}
	clusterWaitFlag = formFlag{name: "wait", ask: "Wait until it is done?",
		help: "Yes: komando stays until every copy runs the new version, or says what went wrong."}
	clusterReleaseArg = formArg{ask: "Which Helm release?", example: "ingress-nginx",
		help: "komando cluster helm ls shows the releases."}
)

func init() {
	addFormHints(clusterReadHints())
	addFormHints(clusterChangeHints())
}

// clusterReadHints are the cluster commands that only look.
func clusterReadHints() map[string]formHint {
	t := clusterTargetArg
	return map[string]formHint{
		"cluster status": {args: []formArg{t, {ask: "One workload to check its rollout? (leave empty for the whole cluster)", example: "deployment/api",
			help: "Empty: the whole cluster, its nodes and what is not healthy."}}},
		"cluster ls": {args: []formArg{t, {ask: "What do you want to list?", def: "pods",
			help: "pods, deployments, services, nodes, ingresses, configmaps ... On a Swarm: services, tasks, nodes, stacks."}},
			flags: []formFlag{{name: "all-namespaces", ask: "From every namespace?",
				help: "No: only the cluster's usual namespace (a namespace is a folder of objects in the cluster)."}}},
		"cluster get":      {args: []formArg{t, clusterTypeArg, clusterNameArg}},
		"cluster describe": {args: []formArg{t, clusterTypeArg, clusterNameArg}},
		"cluster events":   {args: []formArg{t}, flags: []formFlag{{name: "warnings", ask: "Only problems (Warning events)?"}}},
		"cluster logs": {args: []formArg{t, clusterPodArg},
			flags: []formFlag{{name: "since", ask: "Only lines newer than? (leave empty for the last lines)", example: "10m or 2h",
				help: "Empty: the last lines of each pod."}, {name: "follow", ask: "Keep showing new lines? (Ctrl-C stops)"}}},
		"cluster history": {args: []formArg{t, {ask: "Which deployment?", example: "deployment/api",
			help: "Written deployment/NAME. komando cluster ls TARGET deployments shows them."}}},
		"cluster helm ls":      {args: []formArg{t}},
		"cluster helm status":  {args: []formArg{t, clusterReleaseArg}},
		"cluster helm history": {args: []formArg{t, clusterReleaseArg}},
		"cluster helm values": {args: []formArg{t, clusterReleaseArg},
			flags: []formFlag{{name: "all", ask: "Also the chart's own default values?"}}},
	}
}

// clusterChangeHints are the cluster commands that change something.
func clusterChangeHints() map[string]formHint {
	t := clusterTargetArg
	return map[string]formHint{
		"cluster deploy": {args: []formArg{t, clusterRefArg},
			flags: []formFlag{{name: "image", ask: "Which image should it run now?", required: true, example: "ghcr.io/acme/api:1.4.3",
				help: "The full image name with its new tag, as in docker pull."}, clusterWaitFlag}},
		"cluster rollback": {args: []formArg{t, clusterRefArg}, flags: []formFlag{clusterWaitFlag}},
		"cluster restart":  {args: []formArg{t, clusterRefArg}, flags: []formFlag{clusterWaitFlag}},
		"cluster scale": {args: []formArg{t, clusterRefArg, {ask: "How many copies (replicas) should run?", example: "3",
			help: "0 stops every copy, and the app is down until you scale it up again. komando asks a person first."}}, flags: []formFlag{clusterWaitFlag}},
		"cluster apply": {args: []formArg{t}, flags: []formFlag{{name: "file", ask: "Which YAML file on this computer?", required: true,
			example: "./k8s/app.yaml", help: "The objects in it are created, or changed to match it."},
			{name: "stack", ask: "Swarm only: the stack's name (empty on Kubernetes)", example: "shop"}}},
		"cluster rm": {args: []formArg{t, clusterTypeArg, clusterNameArg}},
		"cluster exec": {args: []formArg{t, clusterPodArg, {ask: "Which command should run in the pod?", example: "env"}},
			flags: []formFlag{{name: "read-only", ask: "Does the command only look, changing nothing?"}}},
		"cluster shell": {args: []formArg{t, clusterPodArg, {ask: "A command instead of a shell? (leave empty for the usual shell)", example: "bash",
			help: "Empty: the usual shell of the container."}}},
		"cluster forward": {args: []formArg{t, {ask: "Which pod or service?", example: "service/web",
			help: "A kind and name, like service/web or deployment/api."},
			{ask: "Which port of it?", label: "Port", def: "80", example: "80 or 9000:80",
				help: "The port it listens on. LOCAL:REMOTE picks the port on this computer too; you then open 127.0.0.1:LOCAL."}}},
		"cluster run": {args: []formArg{t, {ask: "Which kubectl or docker command? (without kubectl or docker in front)",
			example: "get pods -o wide", help: "It runs as the cluster's own tool would run it."}},
			flags: []formFlag{{name: "write", ask: "Does it change the cluster?",
				help: "No: komando refuses a command that would change something."}}},
	}
}
