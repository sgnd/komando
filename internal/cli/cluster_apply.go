package cli

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func clusterApplyCmd() *cobra.Command {
	var file, ns, stack string
	var forceConflicts bool
	c := &cobra.Command{
		Use:   "apply TARGET --file FILE",
		Short: "Apply Kubernetes YAML or deploy a Swarm stack",
		Long: `Kubernetes: applies every object in FILE server-side and says per object
whether it was created, configured or unchanged. --dry-run asks the server
what would change and shows it as a diff (Secret values stay hidden; a
changed value shows as "(hidden, changed)"). Objects without a namespace go
to --namespace; one that names another namespace is refused.

A field another field manager owns (an autoscaler's replicas, a kubectl
edit) stops the apply with K8S_CONFLICT naming that manager, and nothing
is applied. --force-conflicts takes those fields over, as
` + "`kubectl apply --server-side --force-conflicts`" + ` does.

Swarm: deploys FILE (a compose file) as the stack --stack; --dry-run checks
the file with ` + "`docker stack config`" + ` on the manager.`,
		Example: `  komando cluster apply prod-k8s --file app.yaml --dry-run
  komando cluster apply prod-k8s --file app.yaml
  komando cluster apply swarm1 --file compose.yml --stack shop`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if file == "" {
				return out.Usage("give the YAML with --file")
			}
			b, err := readFileOrStdin(cl, file)
			if err != nil {
				return localFileErr("FILE_NOT_FOUND", err, "")
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(cl, st, args[0])
			if err != nil {
				return err
			}
			if t.host != nil {
				if err := noNamespace(t, ns); err != nil {
					return err
				}
				if stack == "" {
					return out.Usage("Swarm needs --stack NAME")
				}
				if forceConflicts {
					return out.Usage("--force-conflicts is for Kubernetes; Swarm has no field managers")
				}
				return swarmApply(cl, cmd.Context(), t, stack, b)
			}
			if stack != "" {
				return out.Usage("--stack is for Swarm; Kubernetes objects take their namespace from the file or --namespace")
			}

			docs, err := splitYAML(b)
			if err != nil {
				return out.Usage("%s: %v", file, err)
			}
			if err := refuseHidden(docs); err != nil {
				return err
			}
			for _, d := range docs {
				if d.Namespace != "" && ns != "" && d.Namespace != ns {
					return out.Usage("%s/%s is in namespace %s in the file, not %s from --namespace: leave out --namespace or change the file", strings.ToLower(d.Kind), d.Name, d.Namespace, ns)
				}
			}
			extra := map[string]any{"file": file, "objects": len(docs)}
			if forceConflicts {
				extra["force_conflicts"] = true
			}
			return withKube(cl, cmd.Context(), "cluster.apply", t, driver.RiskWrite, extra, func(ctx context.Context, k *kube.Client) (any, error) {
				return kubeApply(cl, ctx, k, t.conn.Name, docs, ns, forceConflicts)
			})
		}),
	}
	c.Flags().StringVarP(&file, "file", "f", "", "YAML file ('-' for stdin)")
	c.Flags().StringVar(&stack, "stack", "", "Swarm: the stack name")
	c.Flags().BoolVar(&forceConflicts, "force-conflicts", false, "Kubernetes: take over fields another field manager owns")
	nsFlags(c, &ns, nil, nil)
	return c
}

// kubeApply applies docs server-side (a dry run asks the server only) and
// reports per object what happened, or would. A real apply first sends the
// whole file as a server dry run: an object the cluster refuses (a typo, a
// field it does not know, an unknown kind) stops it before anything
// changes, instead of half the file being applied. Without force a field
// another manager owns stops it (K8S_CONFLICT); force takes it over.
func kubeApply(cl *call, ctx context.Context, k *kube.Client, conn string, docs []kubeDoc, ns string, force bool) (any, error) {
	if !cl.flags.dryRun {
		if _, err := applyPass(cl, ctx, k, conn, docs, ns, true, force); err != nil {
			var oe *out.Error
			if errors.As(err, &oe) {
				oe.Message = "nothing was applied: " + oe.Message
				return nil, oe
			}
			return nil, fmt.Errorf("nothing was applied: %w", err)
		}
	}
	return applyPass(cl, ctx, k, conn, docs, ns, cl.flags.dryRun, force)
}

// applyPass applies docs once, as a server dry run (dry) or for real.
func applyPass(cl *call, ctx context.Context, k *kube.Client, conn string, docs []kubeDoc, ns string, dry, force bool) (applyData, error) {
	q := url.Values{"fieldManager": {"komando"}}
	if force {
		q.Set("force", "true")
	}
	if dry {
		q.Set("dryRun", "All")
	}
	res := applyData{Conn: conn, DryRun: dry, Objects: []objectChange{}}
	creates := map[string]bool{} // namespaces this file creates
	for _, d := range docs {
		r, err := k.ResourceFor(ctx, d.APIVersion, d.Kind)
		var uk *kube.UnknownKindError
		if errors.As(err, &uk) {
			return res, out.Usage("%v", err)
		}
		if err != nil {
			return res, err // the cluster could not be asked: kubeErr says why
		}
		space := ""
		if r.IsNamespaced() {
			space = cmp.Or(d.Namespace, ns, k.Namespace)
		}
		path := r.ObjectPath(space, d.Name)
		name := strings.ToLower(d.Kind) + "/" + d.Name
		// the live object, to say what changes
		before, err := k.Do(ctx, "GET", path, nil, nil, "")
		var ae *kube.APIError
		if err != nil && !(errors.As(err, &ae) && ae.Code == 404) {
			return res, fmt.Errorf("%s: %w", name, err)
		}
		if dry && before == nil && creates[space] {
			// the server cannot dry-run into a namespace that does not exist yet
			res.Objects = append(res.Objects, objectChange{Object: name, Namespace: space, Action: "create", Note: "in namespace " + space + ", which this file creates"})
			continue
		}
		after, err := k.Do(ctx, "PATCH", path, q, d.JSON, "application/apply-patch+yaml")
		if errors.As(err, &ae) && ae.Code == 409 && strings.HasPrefix(ae.Message, "Apply failed with") {
			// the server's words name the other manager and its fields
			return res, out.Errf(out.ExitConflict, "K8S_CONFLICT",
				"another field manager owns these fields (named above): leave them out of the file, or take them over with `komando cluster apply TARGET --file FILE --force-conflicts`",
				"%s: %s", name, ae.Message)
		}
		if err != nil {
			return res, fmt.Errorf("%s: %w", name, err)
		}
		if d.Kind == "Namespace" && before == nil {
			creates[d.Name] = true
		}
		c := diffObject(cl, name, before, after)
		c.Namespace = space
		if !dry {
			c.Diff = ""
			c.Action = map[string]string{"create": "created", "change": "configured", "none": "unchanged"}[c.Action]
		}
		res.Objects = append(res.Objects, c)
	}
	return res, nil
}

// applyData is `cluster apply`: what happened to each object (created,
// configured, unchanged), or with --dry-run what would (create, change,
// none) and the diff.
type applyData struct {
	Conn    string         `json:"conn"`
	DryRun  bool           `json:"dry_run"`
	Objects []objectChange `json:"-"`
}

func (a applyData) MarshalJSON() ([]byte, error) {
	names := make([]string, len(a.Objects))
	for i, o := range a.Objects {
		names[i] = o.Object
	}
	m := map[string]any{"conn": a.Conn, "dry_run": a.DryRun}
	if a.DryRun {
		m["would_apply"], m["changes"] = names, a.Objects
	} else {
		m["applied"], m["objects"] = names, a.Objects
	}
	return json.Marshal(m)
}

func (a applyData) Text() string {
	var b strings.Builder
	words := map[string]string{"create": "would be created", "change": "would change", "none": "unchanged"}
	for _, o := range a.Objects {
		what := o.Action
		if a.DryRun {
			what = words[o.Action]
		}
		line := o.Object
		if o.Namespace != "" {
			line += " (" + o.Namespace + ")"
		}
		fmt.Fprintf(&b, "%s %s\n", line, what)
		if o.Note != "" {
			fmt.Fprintf(&b, "  note: %s\n", o.Note)
		}
		if o.Diff != "" && o.Action != "create" {
			b.WriteString(indentText(o.Diff, "    "))
		}
	}
	return b.String()
}

// objectChange is one object in `cluster apply`: what the server did or
// would do with it, and with --dry-run the difference as a unified diff.
type objectChange struct {
	Object    string `json:"object"`
	Namespace string `json:"namespace,omitempty"`
	Action    string `json:"action"` // create | change | none (dry run); created | configured | unchanged
	Diff      string `json:"diff,omitempty"`
	Note      string `json:"note,omitempty"`
}

func diffObject(cl *call, name string, before, after []byte) objectChange {
	c := objectChange{Object: name, Action: "change"}
	parse := func(b []byte) map[string]any {
		var o map[string]any
		if len(b) == 0 || json.Unmarshal(b, &o) != nil {
			return nil
		}
		delete(o, "status")
		if m, ok := o["metadata"].(map[string]any); ok {
			for _, f := range []string{"managedFields", "resourceVersion", "generation", "uid", "creationTimestamp", "selfLink"} {
				delete(m, f)
			}
			if a, ok := m["annotations"].(map[string]any); ok {
				delete(a, "kubectl.kubernetes.io/last-applied-configuration")
				if len(a) == 0 {
					delete(m, "annotations")
				}
			}
		}
		return o
	}
	old, upd := parse(before), parse(after)
	switch {
	case before == nil:
		c.Action = "create"
	case yamlText(old) == yamlText(upd): // compared with Secret values, so a changed value counts
		c.Action = "none"
		return c
	}
	hideSecretValues(old, upd) // Secret values never reach the output, not even in a diff
	if cl.out.Mask {
		hideSecretEnv(old)
		hideSecretEnv(upd)
	}
	c.Diff = unifiedDiff(yamlText(old), yamlText(upd), 3)
	return c
}

// hideSecretValues replaces a Secret's values with markers that still say
// which keys changed: (hidden), (hidden, changed), (hidden, new).
func hideSecretValues(old, upd map[string]any) {
	isSecret := func(o map[string]any) bool { return o != nil && o["kind"] == "Secret" }
	if !isSecret(old) && !isSecret(upd) {
		return
	}
	for _, f := range []string{"data", "stringData"} {
		od, _ := old[f].(map[string]any)
		nd, _ := upd[f].(map[string]any)
		for k, v := range nd {
			ov, had := od[k]
			switch {
			case !had && old != nil:
				nd[k] = "(hidden, new)"
			case had && fmt.Sprint(ov) != fmt.Sprint(v):
				nd[k] = "(hidden, changed)"
			default:
				nd[k] = "(hidden)"
			}
		}
		for k := range od {
			od[k] = "(hidden)"
		}
	}
}

// yamlText is o as YAML with 2-space indents, like kubectl prints it.
func yamlText(o map[string]any) string {
	if o == nil {
		return ""
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	_ = enc.Encode(o)
	_ = enc.Close()
	return b.String()
}

// swarmApply deploys a compose file as a stack; --dry-run checks the file
// with `docker stack config` and names the services it would make.
func swarmApply(cl *call, ctx context.Context, t clusterTarget, stack string, file []byte) error {
	line := "docker stack deploy --detach=true -c - " + sshx.Q(stack) + " 2>&1"
	if cl.flags.dryRun {
		st, err := loadState()
		if err != nil {
			return err
		}
		if err := guard(cl, st, []*store.Host{t.host}, line, true); err != nil {
			return err
		}
		res := map[string]any{"host": t.host.Name, "stack": stack, "dry_run": true, "would_run": line}
		cfg, err := swarmExec(cl, ctx, st, t, "docker stack config -c - 2>&1", file)
		if err != nil {
			msg := toErr(err).Message
			if strings.Contains(msg, "unknown command") || strings.Contains(msg, "is not a docker command") {
				res["checked"] = false // docker before 23 has no stack config
				cl.out.Print("cluster.apply", res, nil)
				return nil
			}
			return out.Usage("the compose file is not valid: %s", msg)
		}
		var c struct {
			Services map[string]any `yaml:"services"`
		}
		_ = yaml.Unmarshal([]byte(cfg), &c)
		var svcs []string
		for n := range c.Services {
			svcs = append(svcs, "service/"+stack+"_"+n)
		}
		sort.Strings(svcs)
		res["checked"], res["would_apply"] = true, svcs
		cl.out.Print("cluster.apply", res, nil)
		return nil
	}
	s, _, err := swarmDo(cl, ctx, "cluster.apply", t, line, file, driver.RiskWrite, line)
	if err != nil {
		return err
	}
	objs := []map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && (f[0] == "Creating" || f[0] == "Updating") {
			act := map[string]string{"Creating": "created", "Updating": "configured"}[f[0]]
			objs = append(objs, map[string]string{"object": f[1] + "/" + f[2], "action": act})
		}
	}
	cl.out.Print("cluster.apply", map[string]any{"host": t.host.Name, "stack": stack, "objects": objs, "output": s}, nil)
	return nil
}

type kubeDoc struct {
	APIVersion, Kind, Name, Namespace string
	JSON                              []byte
}

// splitYAML reads a multi-document YAML file into objects.
func splitYAML(b []byte) ([]kubeDoc, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var docs []kubeDoc
	for {
		var o map[string]any
		if err := dec.Decode(&o); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
		if len(o) == 0 {
			continue
		}
		m, _ := o["metadata"].(map[string]any)
		d := kubeDoc{APIVersion: fmt.Sprint(o["apiVersion"]), Kind: fmt.Sprint(o["kind"]), Name: fmt.Sprint(m["name"])}
		if ns, ok := m["namespace"].(string); ok {
			d.Namespace = ns
		}
		if d.Kind == "<nil>" || d.Name == "<nil>" || d.APIVersion == "<nil>" || d.Name == "" {
			return nil, fmt.Errorf("every object needs apiVersion, kind and metadata.name")
		}
		var err error
		if d.JSON, err = json.Marshal(o); err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no objects found")
	}
	return docs, nil
}
