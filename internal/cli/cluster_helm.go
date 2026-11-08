package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

// Helm keeps each revision of a release in the cluster itself, as a
// Secret (or a ConfigMap) labeled owner=helm, holding the release as
// gzipped JSON. komando reads those, so it needs no helm program and
// changes nothing: installs and upgrades stay with helm.

// helmRelease is the part of a stored Helm release komando shows.
type helmRelease struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Version   int    `json:"version"`
	Info      struct {
		FirstDeployed string `json:"first_deployed"`
		LastDeployed  string `json:"last_deployed"`
		Description   string `json:"description"`
		Status        string `json:"status"`
		Notes         string `json:"notes"`
	} `json:"info"`
	Chart struct {
		Metadata struct {
			Name       string `json:"name"`
			Version    string `json:"version"`
			AppVersion string `json:"appVersion"`
		} `json:"metadata"`
		Values map[string]any `json:"values"`
	} `json:"chart"`
	Config map[string]any `json:"config"`
}

func (r helmRelease) chart() string {
	return strings.TrimSuffix(r.Chart.Metadata.Name+"-"+r.Chart.Metadata.Version, "-")
}

// helmItem is one stored revision, before its release is decoded.
type helmItem struct {
	name, namespace, status string
	version                 int
	data                    string // the release field as the API gives it
	secret                  bool   // a Secret's data is base64 once more
}

// helmItems lists the stored revisions in ns ("" = every namespace),
// only of release when it is not "".
func helmItems(ctx context.Context, k *kube.Client, ns, release string) ([]helmItem, error) {
	sel := "owner=helm"
	if release != "" {
		sel += ",name=" + release
	}
	var items []helmItem
	for _, kind := range []string{"secrets", "configmaps"} {
		path := "/api/v1/" + kind
		if ns != "" {
			path = "/api/v1/namespaces/" + url.PathEscape(ns) + "/" + kind
		}
		var list struct {
			Items []struct {
				Metadata struct {
					Namespace string            `json:"namespace"`
					Labels    map[string]string `json:"labels"`
				} `json:"metadata"`
				Data map[string]string `json:"data"`
			} `json:"items"`
		}
		if err := k.Get(ctx, path, url.Values{"labelSelector": {sel}}, &list); err != nil {
			var ae *kube.APIError
			if errors.As(err, &ae) && (ae.Code == 403 || ae.Code == 401) && kind == "configmaps" && len(items) > 0 {
				break // releases were in Secrets; ConfigMaps are only the old storage
			}
			if errors.As(err, &ae) && (ae.Code == 403 || ae.Code == 401) {
				return nil, out.Errf(out.ExitConnect, "K8S_FORBIDDEN",
					"Helm keeps releases as Secrets: the kubeconfig's user needs to list secrets there (or name one namespace with --namespace)",
					"listing Helm releases: %v", ae.Message)
			}
			return nil, err
		}
		for _, it := range list.Items {
			v, _ := strconv.Atoi(it.Metadata.Labels["version"])
			items = append(items, helmItem{name: it.Metadata.Labels["name"], namespace: it.Metadata.Namespace,
				status: it.Metadata.Labels["status"], version: v, data: it.Data["release"], secret: kind == "secrets"})
		}
	}
	return items, nil
}

// decode turns a stored revision into its release.
func (it helmItem) decode() (helmRelease, error) {
	var r helmRelease
	s := it.data
	if it.secret { // the API's base64 of a Secret value
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return r, err
		}
		s = string(b)
	}
	b, err := base64.StdEncoding.DecodeString(s) // Helm's own base64
	if err != nil {
		return r, err
	}
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return r, err
		}
		if b, err = io.ReadAll(io.LimitReader(zr, 64<<20)); err != nil {
			return r, err
		}
	}
	err = json.Unmarshal(b, &r)
	return r, err
}

// latest keeps the newest revision of each release.
func latest(items []helmItem) []helmItem {
	top := map[string]helmItem{}
	for _, it := range items {
		key := it.namespace + "/" + it.name
		if cur, ok := top[key]; !ok || it.version > cur.version {
			top[key] = it
		}
	}
	res := make([]helmItem, 0, len(top))
	for _, it := range top {
		res = append(res, it)
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].namespace != res[j].namespace {
			return res[i].namespace < res[j].namespace
		}
		return res[i].name < res[j].name
	})
	return res
}

// helmList is `cluster helm ls`.
type helmList map[string]any

func (l helmList) Text() string {
	rels, _ := l["releases"].([]map[string]any)
	if len(rels) == 0 {
		return "no Helm releases\n"
	}
	rows := make([][]string, len(rels))
	for i, r := range rels {
		rows[i] = []string{fmt.Sprint(r["name"]), fmt.Sprint(r["namespace"]), fmt.Sprint(r["revision"]),
			fmt.Sprint(r["status"]), fmt.Sprint(r["chart"]), fmt.Sprint(r["app_version"]), fmt.Sprint(r["updated"])}
	}
	return textTable([]string{"NAME", "NAMESPACE", "REVISION", "STATUS", "CHART", "APP VERSION", "UPDATED"}, rows)
}

func helmLsCmd() *cobra.Command {
	var ns string
	var all bool
	c := &cobra.Command{
		Use:   "ls TARGET",
		Short: "Helm releases: name, revision, status, chart and app version",
		Example: `  komando cluster helm ls prod-k8s -A
  komando cluster helm ls prod-k8s --namespace shop
  komando cluster helm ls @prod -A              # every cluster in the group`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			ts, err := resolveClusters(st, args[0])
			if err != nil {
				return err
			}
			return readClusters(cmd.Context(), "cluster.helm.ls", st, ts, clusterRead{swarmNo: helmNoSwarm,
				kube: func(ctx context.Context, t clusterTarget, k *kube.Client) (any, error) {
					space := firstNonEmpty(ns, k.Namespace)
					if all {
						space = ""
					}
					items, err := helmItems(ctx, k, space, "")
					if err != nil {
						return nil, err
					}
					rels := []map[string]any{}
					for _, it := range latest(items) {
						row := map[string]any{"name": it.name, "namespace": it.namespace, "revision": it.version, "status": it.status}
						if r, err := it.decode(); err == nil {
							row["chart"], row["app_version"], row["updated"] = r.chart(), r.Chart.Metadata.AppVersion, r.Info.LastDeployed
						} else {
							row["error"] = "cannot read the stored release: " + err.Error()
						}
						rels = append(rels, row)
					}
					res := helmList{"conn": t.conn.Name, "count": len(rels), "releases": rels}
					if !all {
						res["namespace"] = space
					}
					return res, nil
				}})
		},
	}
	nsFlags(c, &ns, &all, nil)
	return c
}

const helmNoSwarm = "Helm is for Kubernetes; on Swarm, `cluster ls TARGET stacks` lists the stacks"

// helmRevisions reads every stored revision of one release, oldest first.
func helmRevisions(ctx context.Context, k *kube.Client, ns, release string) ([]helmRelease, error) {
	items, err := helmItems(ctx, k, ns, release)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, out.Errf(out.ExitNotFound, "HELM_RELEASE_NOT_FOUND",
			"see the releases with `komando cluster helm ls TARGET -A`, and name the namespace with --namespace",
			"no Helm release %q in namespace %q", release, ns)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].version < items[j].version })
	revs := make([]helmRelease, 0, len(items))
	for _, it := range items {
		r, err := it.decode()
		if err != nil {
			return nil, fmt.Errorf("revision %d of %s: cannot read the stored release: %w", it.version, release, err)
		}
		if r.Version == 0 {
			r.Version = it.version
		}
		revs = append(revs, r)
	}
	return revs, nil
}

// pickRevision is revision n of revs, or the newest when n is 0.
func pickRevision(revs []helmRelease, n int) (helmRelease, error) {
	if n == 0 {
		return revs[len(revs)-1], nil
	}
	for _, r := range revs {
		if r.Version == n {
			return r, nil
		}
	}
	return helmRelease{}, out.Errf(out.ExitNotFound, "HELM_REVISION_NOT_FOUND",
		"see the revisions with `komando cluster helm history TARGET RELEASE`", "%s has no revision %d", revs[0].Name, n)
}

// helmOne runs a read on one release of one cluster.
func helmOne(cmd *cobra.Command, name, target, release, ns string, fn func(t clusterTarget, revs []helmRelease) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	t, err := resolveCluster(st, target)
	if err != nil {
		return err
	}
	if t.host != nil {
		return out.Usage("%s", helmNoSwarm)
	}
	return withKube(cmd.Context(), name, t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
		revs, err := helmRevisions(ctx, k, firstNonEmpty(ns, k.Namespace), release)
		if err != nil {
			return nil, err
		}
		return fn(t, revs)
	})
}

// helmText is a short record, then a block of text (notes, values).
type helmText struct {
	fields map[string]any
	order  []string
	block  string
}

func (h helmText) MarshalJSON() ([]byte, error) { return json.Marshal(h.fields) }

func (h helmText) Text() string {
	var b strings.Builder
	for _, k := range h.order {
		if v, ok := h.fields[k]; ok && fmt.Sprint(v) != "" {
			fmt.Fprintf(&b, "%-15s %v\n", strings.ReplaceAll(k, "_", " ")+":", v)
		}
	}
	if h.block != "" {
		b.WriteString("\n" + strings.TrimRight(h.block, "\n") + "\n")
	}
	return b.String()
}

func helmStatusCmd() *cobra.Command {
	var ns string
	var revision int
	c := &cobra.Command{
		Use:     "status TARGET RELEASE",
		Short:   "One Helm release: status, chart, when it was deployed, and its notes",
		Example: `  komando cluster helm status prod-k8s shop-api --namespace shop`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return helmOne(cmd, "cluster.helm.status", args[0], args[1], ns, func(t clusterTarget, revs []helmRelease) (any, error) {
				r, err := pickRevision(revs, revision)
				if err != nil {
					return nil, err
				}
				f := map[string]any{"conn": t.conn.Name, "name": r.Name, "namespace": r.Namespace, "revision": r.Version,
					"status": r.Info.Status, "chart": r.chart(), "app_version": r.Chart.Metadata.AppVersion,
					"first_deployed": r.Info.FirstDeployed, "last_deployed": r.Info.LastDeployed,
					"description": r.Info.Description, "notes": r.Info.Notes}
				return helmText{fields: f, block: r.Info.Notes, order: []string{"name", "namespace", "revision", "status",
					"chart", "app_version", "first_deployed", "last_deployed", "description"}}, nil
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	c.Flags().IntVar(&revision, "revision", 0, "this revision instead of the newest")
	return c
}

func helmHistoryCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:     "history TARGET RELEASE",
		Short:   "Every stored revision of a Helm release, oldest first",
		Example: `  komando cluster helm history prod-k8s shop-api --namespace shop`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return helmOne(cmd, "cluster.helm.history", args[0], args[1], ns, func(t clusterTarget, revs []helmRelease) (any, error) {
				rows := make([]map[string]any, len(revs))
				for i, r := range revs {
					rows[i] = map[string]any{"revision": r.Version, "updated": r.Info.LastDeployed, "status": r.Info.Status,
						"chart": r.chart(), "app_version": r.Chart.Metadata.AppVersion, "description": r.Info.Description}
				}
				return helmHistory{"conn": t.conn.Name, "name": args[1], "namespace": revs[0].Namespace, "revisions": rows}, nil
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	return c
}

type helmHistory map[string]any

func (h helmHistory) Text() string {
	revs, _ := h["revisions"].([]map[string]any)
	rows := make([][]string, len(revs))
	for i, r := range revs {
		rows[i] = []string{fmt.Sprint(r["revision"]), fmt.Sprint(r["updated"]), fmt.Sprint(r["status"]),
			fmt.Sprint(r["chart"]), fmt.Sprint(r["app_version"]), fmt.Sprint(r["description"])}
	}
	return textTable([]string{"REVISION", "UPDATED", "STATUS", "CHART", "APP VERSION", "DESCRIPTION"}, rows)
}

func helmValuesCmd() *cobra.Command {
	var ns string
	var revision int
	var all bool
	c := &cobra.Command{
		Use:   "values TARGET RELEASE",
		Short: "The values a Helm release was installed with (--all: with the chart's defaults)",
		Example: `  komando cluster helm values prod-k8s shop-api --namespace shop
  komando cluster helm values prod-k8s shop-api --namespace shop --all --revision 3`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return helmOne(cmd, "cluster.helm.values", args[0], args[1], ns, func(t clusterTarget, revs []helmRelease) (any, error) {
				r, err := pickRevision(revs, revision)
				if err != nil {
					return nil, err
				}
				vals := r.Config
				if all {
					vals = mergeValues(r.Chart.Values, r.Config)
				}
				if vals == nil {
					vals = map[string]any{}
				}
				y, _ := yaml.Marshal(vals)
				f := map[string]any{"conn": t.conn.Name, "name": r.Name, "namespace": r.Namespace, "revision": r.Version, "values": vals}
				return helmText{fields: f, block: string(y), order: []string{"name", "namespace", "revision"}}, nil
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	c.Flags().IntVar(&revision, "revision", 0, "this revision instead of the newest")
	c.Flags().BoolVar(&all, "all", false, "the chart's default values too, as Helm merged them")
	return c
}

// mergeValues lays over on top of base, map by map, as Helm does.
func mergeValues(base, over map[string]any) map[string]any {
	res := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		res[k] = v
	}
	for k, v := range over {
		if bm, ok := res[k].(map[string]any); ok {
			if om, ok := v.(map[string]any); ok {
				res[k] = mergeValues(bm, om)
				continue
			}
		}
		res[k] = v
	}
	return res
}

func clusterHelmCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "helm",
		Short: "Helm releases, read-only: ls, status, history, values (no helm program needed)",
		Long: `Reads the Helm releases stored in a Kubernetes cluster, without the helm
program. It only reads: install, upgrade and rollback stay with helm. The
kubeconfig's user needs to list Secrets where the releases are.`,
	}
	c.AddCommand(helmLsCmd(), helmStatusCmd(), helmHistoryCmd(), helmValuesCmd())
	return c
}
