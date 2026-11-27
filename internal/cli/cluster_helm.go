package cli

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/snippet"
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

// helmRevisions reads every stored revision of one release, oldest first.
func helmRevisions(ctx context.Context, k *kube.Client, ns, release string) ([]helmRelease, error) {
	items, err := helmItems(ctx, k, ns, release)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, out.Errf(out.ExitNotFound, "HELM_RELEASE_NOT_FOUND",
			"see the releases with `komando cluster helm list TARGET -A`, and name the namespace with --namespace",
			"no Helm release named %q in namespace %q", release, ns)
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

// helmSnippets are the ready-made snippets that keep the Helm reads when
// `cluster helm` goes (row C631): a client call on the Kubernetes API, no
// helm program, nothing changed.
func helmSnippets() []snippet.Builtin {
	name := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	longName := strings.Repeat("a", 63)
	namespace := snippet.Var{Name: "namespace", Channel: snippet.KubeName, Pattern: name, MaxLen: 63, Longest: longName}
	checks := []string{"TestHelmSnippets", "TestHelmSnippetForbidden"}
	return []snippet.Builtin{
		{
			Name: "helm-list", Type: "cluster", Replaces: "cluster helm list", Reader: "agent: the Helm releases of a cluster without the helm program (row C631)",
			Tier: capability.Read, Shape: "helm-list/1", Checks: checks,
			Vars: []snippet.Var{namespace},
			Run: func(ctx context.Context, c snippet.Client, v snippet.Values) (any, error) {
				k := c.(*clusterClient).kube
				items, err := helmItems(ctx, k, v["namespace"], "")
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
				res := map[string]any{"count": len(rels), "releases": rels}
				if v["namespace"] != "" {
					res["namespace"] = v["namespace"]
				}
				return res, nil
			},
		},
		{
			Name: "helm-release", Type: "cluster", Replaces: "cluster helm status", Reader: "agent: one Helm release, its history and values, without the helm program (row C631)",
			Tier: capability.Read, Shape: "helm-release/1", Checks: checks,
			Vars: []snippet.Var{
				{Name: "release", Channel: snippet.KubeName, Pattern: name, MaxLen: 63, Longest: longName, Required: true},
				namespace,
				{Name: "revision", Channel: snippet.Number, Pattern: regexp.MustCompile(`^[0-9]{1,9}$`), MaxLen: 9, Longest: "999999999", Default: "0"},
			},
			Run: func(ctx context.Context, c snippet.Client, v snippet.Values) (any, error) {
				k := c.(*clusterClient).kube
				n, err := strconv.Atoi(v["revision"])
				if err != nil {
					return nil, out.Usage("--var revision is a revision number from 1; leave it out for the newest")
				}
				revs, err := helmRevisions(ctx, k, cmp.Or(v["namespace"], k.Namespace), v["release"])
				if err != nil {
					return nil, err
				}
				r, err := pickRevision(revs, n)
				if err != nil {
					return nil, err
				}
				history := make([]map[string]any, len(revs))
				for i, h := range revs {
					history[i] = map[string]any{"revision": h.Version, "updated": h.Info.LastDeployed, "status": h.Info.Status,
						"chart": h.chart(), "app_version": h.Chart.Metadata.AppVersion, "description": h.Info.Description}
				}
				vals := r.Config
				if vals == nil {
					vals = map[string]any{}
				}
				return map[string]any{"name": r.Name, "namespace": r.Namespace, "revision": r.Version, "status": r.Info.Status,
					"chart": r.chart(), "app_version": r.Chart.Metadata.AppVersion, "first_deployed": r.Info.FirstDeployed,
					"last_deployed": r.Info.LastDeployed, "description": r.Info.Description, "notes": r.Info.Notes,
					"values": vals, "values_all": mergeValues(r.Chart.Values, r.Config), "history": history}, nil
			},
		},
	}
}
