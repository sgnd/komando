package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/registry"
	"github.com/sgnd/komando/internal/store"
)

// `komando registry` reads and cleans up container registries through the
// OCI Distribution API, reached through --via paths and VPNs like any conn.

func registryCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "registry",
		Aliases: []string{"oci"},
		Short:   "Container registries: list repositories and tags, inspect images, delete tags",
		Long: `Works with a registry conn: ` + "`komando conn add ghcr registry://myuser@ghcr.io --password-ref secret:ghcr-token`" + `
or ` + "`komando import docker`" + ` (from ~/.docker/config.json). ls and inspect
only read; rm deletes an image and needs --allow-dangerous.`,
	}
	c.AddCommand(registryLsCmd(), registryInspectCmd(), registryRmCmd())
	return c
}

// withRegistry opens a registry conn and runs fn after the safety check.
func withRegistry(ctx context.Context, name, expr string, risk driver.Risk, extra map[string]any,
	fn func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, expr, "registry")
	if err != nil {
		return err
	}
	if err := guardConns(st, []*store.Conn{c}, driver.Verdict{Risk: risk, RuleIDs: []string{"registry"}, Reasons: []string{name}}); err != nil {
		if g.dryRun {
			out.P.Print(name, map[string]any{"conn": c.Name, "dry_run": true, "would_be_blocked": toErr(err)}, nil)
			return nil
		}
		return err
	}
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return err
	}
	defer a.Close()
	host, port, _ := net.SplitHostPort(a.Target.Address)
	if port != "443" {
		host = a.Target.Address
	}
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if a.Dial != nil {
		dial = a.Dial
	}
	rc := registry.New(host, a.Target.TLS == "false", a.Target.User, a.Password, dial)
	res, err := fn(ctx, c, rc)
	if err != nil {
		err = registryErr(err)
	}
	if risk > driver.RiskRead {
		rec := map[string]any{"conns": []string{c.Name}, "risk": risk.String()}
		for k, v := range extra {
			rec[k] = v
		}
		audit(st, name, nil, "", err == nil, rec)
	}
	if err != nil {
		return err
	}
	out.P.Print(name, res, nil)
	return nil
}

func registryErr(err error) error {
	if e, ok := err.(*registry.Error); ok {
		code, exit := "REGISTRY_ERROR", out.ExitRemote
		hint := ""
		switch e.Status {
		case 401, 403:
			code, exit, hint = "REGISTRY_AUTH", out.ExitConnect, "check the user in the conn URL and its --password-ref (a token with the right scopes)"
		case 404:
			code, exit = "REGISTRY_NOT_FOUND", out.ExitNotFound
		case 405:
			code, hint = "REGISTRY_UNSUPPORTED", "this registry does not allow it (Docker Hub and GHCR have no catalog; deletes may be turned off)"
		}
		return out.Errf(exit, code, hint, "%s", e.Error())
	}
	if _, ok := err.(*out.Error); ok {
		return err
	}
	return out.Errf(out.ExitConnect, "REGISTRY_UNREACHABLE", "check the conn with `komando test NAME`", "%v", err)
}

// splitImage parses REPO[:TAG|@DIGEST]; the tag defaults to latest.
func splitImage(s string) (repo, ref string) {
	if i := strings.Index(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		return s[:i], s[i+1:]
	}
	return s, "latest"
}

func registryLsCmd() *cobra.Command {
	var limit int
	c := &cobra.Command{
		Use:   "ls CONN [REPO]",
		Short: "List repositories, or the tags of one repository",
		Example: `  komando registry ls harbor
  komando registry ls ghcr myorg/api`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withRegistry(cmd.Context(), "registry.ls", args[0], driver.RiskRead, nil, func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error) {
				if len(args) == 1 {
					repos, err := r.Catalog(ctx, limit)
					if err != nil {
						return nil, err
					}
					return map[string]any{"conn": c.Name, "count": len(repos), "repositories": repos}, nil
				}
				tags, err := r.Tags(ctx, args[1], limit)
				if err != nil {
					return nil, err
				}
				return map[string]any{"conn": c.Name, "repo": args[1], "count": len(tags), "tags": tags}, nil
			})
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 1000, "max entries")
	return c
}

func registryInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "inspect CONN REPO[:TAG|@DIGEST]",
		Aliases: []string{"get", "show"},
		Short:   "Digest, size, platforms, created time and labels of an image",
		Example: "  komando registry inspect ghcr myorg/api:1.4.2",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withRegistry(cmd.Context(), "registry.inspect", args[0], driver.RiskRead, nil, func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error) {
				repo, ref := splitImage(args[1])
				return r.Inspect(ctx, repo, ref)
			})
		},
	}
}

func registryRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm CONN REPO[:TAG|@DIGEST]",
		Short:   "Delete an image (every tag that points at it goes too); needs --allow-dangerous",
		Example: "  komando registry rm harbor myorg/api:old --allow-dangerous",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withRegistry(cmd.Context(), "registry.rm", args[0], driver.RiskDestructive, map[string]any{"image": args[1]},
				func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error) {
					repo, ref := splitImage(args[1])
					m, err := r.Inspect(ctx, repo, ref)
					if err != nil {
						return nil, err
					}
					if m.Digest == "" {
						return nil, out.Errf(out.ExitRemote, "REGISTRY_ERROR", "", "the registry did not say the image's digest")
					}
					if g.dryRun {
						return map[string]any{"conn": c.Name, "would_delete": repo + "@" + m.Digest, "dry_run": true}, nil
					}
					if err := r.Delete(ctx, repo, m.Digest); err != nil {
						return nil, err
					}
					return map[string]any{"conn": c.Name, "deleted": repo + "@" + m.Digest,
						"note": "the space comes back after the registry's garbage collection"}, nil
				})
		},
	}
}

// importDocker reads ~/.docker/config.json: inline auths, and credential
// helpers (docker-credential-*) when the config names one.
func importDocker(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
		CredsStore  string            `json:"credsStore"`
		CredHelpers map[string]string `json:"credHelpers"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, out.Usage("%s: %v", path, err)
	}
	p := newPlan()
	for server, a := range cfg.Auths {
		host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(server, "https://"), "http://"), "/")
		host = strings.TrimSuffix(host, "/v1")
		if host == "index.docker.io" {
			host = "docker.io"
		}
		user, pass := "", ""
		if a.Auth != "" {
			raw, err := base64.StdEncoding.DecodeString(a.Auth)
			if err == nil {
				user, pass, _ = strings.Cut(string(raw), ":")
			}
		} else if helper := firstNonEmpty(cfg.CredHelpers[server], cfg.CredsStore); helper != "" {
			user, pass, err = credHelper(helper, server)
			if err != nil {
				p.Notes = append(p.Notes, fmt.Sprintf("%s: %v", server, err))
				continue
			}
		}
		if user == "" {
			p.Notes = append(p.Notes, server+": no login stored")
			continue
		}
		name := p.name(strings.Split(host, ".")[0])
		if host == "docker.io" {
			name = p.name("dockerhub")
		}
		u := url.URL{Scheme: "registry", User: url.UserPassword(user, pass), Host: host}
		p.addConn(name, u.String(), server)
	}
	return p, nil
}

func credHelper(helper, server string) (string, string, error) {
	c := exec.Command("docker-credential-"+helper, "get")
	c.Stdin = strings.NewReader(server)
	b, err := c.Output()
	if err != nil {
		return "", "", fmt.Errorf("docker-credential-%s: %v", helper, err)
	}
	var r struct{ Username, Secret string }
	if err := json.Unmarshal(b, &r); err != nil {
		return "", "", err
	}
	return r.Username, r.Secret, nil
}
