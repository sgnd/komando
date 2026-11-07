package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/registry"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `komando registry` reads and cleans up container registries through the
// OCI Distribution API, reached through --via paths and VPNs like any conn.

func registryCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "registry",
		Aliases: []string{"oci"},
		Short:   "Container registries: repositories, tags, images, cleanup",
		Long: `Works with a registry conn: ` + "`komando conn add ghcr registry://myuser@ghcr.io --password-ref secret:ghcr-token`" + `
or ` + "`komando import docker`" + ` (from ~/.docker/config.json). ls and inspect
only read; rm and prune delete images and need --allow-dangerous.

TLS options in the conn URL: ?ca=secret:NAME trusts a private CA, or pins the
registry's own certificate (PEM in the vault; the check stays on), ?tls=skip-verify does not check the certificate,
?tls=false is plain HTTP. With --via the last server looks the name up.`,
	}
	c.AddCommand(registryLsCmd(), registryInspectCmd(), registryCopyCmd(), registryRmCmd(), registryPruneCmd())
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
	rc, closeRC, err := openRegistry(ctx, st, c)
	if err != nil {
		return err
	}
	defer closeRC()
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

// openRegistry makes a client for a registry conn, through its --via path.
func openRegistry(ctx context.Context, st *store.State, c *store.Conn) (*registry.Client, func(), error) {
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return nil, nil, err
	}
	host, port, _ := net.SplitHostPort(a.Target.Address)
	if port != "443" {
		host = a.Target.Address
	}
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if a.Dial != nil {
		dial = a.Dial
	}
	user, password := a.Target.User, a.Password
	if region := ecrRegion(strings.TrimSuffix(host, ":443")); region != "" && c.PasswordRef == "" {
		// Amazon ECR logins last 12 hours: get a fresh one each time
		tok, err := ecrToken(ctx, firstNonEmpty(awsProfile(c), "default"), region)
		if err != nil {
			a.Close()
			return nil, nil, err
		}
		user, password = "AWS", tok
	}
	tc, err := registryTLS(a.Target)
	if err != nil {
		a.Close()
		return nil, nil, err
	}
	return registry.New(host, tc, user, password, dial), a.Close, nil
}

// registryTLS turns a registry conn's tls= and ca= options into the
// client's TLS settings; ca= is read from the vault.
func registryTLS(t driver.Target) (registry.TLS, error) {
	tc := registry.TLS{Plain: t.TLS == "false", SkipVerify: t.TLS == "skip-verify"}
	if t.CA == "" {
		return tc, nil
	}
	pem, err := vault.Resolve(t.CA)
	if err != nil {
		code, exit := "SECRET_UNRESOLVED", out.ExitError
		if errors.Is(err, vault.ErrNotFound) {
			code, exit = "SECRET_NOT_FOUND", out.ExitNotFound
		}
		return tc, out.Errf(exit, code, "store the CA certificate with `komando secret set NAME < ca.crt`",
			"registry CA %s: %v", t.CA, err)
	}
	if tc.RootCAs, err = registry.CAPool([]byte(pem)); err != nil {
		return tc, out.Errf(out.ExitUsage, "BAD_CA", "store the registry's CA certificate (PEM) with `komando secret set NAME < ca.crt`",
			"registry CA %s: %v", t.CA, err)
	}
	return tc, nil
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
	var wrongName x509.HostnameError
	if errors.As(err, &wrongName) {
		return out.Errf(out.ExitConnect, "REGISTRY_TLS",
			"use the host name the certificate is for in the conn URL; with --via the server on the path looks the name up (its /etc/hosts applies)",
			"the registry's TLS certificate is for another name: %v", err)
	}
	if certErr(err) {
		return out.Errf(out.ExitConnect, "REGISTRY_TLS",
			"if the registry uses a private CA (mkcert, an internal CA), store that CA with `komando secret set NAME < ca.crt` and add ?ca=secret:NAME to the conn URL (preferred: the check stays on); without the CA, store the registry's own certificate the same way, which pins it; ?tls=skip-verify turns the check off",
			"the registry's TLS certificate is not trusted: %v", err)
	}
	return out.Errf(out.ExitConnect, "REGISTRY_UNREACHABLE", "check the conn with `komando test NAME`", "%v", err)
}

// certErr says whether err is a failed certificate check.
func certErr(err error) bool {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	return errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &verify)
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
					return nil, imageErr(ctx, r, args[1], "", err)
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
				m, err := r.Inspect(ctx, repo, ref)
				if err != nil {
					return nil, imageErr(ctx, r, repo, ref, err)
				}
				return inspectData{m}, nil
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
						return nil, imageErr(ctx, r, repo, ref, err)
					}
					if m.Digest == "" {
						return nil, out.Errf(out.ExitRemote, "REGISTRY_ERROR", "run it again; if it keeps failing, the registry may not support this image format", "the registry did not say the image's digest")
					}
					// deleting by digest removes every tag on it: name them all
					tags, checked, more := tagsOn(ctx, r, repo, m.Digest)
					res := map[string]any{"conn": c.Name, "tags": tags}
					if more {
						res["tags_note"] = fmt.Sprintf("only the first %d tags were checked; others may point at this image too", checked)
					}
					if g.dryRun {
						res["would_delete"], res["dry_run"] = repo+"@"+m.Digest, true
						res["would_remove_tags"] = tags // every tag on the digest goes with it
						return res, nil
					}
					if err := r.Delete(ctx, repo, m.Digest); err != nil {
						return nil, err
					}
					res["deleted"] = repo + "@" + m.Digest
					res["note"] = "the space comes back after the registry's garbage collection"
					return res, nil
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

// tagsOn lists the tags of repo that point at digest, checking at most 200
// tags (one HEAD request each). more is true when the repo has more tags.
func tagsOn(ctx context.Context, r *registry.Client, repo, digest string) (tags []string, checked int, more bool) {
	const max = 200
	all, err := r.Tags(ctx, repo, max+1)
	if err != nil {
		return nil, 0, false
	}
	if len(all) > max {
		all, more = all[:max], true
	}
	tags = []string{}
	for _, t := range all {
		if d, err := r.Digest(ctx, repo, t); err == nil && d == digest {
			tags = append(tags, t)
		}
	}
	return tags, len(all), more
}

// imageErr says which image or repository is missing, and what is there
// instead: "mirror/busybox:latest not found; tags: stable".
func imageErr(ctx context.Context, r *registry.Client, repo, ref string, err error) error {
	var e *registry.Error
	if !errors.As(err, &e) || e.Status != 404 {
		return err
	}
	hint := "list the repositories with `komando registry ls CONN`"
	tags, terr := r.Tags(ctx, repo, 50)
	if terr != nil || ref == "" {
		return out.Errf(out.ExitNotFound, "REGISTRY_NOT_FOUND", hint, "repository %s not found", repo)
	}
	name := repo + refSep(ref) + ref
	if len(tags) == 0 {
		return out.Errf(out.ExitNotFound, "REGISTRY_NOT_FOUND", hint, "%s not found; the repository has no tags", name)
	}
	more := ""
	if len(tags) == 50 {
		more = ", ..."
	}
	return out.Errf(out.ExitNotFound, "REGISTRY_NOT_FOUND", "list the tags with `komando registry ls CONN "+repo+"`",
		"%s not found; tags: %s%s", name, strings.Join(tags, ", "), more)
}

// inspectData is `registry inspect`; a person reads the size in MB.
type inspectData struct{ *registry.Manifest }

func (d inspectData) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s%s\n", d.Repo, refSep(d.Ref), d.Ref)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "  %s: %s\n", k, v)
		}
	}
	row("digest", d.Digest)
	row("media type", d.MediaType)
	if d.Size > 0 {
		row("size", fmt.Sprintf("%s in %s, compressed", humanBytes(d.Size), countOf(d.Layers, "layer")))
	}
	row("platforms", strings.Join(d.Platforms, ", "))
	row("created", d.Created)
	if len(d.Labels) > 0 {
		keys := make([]string, 0, len(d.Labels))
		for k := range d.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("  labels:\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "    %s=%s\n", k, d.Labels[k])
		}
	}
	return b.String()
}

func registryPruneCmd() *cobra.Command {
	var keep int
	var olderThan, match string
	c := &cobra.Command{
		Use:   "prune CONN REPO",
		Short: "Delete old images: keep the newest N, or drop older than an age",
		Long: `Reads every tag's image and build date, then deletes the images the rule
lets go: --keep N keeps the newest N matching tags, --older-than deletes
only images built before that age; with both, a tag must pass both to go.
"latest", tags that do not match --match, and tags with no build date (a
multi-platform index) always stay. An image a kept tag points at is never
deleted. Needs --allow-dangerous; --dry-run shows the plan.`,
		Example: `  komando registry prune harbor shop/api --keep 10 --dry-run
  komando registry prune harbor shop/api --keep 5 --older-than 30d --match '^v' --allow-dangerous`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			rule := registry.PruneRule{Keep: keep}
			if keep < 0 {
				return out.Usage("--keep must be 0 or more")
			}
			if !cmd.Flags().Changed("keep") && olderThan == "" {
				return out.Usage("say what to keep: --keep N, --older-than AGE, or both")
			}
			if olderThan != "" {
				d, err := parseAge(olderThan, "--older-than")
				if err != nil {
					return err
				}
				rule.OlderThan = time.Now().Add(-d)
			}
			if match != "" {
				re, err := regexp.Compile(match)
				if err != nil {
					return out.Usage("--match: %v", err)
				}
				rule.Match = re
			}
			repo := args[1]
			return withRegistry(cmd.Context(), "registry.prune", args[0], driver.RiskDestructive, map[string]any{"repo": repo},
				func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error) {
					const max = 1000
					tags, err := r.Tags(ctx, repo, max+1)
					if err != nil {
						return nil, imageErr(ctx, r, repo, "", err)
					}
					if len(tags) > max {
						return nil, out.Errf(out.ExitUsage, "TOO_MANY_TAGS", "prune a narrower set with --match, or in several runs",
							"%s has more than %d tags", repo, max)
					}
					infos := make([]registry.TagInfo, 0, len(tags))
					for _, t := range tags {
						m, err := r.Inspect(ctx, repo, t)
						if err != nil {
							return nil, err
						}
						ti := registry.TagInfo{Tag: t, Digest: m.Digest}
						if ts, err := time.Parse(time.RFC3339Nano, m.Created); err == nil {
							ti.Created = ts
						}
						infos = append(infos, ti)
					}
					plan := rule.Plan(infos)
					res := map[string]any{"conn": c.Name, "repo": repo, "tags": len(tags), "delete": plan.Delete, "keep": plan.Keep}
					if plan.Delete == nil {
						res["delete"] = []registry.PruneImage{}
					}
					if g.dryRun {
						res["dry_run"] = true
						return res, nil
					}
					deleted := []string{}
					for _, img := range plan.Delete {
						if err := r.Delete(ctx, repo, img.Digest); err != nil {
							res["deleted"] = deleted
							return res, err
						}
						deleted = append(deleted, img.Digest)
					}
					res["deleted"] = deleted
					if len(deleted) > 0 {
						res["note"] = "the space comes back after the registry's garbage collection"
					}
					return res, nil
				})
		},
	}
	c.Flags().IntVar(&keep, "keep", 0, "keep the newest N matching tags")
	c.Flags().StringVar(&olderThan, "older-than", "", "delete only images built before this age (30d, 12h)")
	c.Flags().StringVar(&match, "match", "", "only tags matching this regular expression may go")
	return c
}
