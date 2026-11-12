package cli

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
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
		Long: `Look at, copy and clean up container images. Add a registry with
` + "`komando registry add ghcr registry://myuser@ghcr.io --ask-password`" + `,
or bring in the ones you use with ` + "`komando import docker`" + `.
ls and inspect only read, copy writes to the destination, rm and prune
delete images and need --allow-dangerous (try --dry-run first).

TLS options in the registry URL: ?ca=secret:NAME trusts a private CA (or
pins the registry's own certificate; the check stays on), ?tls=skip-verify
does not check the certificate, ?tls=false is plain HTTP. ?resolve=IP
connects to that IP instead of what DNS says (like curl --resolve). With
--via the last server looks the name up.`,
		Example: `  komando registry add ghcr registry://myuser@ghcr.io --ask-password
  komando registry ls ghcr myorg/api
  komando registry inspect ghcr myorg/api:1.4.2
  komando registry copy ghcr:myorg/api:1.4.2 harbor:prod/api:1.4.2
  komando registry prune harbor prod/api --keep 10 --dry-run`,
	}
	c.AddCommand(connAddCmdFor("registry"), registryLsCmd(), registryInspectCmd(), registryCopyCmd(), registryRmCmd(), registryPruneCmd())
	return c
}

// withRegistry opens a registry conn and runs fn after the safety check.
// what, when not nil, reads what a delete takes before the check, so the
// question a person answers (and the approval a person gives an agent)
// names the image and its tags, not only the command.
func withRegistry(ctx context.Context, name, expr string, risk driver.Risk, extra map[string]any,
	what func(ctx context.Context, r *registry.Client) string,
	fn func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, expr, "registry")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout(st))
	defer cancel()
	var rc *registry.Client
	var closeRC func()
	defer func() {
		if closeRC != nil {
			closeRC()
		}
	}()
	open := func() (err error) {
		if rc == nil {
			rc, closeRC, err = openRegistry(ctx, st, c)
		}
		return err
	}
	reasons := []string{name}
	// a registry that does not answer is reported after the check, so a
	// blocked delete stays blocked whatever the network does
	if what != nil && !g.dryRun && open() == nil {
		if s := what(ctx, rc); s != "" {
			reasons = append(reasons, s)
		}
	}
	if err := guardConns(st, []*store.Conn{c}, driver.Verdict{Risk: risk, RuleIDs: []string{"registry"}, Reasons: reasons}); err != nil {
		if g.dryRun {
			out.P.Print(name, map[string]any{"conn": c.Name, "dry_run": true, "would_be_blocked": toErr(err)}, nil)
			return nil
		}
		return err
	}
	if err := open(); err != nil {
		return err
	}
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
	tc, err := registryTLS(a.Target)
	if err != nil {
		a.Close()
		return nil, nil, err
	}
	rc := registry.New(host, tc, a.Target.User, a.Password, dial)
	if err := cloudRegistryLogin(ctx, c, host, rc); err != nil {
		a.Close()
		return nil, nil, err
	}
	return rc, a.Close, nil
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
		code := "SECRET_UNRESOLVED"
		if errors.Is(err, vault.ErrNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		return tc, out.Errf(out.ExitNotFound, code, "store the CA certificate with `komando secret set NAME < ca.crt`",
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
		case 429:
			code, hint = "REGISTRY_RATE_LIMIT", "the registry limits how many requests it takes (Docker Hub: pulls per 6 hours, fewer without a login); wait and run it again"
			if e.RetryAfter != "" {
				hint += " after " + retryAfter(e.RetryAfter)
			}
			hint += ", or log in: put the user in the conn URL and give --password-ref"
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
	if errors.Is(err, context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout, or check the conn with `komando test NAME`",
			"the registry did not answer within the time limit (--timeout)")
	}
	return out.Errf(out.ExitConnect, "REGISTRY_UNREACHABLE", "check the conn with `komando test NAME`", "%s", dialMessage(err))
}

// retryAfter turns a Retry-After header (seconds, or an HTTP date) into
// words: "120 s", or the local time.
func retryAfter(v string) string {
	if n, err := strconv.Atoi(v); err == nil {
		return (time.Duration(n) * time.Second).String()
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.Local().Format("15:04:05")
	}
	return v
}

// catalogErr explains a refused catalog: Docker Hub and GHCR have none, and
// elsewhere a token may read repositories without being allowed to list them.
func catalogErr(r *registry.Client, err error) error {
	var e *registry.Error
	if !errors.As(err, &e) {
		return err
	}
	noCatalog := r.DockerHub() || r.Base.Host == "ghcr.io"
	switch {
	case noCatalog && (e.Status == 401 || e.Status == 403 || e.Status == 404 || e.Status == 405):
		return out.Errf(out.ExitRemote, "REGISTRY_UNSUPPORTED", "name the repository: `komando registry ls CONN REPO` (on Docker Hub, nginx means library/nginx)",
			"%s has no list of every repository", r.Base.Host)
	case e.Status == 401 || e.Status == 403:
		return out.Errf(out.ExitConnect, "REGISTRY_AUTH", "the login may read images but not list every repository: name one with `komando registry ls CONN REPO`; else check the user in the conn URL and its --password-ref",
			"the registry refused to list its repositories: %s", e.Error())
	}
	return err
}

// imageArg splits and checks REPO[:TAG|@DIGEST] before it goes into a URL.
func imageArg(s string) (repo, ref string, err error) {
	repo, ref = splitImage(s)
	if err := registry.CheckRepo(repo); err != nil {
		return "", "", out.Usage("%s: %v", s, err)
	}
	if err := registry.CheckRef(ref); err != nil {
		return "", "", out.Usage("%s: %v", s, err)
	}
	return repo, ref, nil
}

func repoArg(s string) error {
	if err := registry.CheckRepo(s); err != nil {
		if strings.ContainsAny(s, ":@") {
			return out.Usage("%v; give only the repository, without a tag", err)
		}
		return out.Usage("%v", err)
	}
	return nil
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
			if limit < 1 {
				return out.Usage("--limit must be 1 or more")
			}
			if len(args) == 2 {
				if err := repoArg(args[1]); err != nil {
					return err
				}
			}
			return withRegistry(cmd.Context(), "registry.ls", args[0], driver.RiskRead, nil, nil, func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error) {
				// one more than asked tells whether the list was cut
				if len(args) == 1 {
					repos, err := r.Catalog(ctx, limit+1)
					if err != nil {
						return nil, catalogErr(r, err)
					}
					repos, cut := cutList(repos, limit)
					return lsData(withTruncated(map[string]any{"conn": c.Name, "count": len(repos), "repositories": repos}, cut)), nil
				}
				repo := r.Repo(args[1])
				tags, err := r.Tags(ctx, repo, limit+1)
				if err != nil {
					return nil, imageErr(ctx, r, repo, "", err)
				}
				tags, cut := cutList(tags, limit)
				return lsData(withTruncated(map[string]any{"conn": c.Name, "repo": repo, "count": len(tags), "tags": tags}, cut)), nil
			})
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 1000, "the most entries to show")
	return c
}

// cutList keeps the first limit items (never nil, so JSON shows []) and
// reports whether there were more.
func cutList(items []string, limit int) ([]string, bool) {
	if items == nil {
		items = []string{}
	}
	if len(items) > limit {
		return items[:limit], true
	}
	return items, false
}

// withTruncated marks a cut list, as cluster ls does.
func withTruncated(res map[string]any, cut bool) map[string]any {
	if cut {
		res["truncated"] = true
	}
	return res
}

func registryInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "inspect CONN REPO[:TAG|@DIGEST]",
		Aliases: []string{"get", "show"},
		Short:   "Digest, size, platforms, created time and labels of an image",
		Example: `  komando registry inspect ghcr myorg/api:1.4.2
  komando registry inspect dockerhub nginx            # Docker Hub: library/nginx:latest
  komando registry inspect harbor shop/api@sha256:4c2e...`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			repo, ref, err := imageArg(args[1])
			if err != nil {
				return err
			}
			return withRegistry(cmd.Context(), "registry.inspect", args[0], driver.RiskRead, nil, nil, func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error) {
				repo := r.Repo(repo)
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
		Use:   "rm CONN REPO:TAG|REPO@DIGEST",
		Short: "Delete an image and every tag on it (needs --allow-dangerous)",
		Long: `Deletes the image a tag (or digest) points at. A registry deletes images,
not tags: every other tag on the same image goes too, latest included.
--dry-run names each tag that would go. The space comes back after the
registry's garbage collection.`,
		Example: `  komando registry rm harbor myorg/api:old --dry-run
  komando registry rm harbor myorg/api:old --allow-dangerous`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// a forgotten tag must not mean latest, the image that usually runs
			if _, ref := splitImage(args[1]); ref == "latest" && !strings.HasSuffix(args[1], ":latest") {
				return out.Usage("name the tag or digest to delete, e.g. %s:1.2 (komando does not pick latest for a delete)", args[1])
			}
			repo, ref, err := imageArg(args[1])
			if err != nil {
				return err
			}
			return withRegistry(cmd.Context(), "registry.rm", args[0], driver.RiskDestructive, map[string]any{"image": args[1]},
				func(ctx context.Context, r *registry.Client) string { return rmWhat(ctx, r, r.Repo(repo), ref) },
				func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error) {
					repo := r.Repo(repo)
					m, err := r.Inspect(ctx, repo, ref)
					if err != nil {
						return nil, imageErr(ctx, r, repo, ref, err)
					}
					if m.Digest == "" {
						return nil, out.Errf(out.ExitRemote, "REGISTRY_ERROR", "run it again; if it keeps failing, the registry may not support this image format", "the registry did not say the image's digest")
					}
					// deleting by digest removes every tag on it: name them all
					tags, checked, more := tagsOn(ctx, r, repo, m.Digest)
					res := rmData{"conn": c.Name, "tags": tags}
					switch {
					case tags == nil:
						res["tags"] = []string{}
						res["tags_note"] = "komando could not list the repository's tags; other tags may point at this image too"
					case more:
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
// helpers (docker-credential-*) when the config names one. A cloud
// registry whose docker login is a short-lived token (Amazon ECR, Google
// with gcloud, Azure with az acr login) is added without it: komando logs
// in with the cloud login each time, so the conn does not die in hours.
func importDocker(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			IdentityToken string `json:"identitytoken"`
		} `json:"auths"`
		CredsStore  string            `json:"credsStore"`
		CredHelpers map[string]string `json:"credHelpers"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, out.Usage("%s: %v", path, err)
	}
	// a credHelpers entry needs no auths entry (docker-credential-ecr-login)
	servers := make([]string, 0, len(cfg.Auths)+len(cfg.CredHelpers))
	for server := range cfg.Auths {
		servers = append(servers, server)
	}
	for server := range cfg.CredHelpers {
		if _, ok := cfg.Auths[server]; !ok {
			servers = append(servers, server)
		}
	}
	sort.Strings(servers) // the same names on every run
	p := newPlan()
	for _, server := range servers {
		a := cfg.Auths[server]
		host := dockerHost(server)
		helper := cmp.Or(cfg.CredHelpers[server], cfg.CredsStore)
		name := p.name(strings.Split(host, ".")[0])
		if host == "docker.io" {
			name = p.name("dockerhub")
		}
		user, pass := "", ""
		if a.Auth != "" {
			raw, err := base64.StdEncoding.DecodeString(a.Auth)
			if err == nil {
				user, pass, _ = strings.Cut(string(raw), ":")
			}
		}
		if cloud := cloudLoginOf(host, user, a.IdentityToken != "", cfg.CredHelpers[server]); cloud != "" {
			u := url.URL{Scheme: "registry", Host: host}
			p.addConn(name, u.String(), server)
			if n := len(p.Conns); n > 0 && p.Conns[n-1].Name == name {
				p.ConnNotes[p.Conns[n-1]] = append(p.ConnNotes[p.Conns[n-1]],
					name+": logs in with your "+cloud+" login each time; docker's token there lasts only hours, so it is not kept")
			}
			continue
		}
		if a.Auth == "" && helper != "" {
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
		if user == "<token>" || a.IdentityToken != "" {
			p.Notes = append(p.Notes, server+": docker keeps an identity token for it, which komando cannot use; add it with a user and --password-ref")
			continue
		}
		u := url.URL{Scheme: "registry", User: url.UserPassword(user, pass), Host: host}
		p.addConn(name, u.String(), server)
	}
	return p, nil
}

// dockerHost is the registry address in a docker config key
// ("https://index.docker.io/v1/" is Docker Hub).
func dockerHost(server string) string {
	host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(server, "https://"), "http://"), "/")
	host = strings.TrimSuffix(host, "/v1")
	if host == "index.docker.io" || host == "registry-1.docker.io" {
		host = "docker.io"
	}
	return strings.ToLower(host)
}

// cloudLoginOf names the cloud login komando uses for host ("AWS",
// "Google", "Azure") when docker's own login there is a short-lived token,
// or "". A Google service account key (_json_key) and an Azure admin user
// or registry token last, so they are kept as they are.
func cloudLoginOf(host, user string, identityToken bool, helper string) string {
	switch {
	case ecrRegion(host) != "":
		return "AWS"
	case isGoogleRegistry(host) && (user == "oauth2accesstoken" || helper == "gcloud" || helper == "gcr" || (user == "" && helper == "")):
		return "Google"
	case acrResource(host) != "" && (identityToken || user == "<token>" || user == "00000000-0000-0000-0000-000000000000"):
		return "Azure"
	}
	return ""
}

// helperName is what may follow docker-credential-: a plain program name,
// never a path a config file could point somewhere else with.
var helperName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func credHelper(helper, server string) (string, string, error) {
	if !helperName.MatchString(helper) {
		return "", "", fmt.Errorf("the credential helper name %q is not a program name; komando did not run it", helper)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // a helper may wait for a click
	defer cancel()
	c := exec.CommandContext(ctx, "docker-credential-"+helper, "get")
	c.Stdin = strings.NewReader(server)
	b, err := c.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", "", fmt.Errorf("the credential helper docker-credential-%s did not answer within 30 s", helper)
		}
		return "", "", fmt.Errorf("the credential helper docker-credential-%s failed (%v)", helper, err)
	}
	var r struct{ Username, Secret string }
	if err := json.Unmarshal(b, &r); err != nil {
		return "", "", fmt.Errorf("the credential helper docker-credential-%s gave no login", helper)
	}
	return r.Username, r.Secret, nil
}

// rmWhat says what `registry rm` takes: the image and every tag on it.
// Tags come from the registry, so only names a tag may have are shown.
func rmWhat(ctx context.Context, r *registry.Client, repo, ref string) string {
	d, err := r.Digest(ctx, repo, ref)
	if err != nil || registry.CheckRef(d) != nil {
		return ""
	}
	tags, _, more := tagsOn(ctx, r, repo, d)
	shown := []string{}
	for _, t := range tags {
		if registry.CheckRef(t) == nil {
			shown = append(shown, t)
		}
	}
	s := "deletes " + repo + "@" + shortDigest(d)
	switch {
	case len(shown) > 0:
		s += " and every tag on it: " + strings.Join(shown, ", ")
	case ref == d:
		s += ", an image no tag points at"
	}
	if more {
		s += ", and maybe more"
	}
	return s
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
	for _, t := range all { // HEAD requests: Docker Hub does not count them as pulls
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
	row("created", localCreated(d.Created))
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
"latest", tags that do not match --match, and tags with no build date
always stay (a multi-platform index has the date of its first image, so
it can go). An image a kept tag points at is never deleted. Needs
--allow-dangerous; --dry-run shows the plan.`,
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
			if err := repoArg(args[1]); err != nil {
				return err
			}
			return withRegistry(cmd.Context(), "registry.prune", args[0], driver.RiskDestructive, map[string]any{"repo": args[1]},
				func(context.Context, *registry.Client) string {
					return "deletes old images of " + args[1] + " (--dry-run lists them)"
				},
				func(ctx context.Context, c *store.Conn, r *registry.Client) (any, error) {
					repo := r.Repo(args[1])
					const max = 1000
					tags, err := r.Tags(ctx, repo, max+1)
					if err != nil {
						return nil, imageErr(ctx, r, repo, "", err)
					}
					if len(tags) > max {
						return nil, out.Errf(out.ExitUsage, "TOO_MANY_TAGS", "prune a narrower set with --match, or in several runs",
							"%s has more than %d tags", repo, max)
					}
					// a HEAD per tag for its digest, then one read per image:
					// tags often share images, and Docker Hub counts every
					// manifest read as a pull
					infos := make([]registry.TagInfo, 0, len(tags))
					built := map[string]time.Time{}
					for _, t := range tags {
						d, err := r.Digest(ctx, repo, t)
						if err != nil {
							return nil, err
						}
						if d == "" { // the registry did not say: read the manifest
							m, err := r.Inspect(ctx, repo, t)
							if err != nil {
								return nil, err
							}
							d = m.Digest
						}
						if _, ok := built[d]; !ok && d != "" {
							m, err := r.Inspect(ctx, repo, d)
							if err != nil {
								return nil, err
							}
							ts, _ := time.Parse(time.RFC3339Nano, m.Created)
							built[d] = ts
						}
						infos = append(infos, registry.TagInfo{Tag: t, Digest: d, Created: built[d]})
					}
					plan := rule.Plan(infos)
					res := pruneData{"conn": c.Name, "repo": repo, "tags": len(tags), "delete": plan.Delete, "keep": plan.Keep}
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
