package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Conns are non-SSH resources (databases for now). They share the name space
// and selector syntax of hosts, and reach private networks through a host
// (--via) without opening a local port.

// checkNewName is the name check for add: the name may be replaced only by
// the same type with exactly the same name (with --overwrite).
func checkNewName(s *store.State, kind, name string, overwrite bool) error {
	k, existing, ok := s.FindName(name)
	switch {
	case !ok:
		return nil
	case k != kind || existing != name:
		return nameTaken(k, existing)
	case !overwrite:
		return out.Errf(out.ExitConflict, strings.ToUpper(kind)+"_EXISTS", fmt.Sprintf("use `komando %s edit` or pass --overwrite to replace it", kind),
			"%s %q already exists", kind, name)
	}
	// replacing drops the protected mark, so it counts as changing it
	if h, ok := s.Hosts[name]; ok && h.Protected {
		return guardProtection("host", "replacing", []string{name})
	}
	if c, ok := s.Conns[name]; ok && c.Protected {
		return guardProtection("conn", "replacing", []string{name})
	}
	return nil
}

func nameTaken(kind, name string) error {
	return out.Errf(out.ExitConflict, "NAME_TAKEN", fmt.Sprintf("pick another name; servers, conns and VPNs share one name space (see `komando %s show %s`)", kind, name),
		"name %q is already used by a %s", name, kind)
}

type connFlags struct {
	via, passwordRef, notes                     string
	groups, tags, labels, options               []string
	protected                                   bool
	addGroups, rmGroups, addTags, rmTags, unset []string
}

func (f *connFlags) bind(c *cobra.Command, edit bool) {
	fl := c.Flags()
	fl.StringVar(&f.via, "via", "", "reach it through these servers (bastions) or a VPN first, comma-separated path; no local port is opened")
	fl.StringVar(&f.passwordRef, "password-ref", "", "password reference: secret:NAME | env:VAR | file:PATH | op://... | bw://... | kdbx:... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME")
	fl.StringVar(&f.notes, "notes", "", "free-form notes (shown to agents in conn show)")
	fl.BoolVar(&f.protected, "protected", false, "require --yes for any change (production safety)")
	if edit {
		fl.StringSliceVar(&f.addGroups, "add-group", nil, "add to group(s)")
		fl.StringSliceVar(&f.rmGroups, "rm-group", nil, "remove from group(s)")
		fl.StringSliceVar(&f.addTags, "add-tag", nil, "add tag(s)")
		shortAlias(fl, "group", "g", "add-group")
		shortAlias(fl, "tag", "t", "add-tag")
		fl.StringSliceVar(&f.rmTags, "rm-tag", nil, "remove tag(s)")
		fl.StringSliceVar(&f.labels, "label", nil, "set label KEY=VALUE (empty value removes)")
		fl.StringSliceVar(&f.options, "option", nil, "set kind-specific option KEY=VALUE (empty value removes)")
		fl.StringSliceVar(&f.unset, "unset", nil, "clear fields: via,password-ref,notes,protected")
	} else {
		fl.StringSliceVarP(&f.groups, "group", "g", nil, "group(s)")
		fl.StringSliceVarP(&f.tags, "tag", "t", nil, "tag(s)")
		fl.StringSliceVar(&f.labels, "label", nil, "label KEY=VALUE (repeatable)")
		fl.StringSliceVar(&f.options, "option", nil, "kind-specific option KEY=VALUE (repeatable)")
	}
}

// checkConn validates c against the inventory and fills c.Kind from its URL.
func checkConn(s *store.State, c *store.Conn) (driver.Target, error) {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return t, err
	}
	c.Kind = t.Kind.Name
	if c.Via != "" {
		if t.Kind.File {
			return t, out.Usage("%s conns are local files; --via is not supported", t.Kind.Name)
		}
		if _, _, err := resolveVia(s, c.Via); err != nil {
			return t, err
		}
	}
	if r := c.PasswordRef; r != "" && !vault.ValidRef(r) {
		return t, out.Errf(out.ExitUsage, "USAGE", "store the password with `komando secret set NAME` and pass --password-ref secret:NAME ("+vault.RefHelp()+")",
			"invalid --password-ref: it takes a reference, not the password itself")
	}
	return t, checkLabels(c.Groups, c.Tags, c.Labels)
}

func connCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "conn",
		Aliases: []string{"conns"},
		Short:   "Manage databases, caches, buckets, clusters and registries",
		Long: `A conn is a database, cache, storage bucket, cluster or registry komando
talks to directly. The kind comes from the URL scheme (` + "`komando conn kinds`" + ` lists them). Passwords never go in the URL: store them with
` + "`komando secret set`" + ` and pass --password-ref. Use --via HOST when the
resource is only reachable from a server.

Conns share names and selectors (@group, tag:x, glob, all) with hosts.`,
	}
	c.AddCommand(connAddCmd(), connEditCmd(), connMvCmd(), alias(listCmdFor("conn"), "list kind:conn"), connShowCmd(), connRmCmd(), alias(testCmdFor("conn"), "test"), connKindsCmd())
	return c
}

func connAddCmd() *cobra.Command {
	var f connFlags
	var force bool
	c := &cobra.Command{
		Use:   "add NAME URL",
		Short: "Add a conn (kind is taken from the URL scheme)",
		Example: `  komando conn add prod-db postgres://app@10.0.0.5:5432/app --via web1 --password-ref secret:prod-db-pass --protected
  komando conn add shop mysql://shop@db.internal/shop --group shop
  komando conn add local sqlite:///var/lib/app.db
  komando conn add cache redis://default@10.0.0.7:6379/0 --via web1 --password-ref secret:redis-pass
  komando conn add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --password-ref secret:s3-secret`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := validName("conn", name); err != nil {
				return err
			}
			cn := &store.Conn{Name: name, URL: normConnURL(strings.TrimSpace(args[1])), PasswordRef: f.passwordRef, Via: f.via,
				Groups: dedupe(f.groups), Tags: dedupe(f.tags), Protected: f.protected, Notes: f.notes}
			var err error
			if cn.Labels, err = parseKV(f.labels); err != nil {
				return err
			}
			if cn.Options, err = parseKV(f.options); err != nil {
				return err
			}
			if len(cn.Labels) == 0 {
				cn.Labels = nil
			}
			if len(cn.Options) == 0 {
				cn.Options = nil
			}
			now := time.Now().UTC()
			cn.CreatedAt, cn.UpdatedAt = now, now
			res := connResult{Conn: cn}
			replaced := false
			err = store.Update(func(s *store.State) error {
				if err := checkNewName(s, "conn", name, force); err != nil {
					return err
				}
				_, replaced = s.Conns[name]
				if _, err := checkConn(s, cn); err != nil {
					return err
				}
				if twin := protectedTwinConn(s, cn); twin != "" && !cn.Protected {
					cn.Protected = true
					res.Warnings = append(res.Warnings, sameTwinWarning(cn.Kind+" resource", name, twin))
				}
				s.Conns[name] = cn
				return nil
			})
			if err != nil {
				return err
			}
			res.Action = addVerb(replaced)
			audit(nil, "conn.add", nil, "", true, map[string]any{"conns": []string{name}, "action": res.Action})
			out.P.Print("conn.add", res, nil)
			return nil
		},
	}
	f.bind(c, false)
	c.Flags().BoolVar(&force, "overwrite", false, "replace an existing conn with the same name")
	aliasFlag(c.Flags(), "force", "overwrite")
	return c
}

func connEditCmd() *cobra.Command {
	var f connFlags
	var url, rename string
	c := &cobra.Command{
		Use:   "edit NAME",
		Short: "Edit a conn (only flags you pass are changed)",
		Example: `  komando conn edit prod-db --via bastion --add-tag critical --option statement_timeout=10s
  komando conn edit shop -g shop -t live          # -g/-t add a group/tag`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fl := cmd.Flags()
			if len(changedFlags(cmd)) == 0 {
				return out.Errf(out.ExitUsage, "USAGE", "pass what to change, e.g. komando conn edit "+args[0]+" --via bastion (see --help)", "nothing to change")
			}
			if err := editConflicts(fl, f.unset, map[string]string{"via": "via", "password-ref": "password-ref", "notes": "notes", "protected": "protected"},
				[][2][]string{{f.addGroups, f.rmGroups}, {f.addTags, f.rmTags}}); err != nil {
				return err
			}
			var res connResult
			err := store.Update(func(s *store.State) error {
				cn, err := findConn(s, args[0])
				if err != nil {
					return err
				}
				before, _ := json.Marshal(cn)
				wasProtected := cn.Protected
				old := *cn
				set := func(name string, dst *string, v string) {
					if fl.Changed(name) {
						*dst = v
					}
				}
				set("url", &cn.URL, normConnURL(strings.TrimSpace(url)))
				set("via", &cn.Via, f.via)
				set("password-ref", &cn.PasswordRef, f.passwordRef)
				set("notes", &cn.Notes, f.notes)
				if fl.Changed("protected") {
					cn.Protected = f.protected
				}
				cn.Groups = dedupe(append(removeFold(cn.Groups, f.rmGroups), f.addGroups...))
				cn.Tags = dedupe(append(removeFold(cn.Tags, f.rmTags), f.addTags...))
				if err := applyKV(&cn.Labels, f.labels); err != nil {
					return err
				}
				if err := applyKV(&cn.Options, f.options); err != nil {
					return err
				}
				for _, u := range f.unset {
					switch u {
					case "via":
						cn.Via = ""
					case "password-ref":
						cn.PasswordRef = ""
					case "notes":
						cn.Notes = ""
					case "protected":
						cn.Protected = false
					default:
						return out.Errf(out.ExitUsage, "USAGE", "--unset takes: via, password-ref, notes, protected", "cannot unset %q", u)
					}
				}
				if wasProtected && !cn.Protected {
					if err := guardProtection("conn", "turning off protection of", []string{cn.Name}); err != nil {
						return err
					}
				}
				if wasProtected && (old.URL != cn.URL || old.Via != cn.Via || old.PasswordRef != cn.PasswordRef) {
					if err := guardProtection("conn", "changing where or how komando logs in to", []string{cn.Name}); err != nil {
						return err
					}
				}
				if _, err := checkConn(s, cn); err != nil {
					return err
				}
				if rename != "" && rename != cn.Name {
					if _, err := renameConn(s, cn.Name, rename); err != nil {
						return err
					}
				}
				if !cn.Protected {
					if twin := protectedTwinConn(s, cn); twin != "" {
						cn.Protected = true
						res.Warnings = append(res.Warnings, sameTwinWarning(cn.Kind+" resource", cn.Name, twin))
					}
				}
				after, _ := json.Marshal(cn)
				ch := string(before) != string(after)
				if ch {
					cn.UpdatedAt = time.Now().UTC()
				}
				res.Conn, res.Changed = cn, &ch
				return nil
			})
			if err != nil {
				return err
			}
			if *res.Changed {
				audit(nil, "conn.edit", nil, "", true, map[string]any{"conns": []string{res.Name}, "flags": changedFlags(cmd)})
			}
			out.P.Print("conn.edit", res, nil)
			return nil
		},
	}
	f.bind(c, true)
	c.Flags().StringVar(&url, "url", "", "new URL (the kind may change with the scheme)")
	c.Flags().StringVar(&rename, "rename", "", "rename the conn")
	_ = c.Flags().MarkDeprecated("rename", "use `komando conn mv OLD NEW`")
	return c
}

func connShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Show full conn configuration (secrets are references, never values)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			c, err := findConn(st, args[0])
			if err != nil {
				return err
			}
			out.P.Print("conn.show", c, nil)
			return nil
		},
	}
}

func connRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm NAME|TARGET...",
		Short: "Remove conns from the inventory (does not touch the resource)",
		Example: `  komando conn rm shop-2
  komando conn rm kind:redis --dry-run`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var names []string
			err := store.Update(func(s *store.State) error {
				var prot []string
				names = nil
				conns, err := rmConns(s, args)
				if err != nil {
					return err
				}
				for _, c := range conns {
					names = append(names, c.Name)
					if c.Protected {
						prot = append(prot, c.Name)
					}
				}
				if err := guardProtection("conn", "removing", prot); err != nil {
					return err
				}
				for _, n := range names {
					delete(s.Conns, n)
				}
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "conn.rm", nil, "", true, map[string]any{"conns": names})
			out.P.Print("conn.rm", rmResult{Removed: names}, nil)
			return nil
		},
	}
}

func connKindsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "kinds",
		Short: "List the resource kinds komando knows and their URL schemes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out.P.Print("conn.kinds", kindList{Kinds: driver.Kinds()}, nil)
			return nil
		},
	}
}

type kindList struct {
	Kinds []driver.Kind `json:"kinds"`
}

func (l kindList) Text() string {
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tCOMMANDS\tURL EXAMPLE")
	for _, k := range l.Kinds {
		fmt.Fprintf(tw, "%s\tkomando %s\t%s\n", k.Name, k.Family, k.Example)
	}
	tw.Flush()
	return sb.String()
}

// --- access ----------------------------------------------------------------

// access is what every conn command needs: the parsed URL, the password and
// a dialer that goes through the --via host (nil Dial = connect directly).
type access struct {
	Target   driver.Target
	Password string
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	ssh      *sshx.Client
	vpn      io.Closer
}

func (a *access) Close() {
	if a.ssh != nil {
		a.ssh.Close()
	}
	if a.vpn != nil {
		a.vpn.Close()
	}
}

func openAccess(ctx context.Context, st *store.State, c *store.Conn) (*access, error) {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return nil, err
	}
	password, err := resolvePassword(c)
	if err != nil {
		return nil, err
	}
	a := &access{Target: t, Password: password}
	// ?resolve=IP: connections to the URL's address go to that IP, from the
	// end of the --via path set up below
	defer func() { a.Dial = pinDial(a.Dial, t.Address, t.Resolve) }()
	if c.Via == "" {
		return a, nil
	}
	h, vpn, err := resolveVia(st, c.Via)
	if err != nil {
		return nil, err
	}
	if vpn != nil {
		d, closer, err := netx.Open(ctx, vpn, sshOpts(st).ConnectTimeout)
		if err != nil {
			return nil, err
		}
		a.Dial, a.vpn = d, closer
		return a, nil
	}
	cctx, cancel := context.WithTimeout(ctx, sshOpts(st).ConnectTimeout)
	defer cancel()
	if a.ssh, err = sshx.Dial(cctx, st, h, sshOpts(st)); err != nil {
		return nil, err
	}
	a.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := a.ssh.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return sshx.WithDeadlines(c), nil
	}
	return a, nil
}

// resolveVia turns a --via chain ("office,bastion,db1") into what to dial:
// the last host, reached through the steps before it (sshx opens a VPN
// first step itself), or, when the path is only a VPN, that VPN. A chain
// given here replaces the last host's own --via; a single host keeps its own.
func resolveVia(st *store.State, via string) (*store.Host, *store.Vpn, error) {
	steps := viaChain(via)
	if len(steps) == 0 {
		return nil, nil, out.Usage("empty --via")
	}
	for i, s := range steps {
		if _, ok := st.Vpns[s]; ok {
			if i > 0 {
				return nil, nil, out.Errf(out.ExitUsage, "VIA_ORDER", "put the VPN first: --via "+s+","+steps[0],
					"a VPN can only be the first step of a --via path")
			}
			continue
		}
		if _, ok := st.Hosts[s]; !ok {
			return nil, nil, out.Errf(out.ExitNotFound, "VIA_NOT_FOUND", "--via takes server and VPN names; see `komando list`",
				"no server or VPN named %q", s)
		}
	}
	last := steps[len(steps)-1]
	if v, ok := st.Vpns[last]; ok {
		return nil, v, nil
	}
	h := st.Hosts[last]
	if len(steps) > 1 {
		cp := *h
		cp.Via = strings.Join(steps[:len(steps)-1], ",")
		h = &cp
	}
	return h, nil, nil
}

func resolvePassword(c *store.Conn) (string, error) {
	p, err := vault.Resolve(c.PasswordRef)
	if err == nil {
		return p, nil
	}
	hint := "store it with `komando secret set NAME` or fix the conn's --password-ref"
	if errors.Is(err, vault.ErrNotFound) {
		return "", out.Errf(out.ExitNotFound, "SECRET_NOT_FOUND", hint, "password reference %s: %v", c.PasswordRef, err)
	}
	return "", out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", hint, "password reference %s: %v", c.PasswordRef, err)
}

// --- connectivity ----------------------------------------------------------

type connTestResult struct {
	Conn      string     `json:"conn"`
	OK        bool       `json:"ok"`
	Kind      string     `json:"kind,omitempty"`
	Where     string     `json:"where,omitempty"`
	Via       string     `json:"via,omitempty"`
	Check     string     `json:"check,omitempty"`   // login (db, cache, registry) | tcp | file
	Version   string     `json:"version,omitempty"` // server version, when the login check reads it
	LatencyMS int64      `json:"latency_ms,omitempty"`
	Error     *out.Error `json:"error,omitempty"`
}

func testConn(ctx context.Context, st *store.State, c *store.Conn) connTestResult {
	r := connTestResult{Conn: c.Name, Kind: c.Kind, Via: c.Via}
	fail := func(err error) connTestResult {
		r.OK, r.Error = false, toErr(err)
		return r
	}
	if t, err := driver.Parse(c.URL); err == nil {
		r.Where = t.Where()
	}
	t0 := time.Now()
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	if a.Target.Kind.File {
		r.Check = "file"
		if _, err := os.Stat(expandHome(a.Target.Path)); err != nil {
			return fail(localFileErr("FILE_NOT_FOUND", err, "check the path in the conn URL (`komando conn edit "+c.Name+" --url ...`)"))
		}
	} else {
		r.Check = "tcp"
		dctx, cancel := context.WithTimeout(ctx, sshOpts(st).ConnectTimeout)
		defer cancel()
		dial := a.Dial
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		nc, err := dial(dctx, "tcp", a.Target.Address)
		if err != nil {
			return fail(unreachable(c, a.Target, err))
		}
		nc.Close()
	}
	// reaching the port is not enough: log in like the real commands do
	if err := loginCheck(ctx, st, c, a, &r); err != nil {
		return fail(err)
	}
	r.OK, r.LatencyMS = true, time.Since(t0).Milliseconds()
	return r
}

// loginCheck logs in to db, cache and registry conns with their stored
// password and reads the server version where that is cheap. Other kinds
// keep the reachability check (`cluster status` logs in to clusters).
func loginCheck(ctx context.Context, st *store.State, c *store.Conn, a *access, r *connTestResult) error {
	cctx, cancel := context.WithTimeout(ctx, sshOpts(st).ConnectTimeout)
	defer cancel()
	switch a.Target.Kind.Family {
	case "db":
		db, err := dbx.Open(cctx, c.URL, a.Target, a.Password, a.Dial, true, "komando/"+actor())
		if err != nil {
			return viaTimeout(c, err)
		}
		defer db.Close()
		q := map[string]string{"postgres": "select version()", "mysql": "select version()", "sqlite": "select sqlite_version()"}[a.Target.Kind.Name]
		if q != "" {
			_ = db.QueryRowContext(cctx, q).Scan(&r.Version)
		}
	case "cache":
		rc, err := cachex.OpenStore(cctx, a.Target, a.Password, a.Dial, sshOpts(st).ConnectTimeout)
		if err != nil {
			return err
		}
		defer rc.Close()
		section := "server"
		if a.Target.Kind.Name == "memcached" {
			section = ""
		}
		if info, err := rc.Info(cctx, section); err == nil {
			r.Version = cachex.SummarizeFor(a.Target.Kind.Name, info).Version
		}
	case "registry":
		rg, closeFn, err := openRegistry(cctx, st, c)
		if err != nil {
			return err
		}
		defer closeFn()
		if err := rg.Ping(cctx); err != nil {
			return registryErr(err)
		}
	default:
		return nil
	}
	r.Check = "login"
	return nil
}

// viaTimeout names the conn's --via path in a "connecting to ADDRESS timed
// out" error, so the message says where komando waited: "connecting to
// 10.0.0.5:5432 via office-vpn timed out". Other errors pass unchanged.
func viaTimeout(c *store.Conn, err error) error {
	var e *out.Error
	if c.Via == "" || !errors.As(err, &e) || e.Code != "TIMEOUT" {
		return err
	}
	if addr, ok := strings.CutSuffix(e.Message, " timed out"); ok && strings.HasPrefix(addr, "connecting to ") {
		e.Message = addr + " via " + strings.Join(viaChain(c.Via), " → ") + " timed out"
	}
	return err
}

func unreachable(c *store.Conn, t driver.Target, err error) *out.Error {
	if errors.Is(err, context.DeadlineExceeded) {
		e := out.Errf(out.ExitTimeout, "TIMEOUT", "the port may be firewalled; check the address or raise --connect-timeout", "connecting to %s timed out", t.Address)
		_ = viaTimeout(c, e)
		return e
	}
	hint := "check the address and port; if the service is only reachable from a server, set `komando conn edit " + c.Name + " --via HOST`"
	if steps := viaChain(c.Via); len(steps) > 0 {
		last := steps[len(steps)-1]
		hint = "the address is resolved on " + last + "; check it from there with `komando net check " + last + " " + t.Address + "`"
		if st, err := loadState(); err == nil {
			if _, isVpn := st.Vpns[last]; isVpn {
				hint = "the address is reached through VPN " + last + "; check the VPN with `komando test " + last + "` and the address in the conn URL"
			}
		}
	}
	return out.Errf(out.ExitConnect, "CONN_UNREACHABLE", hint, "cannot reach %s: %v", t.Address, err)
}
