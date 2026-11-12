package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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

// Conns are non-SSH resources (databases, caches, queues, storage, clusters,
// registries). They share the name space and selector syntax of hosts, and
// reach private networks through a host (--via) without opening a local port.

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
		return out.Errf(out.ExitConflict, map[string]string{"host": "HOST_EXISTS", "conn": "CONN_EXISTS", "vpn": "VPN_EXISTS"}[kind], fmt.Sprintf("use `komando %s edit` or pass --overwrite to replace it", kind),
			"%s %q already exists", kind, name)
	}
	// replacing drops the protected mark, so it counts as changing it
	if h, ok := s.Hosts[name]; ok && h.Protected {
		return guardProtection("host", "replacing", []string{name})
	}
	if c, ok := s.Conns[name]; ok && c.Protected {
		return guardProtection("conn", "replacing", []string{name})
	}
	if v, ok := s.Vpns[name]; ok && v.Protected {
		return guardProtection("vpn", "replacing", []string{name})
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
	fl.StringVar(&f.passwordRef, "password-ref", "", "where the password is: secret:NAME (saved with komando secret set NAME), env:VAR, file:PATH or a password manager like op://...")
	fl.StringVar(&f.notes, "notes", "", "free-form notes (komando conn show shows them to people and agents)")
	fl.BoolVar(&f.protected, "protected", false, "production: komando asks you before every change, and an AI agent needs your yes in a window")
	if edit {
		fl.StringSliceVar(&f.addGroups, "add-group", nil, "put it in these groups (comma-separated)")
		fl.StringSliceVar(&f.rmGroups, "rm-group", nil, "take it out of these groups")
		fl.StringSliceVar(&f.addTags, "add-tag", nil, "add these tags (comma-separated)")
		shortAlias(fl, "group", "g", "add-group")
		shortAlias(fl, "tag", "t", "add-tag")
		fl.StringSliceVar(&f.rmTags, "rm-tag", nil, "remove these tags")
		kvVar(fl, &f.labels, "label", "", "set label KEY=VALUE (an empty value removes it)")
		kvVar(fl, &f.options, "option", "", "set an option of this kind, KEY=VALUE (an empty value removes it)")
		fl.StringSliceVar(&f.unset, "unset", nil, "clear these settings: via,password-ref,notes,protected")
	} else {
		fl.StringSliceVarP(&f.groups, "group", "g", nil, "put it in these groups (comma-separated)")
		fl.StringSliceVarP(&f.tags, "tag", "t", nil, "tags, e.g. prod (comma-separated)")
		kvVar(fl, &f.labels, "label", "", "label KEY=VALUE (repeatable)")
		kvVar(fl, &f.options, "option", "", "an option of this kind, KEY=VALUE (repeatable)")
	}
}

// checkConn validates c against the inventory and fills c.Kind from its URL.
func checkConn(s *store.State, c *store.Conn) error {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return kindExample(c.URL, err)
	}
	c.Kind = t.Kind.Name
	if t.Kind.File && !strings.HasPrefix(t.Path, "/") && !strings.HasPrefix(t.Path, "~/") && !filepath.IsAbs(t.Path) {
		// a relative path would name a different file in every folder komando runs from
		hint := "write the full path, e.g. " + t.Kind.Example + ", or ~/ for your home folder"
		if abs, err := filepath.Abs(t.Path); err == nil {
			hint = "write the full path; for the file in this folder: " + t.Kind.Name + "://" + filepath.ToSlash(abs)
		}
		return out.Errf(out.ExitUsage, "USAGE", hint, "%s URL needs the full path of the file, not %q", t.Kind.Name, t.Path)
	}
	if c.Via != "" {
		if t.Kind.File {
			return out.Usage("%s conns are files on this computer, so they take no --via", t.Kind.Name)
		}
		if _, _, err := resolveVia(s, c.Via); err != nil {
			return err
		}
	}
	if r := c.PasswordRef; r != "" && !vault.ValidRef(r) {
		return out.Errf(out.ExitUsage, "USAGE", "store the password with `komando secret set NAME` and pass --password-ref secret:NAME ("+vault.RefHelp()+")",
			"invalid --password-ref: it takes a reference, not the password itself")
	}
	return checkLabels(c.Groups, c.Tags, c.Labels)
}

func connCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "conn",
		Aliases: []string{"conns"},
		Short:   "Manage databases, caches, queues, storage, clusters, registries",
		Long: `A conn is a database, cache, message queue, file storage, cluster or registry
komando talks to directly. The kind comes from the URL scheme (` + "`komando conn kinds`" + `
lists them). Passwords never go in the URL: store them with
` + "`komando secret set`" + ` and pass --password-ref. Use --via HOST when the
resource is only reachable from a server.

Conns share names and selectors (@group, tag:x, glob, all) with servers.`,
	}
	c.AddCommand(connAddCmd(), connEditCmd(), connMvCmd(), alias(listCmdFor("conn"), "list kind:conn"), connShowCmd(), connRmCmd(), alias(testCmdFor("conn"), "test"), connKindsCmd())
	return c
}

func connAddCmd() *cobra.Command {
	var f connFlags
	var force, askPw bool
	c := &cobra.Command{
		Use:   "add NAME URL",
		Short: "Add a conn (the URL scheme sets its kind)",
		Example: `  komando conn add prod-db postgres://app@10.0.0.5:5432/app --via web1 --password-ref secret:prod-db-pass --protected
  komando conn add shop mysql://shop@db.internal/shop --group shop
  komando conn add local sqlite:///var/lib/app.db
  komando conn add cache redis://default@10.0.0.7:6379/0 --via web1 --password-ref secret:redis-pass
  komando conn add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --password-ref secret:s3-secret
  komando conn add app-db postgres://app@10.0.0.5/app --via web1 --ask-password   # type it now (hidden)`,
		Args: formArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return formOrUsage(cmd, "conn", "komando conn add app-db postgres://app@10.0.0.5/app --ask-password")
			}
			name := args[0]
			if err := checkEntryName("conn", name); err != nil {
				return err
			}
			undoPw := func() {}
			if askPw {
				ref, undo, err := askPassword(cmd, "conn", name)
				if err != nil {
					return err
				}
				f.passwordRef, undoPw = ref, undo
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
				old := s.Conns[name]
				replaced = old != nil
				if err := checkConn(s, cn); err != nil {
					return err
				}
				if err := secureConnURL(cn, &res); err != nil {
					return err
				}
				if err := guardConnSends(old, cn); err != nil {
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
				undoPw()
				return err
			}
			res.Action = addVerb(replaced)
			res.Warnings = append(res.Warnings, missingSecretWarnings(cn.PasswordRef)...)
			res.Next = "komando test " + name
			audit(nil, "conn.add", nil, "", true, map[string]any{"conns": []string{name}, "action": res.Action})
			out.P.Print("conn.add", res, nil)
			return nil
		},
	}
	f.bind(c, false)
	askPasswordFlag(c, &askPw)
	c.Flags().BoolVar(&force, "overwrite", false, "replace a conn that has the same name")
	return c
}

func connEditCmd() *cobra.Command {
	var f connFlags
	var url string
	var askPw bool
	c := &cobra.Command{
		Use:   "edit NAME",
		Short: "Change a conn (only the flags you pass change)",
		Example: `  komando conn edit prod-db --via bastion --add-tag critical --option statement_timeout=10s
  komando conn edit shop -g shop -t live          # -g/-t add a group/tag`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnEdit(cmd, args, &f, url, askPw)
		},
	}
	f.bind(c, true)
	askPasswordFlag(c, &askPw)
	c.Flags().StringVar(&url, "url", "", "new URL (the kind may change with the scheme)")
	return c
}

func runConnEdit(cmd *cobra.Command, args []string, f *connFlags, url string, askPw bool) error {
	fl := cmd.Flags()
	if len(changedFlags(cmd)) == 0 {
		return out.Errf(out.ExitUsage, "USAGE", "pass what to change, e.g. komando conn edit "+args[0]+" --via bastion (see --help)", "nothing to change")
	}
	if err := editConflicts(fl, f.unset, map[string]string{"via": "via", "password-ref": "password-ref", "notes": "notes", "protected": "protected"},
		[][2][]string{{f.addGroups, f.rmGroups}, {f.addTags, f.rmTags}}); err != nil {
		return err
	}
	undoPw := func() {}
	if askPw {
		ref, undo, err := askPassword(cmd, "conn", args[0])
		if err != nil {
			return err
		}
		_ = fl.Set("password-ref", ref)
		undoPw = undo
	}
	var res connResult
	err := store.Update(func(s *store.State) error {
		cn, err := findConn(s, args[0])
		if err != nil {
			return err
		}
		before, _ := json.Marshal(cn)
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
		if err := checkConn(s, cn); err != nil {
			return err
		}
		if err := guardConnEdit(&old, cn, &res); err != nil {
			return err
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
		undoPw()
		return err
	}
	if fl.Changed("password-ref") {
		res.Warnings = append(res.Warnings, missingSecretWarnings(res.PasswordRef)...)
	}
	if *res.Changed {
		audit(nil, "conn.edit", nil, "", true, map[string]any{"conns": []string{res.Name}, "flags": changedFlags(cmd)})
	}
	out.P.Print("conn.edit", res, nil)
	return nil
}

// guardConnEdit: an edit that turns a conn's protection off, or changes
// where or how komando logs in to a protected conn, needs --yes. For an AI
// agent, so do the secrets it sends to a new place and the settings that
// turn its network protection down (guardConnSends); one window asks about
// all of it. A new URL first gets the secure default (secureConnURL), noted
// on res.
func guardConnEdit(old, cn *store.Conn, res *connResult) error {
	if cn.URL != old.URL {
		if err := secureConnURL(cn, res); err != nil {
			return err
		}
	}
	var actions []string
	if old.Protected && !cn.Protected {
		actions = append(actions, "turning off protection of")
	}
	if old.Protected && (old.URL != cn.URL || old.Via != cn.Via || old.PasswordRef != cn.PasswordRef) {
		actions = append(actions, "changing where or how komando logs in to")
	}
	var why []string
	for _, a := range actions {
		why = append(why, a+" protected conn: "+cn.Name)
	}
	if err := guardConnSends(old, cn, why...); err != nil {
		return err
	}
	for _, a := range actions {
		if err := guardProtection("conn", a, []string{cn.Name}); err != nil {
			return err
		}
	}
	return nil
}

func connShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Show all settings of a conn (secrets as references, never values)",
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
		Short: "Remove conns from the inventory (the resources are not touched)",
		Example: `  komando conn rm shop-2
  komando conn rm kind:redis --dry-run`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var names, unused []string
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
				var refs []string
				for _, n := range names {
					refs = append(refs, s.Conns[n].PasswordRef)
					for _, r := range urlSecretRefs(s.Conns[n].URL) {
						refs = append(refs, "secret:"+r.Name)
					}
					delete(s.Conns, n)
				}
				unused = unusedSecrets(s, refs)
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "conn.rm", nil, "", true, map[string]any{"conns": names})
			out.P.Print("conn.rm", rmResult{Removed: names, SecretsUnused: unused}, nil)
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

// Opening a conn.

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

func resolvePassword(c *store.Conn) (string, error) {
	p, err := vault.Resolve(c.PasswordRef)
	if err == nil {
		return p, nil
	}
	hint := netx.SecretHint(c.PasswordRef) + ", or point the conn elsewhere: `komando conn edit " + c.Name + " --password-ref ...`"
	if errors.Is(err, vault.ErrNotFound) {
		return "", out.Errf(out.ExitNotFound, "SECRET_NOT_FOUND", hint, "password reference %s: %v", c.PasswordRef, err)
	}
	return "", out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", hint, "password reference %s: %v", c.PasswordRef, err)
}

// conn test.

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

// loginCheck logs in to db, cache, queue and registry conns with their stored
// password and reads the server version where that is cheap. Other kinds
// keep the reachability check (`cluster status` logs in to clusters).
func loginCheck(ctx context.Context, st *store.State, c *store.Conn, a *access, r *connTestResult) error {
	cctx, cancel := context.WithTimeout(ctx, sshOpts(st).ConnectTimeout)
	defer cancel()
	switch a.Target.Kind.Family {
	case "db":
		if a.Target.Kind.Name == "mongodb" {
			return mongoLogin(cctx, c, a, r)
		}
		db, err := dbx.Open(cctx, c.URL, a.Target, a.Password, a.Dial, true, "komando/"+actor())
		if err != nil {
			return viaTimeout(c, err)
		}
		defer db.Close()
		q := map[string]string{"postgres": "select version()", "mysql": "select version()", "sqlite": "select sqlite_version()",
			"sqlserver":  "select concat('SQL Server ', serverproperty('ProductVersion'), ' ', serverproperty('Edition'))",
			"oracle":     "select max(product) || ' ' || max(version_full) from product_component_version",
			"clickhouse": "select concat('ClickHouse ', version())",
			"snowflake":  "select 'Snowflake ' || current_version()",
			"bigquery":   "select 'BigQuery'"}[a.Target.Kind.Name]
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
	case "queue":
		q, err := openQueue(cctx, c, a, sshOpts(st).ConnectTimeout)
		if err != nil {
			return viaTimeout(c, err)
		}
		defer q.Close()
		if inf, err := q.Info(cctx); err == nil {
			r.Version = inf.Version
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

// kindExample gives a URL error without a hint of its own an example of
// that kind's URL, instead of the command's example of another kind.
func kindExample(raw string, err error) error {
	var e *out.Error
	scheme, _, ok := strings.Cut(raw, ":")
	if !ok || !errors.As(err, &e) || e.Code != "USAGE" || e.Hint != out.UsageHint {
		return err
	}
	for _, k := range driver.Kinds() {
		for _, s := range k.Schemes {
			if strings.EqualFold(s, scheme) && k.Example != "" {
				e.Hint = "a " + k.Name + " URL looks like " + k.Example
				return e
			}
		}
	}
	return err
}

// connAddKinds are the `komando KIND add` shortcuts for `conn add`: the
// same command, under the word a person looks for first. Typed alone at a
// terminal, each opens the guided form for that kind only.
var connAddKinds = map[string]struct{ what, form, example string }{
	"db":       {"database", "Database", "komando db add shop-db postgres://app@10.0.0.5:5432/app --via web1 --ask-password"},
	"cache":    {"cache", "Cache", "komando cache add cache1 redis://default@10.0.0.7:6379/0 --via web1 --ask-password"},
	"queue":    {"message queue", "Message queues", "komando queue add orders kafka://10.0.0.8:9092 --via web1"},
	"storage":  {"file storage", "File storage", "komando storage add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --ask-password"},
	"cluster":  {"cluster", "Kubernetes", "komando cluster add prod-k8s k8s://api.cluster.example:6443 --password-ref secret:prod-kubeconfig"},
	"registry": {"image registry", "Container registry", "komando registry add ghcr registry://myuser@ghcr.io --ask-password"},
}

// addKindFits refuses a URL of another area in `komando KIND add`
// (registry add k8s://...), and a Kubernetes conn without its kubeconfig,
// which could never log in.
func addKindFits(family, raw, passwordRef string) error {
	t, err := driver.Parse(normConnURL(strings.TrimSpace(raw)))
	if err != nil {
		if family == "cluster" && strings.HasPrefix(raw, "ssh://") {
			return out.Errf(out.ExitUsage, "USAGE", "add it with `komando host add NAME user@address`; cluster commands then take its name",
				"a Docker Swarm is reached through its manager server, which is a server, not a conn")
		}
		return nil // conn add says what is wrong with it
	}
	if t.Kind.Family != family { // `cache add` must not quietly save a database
		return out.Errf(out.ExitUsage, "WRONG_KIND", "add it with `komando "+t.Kind.Family+" add` (or `komando conn add`)",
			"%s is a %s URL, not one for `komando %s add`", raw, t.Kind.Name, family)
	}
	if t.Kind.Name == "k8s" && passwordRef == "" {
		return out.Errf(out.ExitUsage, "USAGE", "bring the cluster in with `komando import kubeconfig FILE` (one conn per context), or store the kubeconfig with `komando secret set NAME` and pass --password-ref secret:NAME",
			"a Kubernetes conn logs in with a whole kubeconfig, which %s alone does not give", raw)
	}
	return nil
}

// connAddCmdFor is `komando KIND add`: conn add with help for one kind.
func connAddCmdFor(kind string) *cobra.Command {
	k := connAddKinds[kind]
	c := connAddCmd()
	c.Short = "Add " + article(k.what) + " " + k.what + " (same as conn add)"
	c.Long = "Saves " + article(k.what) + " " + k.what + " under a short name. Typed alone at a terminal, it asks\nstep by step. The URL scheme sets the kind: `komando conn kinds` lists them."
	c.Example = "  " + k.example
	if kind == "cluster" {
		c.Long += "\n\nA Kubernetes cluster usually comes in with `komando import kubeconfig FILE`\n(one conn per context). Here its kubeconfig must be in the vault already\n(--password-ref). A Docker Swarm manager is a server: `komando host add`."
	}
	run := c.RunE
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 2 {
			ref, _ := cmd.Flags().GetString("password-ref")
			if err := addKindFits(kind, args[1], ref); err != nil {
				return err
			}
		}
		if len(args) > 0 {
			return run(cmd, args)
		}
		return out.Errf(out.ExitUsage, "USAGE",
			"for example: "+k.example+". A person can type `komando "+kind+" add` alone at a terminal to be asked step by step",
			"komando %s add needs a name and a URL", kind)
	}
	return c
}
