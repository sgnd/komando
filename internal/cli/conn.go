package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Conns are non-SSH resources (databases for now). They share the name space
// and selector syntax of hosts, and reach private networks through a host
// (--via) without opening a local port.

func nameTaken(kind, name string) error {
	return out.Errf(out.ExitConflict, "NAME_TAKEN", fmt.Sprintf("pick another name; hosts and conns share one name space (see `komando %s show %s`)", kind, name),
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
	fl.StringVar(&f.via, "via", "", "host to reach the resource through (SSH, no local port opened)")
	fl.StringVar(&f.passwordRef, "password-ref", "", "password reference: secret:NAME | env:VAR | file:PATH")
	fl.StringVar(&f.notes, "notes", "", "free-form notes (shown to agents in conn show)")
	fl.BoolVar(&f.protected, "protected", false, "require --yes for any change (production safety)")
	if edit {
		fl.StringSliceVar(&f.addGroups, "add-group", nil, "add to group(s)")
		fl.StringSliceVar(&f.rmGroups, "rm-group", nil, "remove from group(s)")
		fl.StringSliceVar(&f.addTags, "add-tag", nil, "add tag(s)")
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
		if _, ok := s.Hosts[c.Via]; !ok {
			return t, out.NotFound("host", c.Via)
		}
	}
	if r := c.PasswordRef; r != "" && !strings.HasPrefix(r, "secret:") && !strings.HasPrefix(r, "env:") && !strings.HasPrefix(r, "file:") {
		return t, out.Usage("invalid --password-ref %q (use secret:NAME, env:VAR or file:PATH)", r)
	}
	return t, nil
}

func connCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "conn",
		Aliases: []string{"conns"},
		Short:   "Manage non-SSH resources such as databases (add, edit, test)",
		Long: `A conn is a database (or other service) komando talks to directly. The kind
comes from the URL scheme. Passwords never go in the URL: store them with
` + "`komando secret set`" + ` and pass --password-ref. Use --via HOST when the
resource is only reachable from a server.

Conns share names and selectors (@group, tag:x, glob, all) with hosts.`,
	}
	c.AddCommand(connAddCmd(), connEditCmd(), connListCmd(), connShowCmd(), connRmCmd(), connTestCmd(), connKindsCmd())
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
  komando conn add local sqlite:///var/lib/app.db`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := validName("conn", name); err != nil {
				return err
			}
			cn := &store.Conn{Name: name, URL: strings.TrimSpace(args[1]), PasswordRef: f.passwordRef, Via: f.via,
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
			err = store.Update(func(s *store.State) error {
				if _, ok := s.Conns[name]; ok && !force {
					return out.Errf(out.ExitConflict, "CONN_EXISTS", "use `komando conn edit` or pass --force to replace", "conn %q already exists", name)
				}
				if _, ok := s.Hosts[name]; ok {
					return nameTaken("host", name)
				}
				if _, err := checkConn(s, cn); err != nil {
					return err
				}
				s.Conns[name] = cn
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "conn.add", nil, "", true, map[string]any{"conns": []string{name}})
			out.P.Print("conn.add", cn, nil)
			return nil
		},
	}
	f.bind(c, false)
	c.Flags().BoolVar(&force, "force", false, "replace an existing conn")
	return c
}

func connEditCmd() *cobra.Command {
	var f connFlags
	var url, rename string
	c := &cobra.Command{
		Use:     "edit NAME",
		Short:   "Edit a conn (only flags you pass are changed)",
		Example: `  komando conn edit prod-db --via bastion --add-tag critical --option statement_timeout=10s`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res *store.Conn
			err := store.Update(func(s *store.State) error {
				cn, ok := s.Conns[args[0]]
				if !ok {
					return out.NotFound("conn", args[0])
				}
				fl := cmd.Flags()
				set := func(name string, dst *string, v string) {
					if fl.Changed(name) {
						*dst = v
					}
				}
				set("url", &cn.URL, strings.TrimSpace(url))
				set("via", &cn.Via, f.via)
				set("password-ref", &cn.PasswordRef, f.passwordRef)
				set("notes", &cn.Notes, f.notes)
				if fl.Changed("protected") {
					cn.Protected = f.protected
				}
				cn.Groups = dedupe(append(remove(cn.Groups, f.rmGroups), f.addGroups...))
				cn.Tags = dedupe(append(remove(cn.Tags, f.rmTags), f.addTags...))
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
						return out.Usage("cannot unset %q", u)
					}
				}
				if _, err := checkConn(s, cn); err != nil {
					return err
				}
				if rename != "" && rename != cn.Name {
					if err := validName("conn", rename); err != nil {
						return err
					}
					if kind, ok := s.NameTaken(rename); ok {
						return nameTaken(kind, rename)
					}
					delete(s.Conns, cn.Name)
					cn.Name = rename
					s.Conns[rename] = cn
				}
				cn.UpdatedAt = time.Now().UTC()
				res = cn
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "conn.edit", nil, "", true, map[string]any{"conns": []string{res.Name}})
			out.P.Print("conn.edit", res, nil)
			return nil
		},
	}
	f.bind(c, true)
	c.Flags().StringVar(&url, "url", "", "new URL (the kind may change with the scheme)")
	c.Flags().StringVar(&rename, "rename", "", "rename the conn")
	return c
}

func connAttrs(c *store.Conn) selAttrs { return selAttrs{c.Name, c.Groups, c.Tags, c.Labels} }

// resolveConns expands a selector expression into conns (sorted, unique).
func resolveConns(st *store.State, expr string) ([]*store.Conn, error) {
	conns, err := resolveExpr(expr, func(sel string) ([]*store.Conn, error) {
		if res, ok := matchPattern(st.SortedConns(), connAttrs, sel); ok {
			return res, nil
		}
		if c, ok := st.Conns[sel]; ok {
			return []*store.Conn{c}, nil
		}
		return nil, out.NotFound("conn", sel)
	}, func(c *store.Conn) string { return c.Name })
	if err != nil {
		return nil, err
	}
	if len(conns) == 0 {
		return nil, out.Errf(out.ExitNotFound, "TARGET_EMPTY", "run `komando conn list` to see conns, groups and tags", "target %q matched no conns", expr)
	}
	return conns, nil
}

type connRow struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Where     string   `json:"where"`
	Via       string   `json:"via,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Protected bool     `json:"protected,omitempty"`
}

type connList struct {
	Count int       `json:"count"`
	Conns []connRow `json:"conns"`
}

func (l connList) Text() string {
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tWHERE\tVIA\tGROUPS\tTAGS\tPROTECTED")
	for _, c := range l.Conns {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%v\n", c.Name, c.Kind, c.Where, dash(c.Via), dash(strings.Join(c.Groups, ",")), dash(strings.Join(c.Tags, ",")), c.Protected)
	}
	tw.Flush()
	return sb.String()
}

func connListCmd() *cobra.Command {
	var target string
	c := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List conns (optionally filtered by a target selector)",
		Example: "  komando conn list --target @shop,tag:prod",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			conns := st.SortedConns()
			if target != "" {
				if conns, err = resolveConns(st, target); err != nil {
					return err
				}
			}
			l := connList{Conns: []connRow{}}
			for _, c := range conns {
				where := c.URL
				if t, err := driver.Parse(c.URL); err == nil {
					where = t.Where()
				}
				l.Conns = append(l.Conns, connRow{c.Name, c.Kind, where, c.Via, c.Groups, c.Tags, c.Protected})
			}
			l.Count = len(l.Conns)
			out.P.Print("conn.list", l, nil)
			return nil
		},
	}
	c.Flags().StringVar(&target, "target", "", "selector filter (@group, tag:x, glob, ...)")
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
			c, ok := st.Conns[args[0]]
			if !ok {
				return out.NotFound("conn", args[0])
			}
			out.P.Print("conn.show", c, nil)
			return nil
		},
	}
}

func connRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm NAME...",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove conn(s) from the inventory (does not touch the resource)",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := store.Update(func(s *store.State) error {
				for _, n := range args {
					if _, ok := s.Conns[n]; !ok {
						return out.NotFound("conn", n)
					}
				}
				for _, n := range args {
					delete(s.Conns, n)
				}
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "conn.rm", nil, "", true, map[string]any{"conns": args})
			out.P.Print("conn.rm", map[string]any{"removed": args}, nil)
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
			out.P.Print("conn.kinds", map[string]any{"kinds": driver.Kinds()}, nil)
			return nil
		},
	}
}

// --- connectivity ----------------------------------------------------------

type connTestResult struct {
	Conn      string     `json:"conn"`
	OK        bool       `json:"ok"`
	Kind      string     `json:"kind,omitempty"`
	Where     string     `json:"where,omitempty"`
	Via       string     `json:"via,omitempty"`
	Check     string     `json:"check,omitempty"` // tcp | file
	LatencyMS int64      `json:"latency_ms,omitempty"`
	Error     *out.Error `json:"error,omitempty"`
}

type connSummary struct {
	Total       int      `json:"total"`
	OK          int      `json:"ok"`
	Failed      int      `json:"failed"`
	FailedConns []string `json:"failed_conns,omitempty"`
}

func connTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "test TARGET",
		Aliases: []string{"ping"},
		Short:   "Check that conns are reachable (TCP, through --via if set) and their password reference resolves",
		Example: "  komando conn test all\n  komando conn test prod-db",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			conns, err := resolveConns(st, args[0])
			if err != nil {
				return err
			}
			res := make([]connTestResult, len(conns))
			sem := make(chan struct{}, max(1, parallelism(st)))
			var wg sync.WaitGroup
			for i, c := range conns {
				wg.Add(1)
				go func(i int, c *store.Conn) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					res[i] = testConn(cmd.Context(), st, c)
				}(i, c)
			}
			wg.Wait()

			data := struct {
				Results []connTestResult `json:"results"`
				Summary connSummary      `json:"summary"`
			}{Results: res}
			worst := 0
			for _, r := range res {
				if r.OK {
					data.Summary.OK++
					continue
				}
				data.Summary.Failed++
				data.Summary.FailedConns = append(data.Summary.FailedConns, r.Conn)
				worst = worse(worst, r.Error.Exit)
			}
			data.Summary.Total = len(res)
			var soft *out.Error
			if data.Summary.Failed > 0 {
				soft = &out.Error{Code: "PARTIAL_FAILURE", Message: fmt.Sprintf("%d of %d conn(s) failed: %s", data.Summary.Failed, data.Summary.Total, strings.Join(data.Summary.FailedConns, ", ")),
					Hint: "see the per-conn results (data.results) for error codes and hints", Exit: worst}
				if data.Summary.Total == 1 {
					soft.Code, soft.Message = "FAILED", "conn "+data.Summary.FailedConns[0]+" failed"
				}
			}
			names := make([]string, len(conns))
			for i, c := range conns {
				names[i] = c.Name
			}
			audit(st, "conn.test", nil, "", soft == nil, map[string]any{"conns": names})
			out.P.Print("conn.test", data, soft)
			if soft != nil {
				return exitCode(worst)
			}
			return nil
		},
	}
}

func testConn(ctx context.Context, st *store.State, c *store.Conn) connTestResult {
	r := connTestResult{Conn: c.Name, Kind: c.Kind, Via: c.Via}
	fail := func(err error) connTestResult {
		r.OK, r.Error = false, toErr(err)
		return r
	}
	t, err := driver.Parse(c.URL)
	if err != nil {
		return fail(err)
	}
	r.Where = t.Where()
	if c.PasswordRef != "" {
		if _, err := vault.Resolve(c.PasswordRef); err != nil {
			hint := "store it with `komando secret set NAME` or fix --password-ref"
			if errors.Is(err, vault.ErrNotFound) {
				return fail(out.Errf(out.ExitNotFound, "SECRET_NOT_FOUND", hint, "password reference %s: %v", c.PasswordRef, err))
			}
			return fail(out.Errf(out.ExitError, "SECRET_UNRESOLVED", hint, "password reference %s: %v", c.PasswordRef, err))
		}
	}
	t0 := time.Now()
	if t.Kind.File {
		r.Check = "file"
		if _, err := os.Stat(expandHome(t.Path)); err != nil {
			return fail(out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "check the path in the conn URL (`komando conn edit "+c.Name+" --url ...`)", "%v", err))
		}
	} else {
		r.Check = "tcp"
		timeout := sshOpts(st).ConnectTimeout
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var nc net.Conn
		if c.Via != "" {
			h, ok := st.Hosts[c.Via]
			if !ok {
				return fail(out.NotFound("host", c.Via))
			}
			sc, err := sshx.Dial(dctx, st, h, sshOpts(st))
			if err != nil {
				return fail(err)
			}
			defer sc.Close()
			nc, err = sc.DialContext(dctx, "tcp", t.Address)
			if err != nil {
				return fail(unreachable(c, t, err))
			}
		} else {
			var d net.Dialer
			nc, err = d.DialContext(dctx, "tcp", t.Address)
			if err != nil {
				return fail(unreachable(c, t, err))
			}
		}
		nc.Close()
	}
	r.OK, r.LatencyMS = true, time.Since(t0).Milliseconds()
	return r
}

func unreachable(c *store.Conn, t driver.Target, err error) *out.Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "the port may be firewalled; check the address or raise --connect-timeout", "connecting to %s timed out", t.Address)
	}
	hint := "check the address and port; if the service is only reachable from a server, set `komando conn edit " + c.Name + " --via HOST`"
	if c.Via != "" {
		hint = "the address is resolved on " + c.Via + "; check it from there with `komando net check " + c.Via + " " + t.Address + "`"
	}
	return out.Errf(out.ExitConnect, "CONN_UNREACHABLE", hint, "cannot reach %s: %v", t.Address, err)
}
