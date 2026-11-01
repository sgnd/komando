package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func validName(kind, n string) error {
	if !nameRe.MatchString(n) {
		return out.Usage("invalid %s name %q (letters, digits, . _ -; max 63)", kind, n)
	}
	return nil
}

type hostFlags struct {
	address, user, key, identity, passwordRef, sudoRef, jump, notes string
	port                                                            int
	groups, tags, labels, env                                       []string
	protected                                                       bool
	addGroups, rmGroups, addTags, rmTags, unset                     []string
}

func (f *hostFlags) bind(c *cobra.Command, edit bool) {
	fl := c.Flags()
	fl.StringVar(&f.address, "address", "", "hostname or IP")
	fl.IntVar(&f.port, "port", 0, "SSH port (default 22)")
	fl.StringVar(&f.user, "user", "", "login user")
	fl.StringVar(&f.key, "key", "", "keychain key name (see `komando key`)")
	fl.StringVar(&f.identity, "identity", "", "path to a private key file")
	fl.StringVar(&f.passwordRef, "password-ref", "", "password reference: secret:NAME | env:VAR | file:PATH")
	fl.StringVar(&f.sudoRef, "sudo-ref", "", "sudo password reference: secret:NAME | env:VAR | file:PATH")
	fl.StringVar(&f.jump, "jump", "", "jump host name(s) or user@host:port, comma-separated chain")
	fl.StringVar(&f.notes, "notes", "", "free-form notes (shown to agents in host show)")
	fl.BoolVar(&f.protected, "protected", false, "require --yes for mutating actions (production safety)")
	if edit {
		fl.StringSliceVar(&f.addGroups, "add-group", nil, "add to group(s)")
		fl.StringSliceVar(&f.rmGroups, "rm-group", nil, "remove from group(s)")
		fl.StringSliceVar(&f.addTags, "add-tag", nil, "add tag(s)")
		fl.StringSliceVar(&f.rmTags, "rm-tag", nil, "remove tag(s)")
		fl.StringSliceVar(&f.labels, "label", nil, "set label KEY=VALUE (empty value removes)")
		fl.StringSliceVar(&f.env, "env", nil, "set env KEY=VALUE exported before commands (empty value removes)")
		fl.StringSliceVar(&f.unset, "unset", nil, "clear fields: user,key,identity,password-ref,sudo-ref,jump,notes,port,protected")
	} else {
		fl.StringSliceVarP(&f.groups, "group", "g", nil, "group(s)")
		fl.StringSliceVarP(&f.tags, "tag", "t", nil, "tag(s)")
		fl.StringSliceVar(&f.labels, "label", nil, "label KEY=VALUE (repeatable)")
		fl.StringSliceVar(&f.env, "env", nil, "env KEY=VALUE exported before every command (repeatable)")
	}
}

func hostCmd() *cobra.Command {
	c := &cobra.Command{Use: "host", Aliases: []string{"hosts"}, Short: "Manage the server inventory (add, edit, import ~/.ssh/config, test, trust)"}
	c.AddCommand(hostAddCmd(), hostEditCmd(), hostListCmd(), hostShowCmd(), hostRmCmd(), hostImportCmd(), hostExportCmd(), hostTestCmd(), hostTrustCmd(), hostSSHArgsCmd())
	return c
}

func hostAddCmd() *cobra.Command {
	var f hostFlags
	var force bool
	c := &cobra.Command{
		Use:   "add NAME [user@address[:port]]",
		Short: "Add a host",
		Example: `  komando host add web1 deploy@10.0.0.11 --group web --tag prod --key deploy
  komando host add db1 --address db.internal --user root --jump bastion --protected`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := validName("host", name); err != nil {
				return err
			}
			h := &store.Host{Name: name, Address: f.address, Port: f.port, User: f.user, Key: f.key, Identity: f.identity,
				PasswordRef: f.passwordRef, SudoRef: f.sudoRef, Jump: f.jump, Groups: dedupe(f.groups), Tags: dedupe(f.tags),
				Protected: f.protected, Notes: f.notes}
			if len(args) == 2 {
				a, err := sshx.ParseAdhoc(args[1])
				if err != nil {
					return out.Usage("invalid address %q", args[1])
				}
				h.Address = a.Address
				if a.User != "" && h.User == "" {
					h.User = a.User
				}
				if a.Port != 0 && h.Port == 0 {
					h.Port = a.Port
				}
			}
			if h.Address == "" {
				return out.Usage("address required: pass user@address[:port] or --address")
			}
			var err error
			if h.Labels, err = parseKV(f.labels); err != nil {
				return err
			}
			if h.Env, err = parseKV(f.env); err != nil {
				return err
			}
			if len(h.Labels) == 0 {
				h.Labels = nil
			}
			if len(h.Env) == 0 {
				h.Env = nil
			}
			now := time.Now().UTC()
			h.CreatedAt, h.UpdatedAt = now, now
			err = store.Update(func(s *store.State) error {
				if _, ok := s.Hosts[name]; ok && !force {
					return out.Errf(out.ExitConflict, "HOST_EXISTS", "use `komando host edit` or pass --force to replace", "host %q already exists", name)
				}
				if _, ok := s.Conns[name]; ok {
					return nameTaken("conn", name)
				}
				if h.Key != "" {
					if _, ok := s.Keys[h.Key]; !ok {
						return out.NotFound("key", h.Key)
					}
				}
				s.Hosts[name] = h
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "host.add", []string{name}, "", true, nil)
			out.P.Print("host.add", h, nil)
			return nil
		},
	}
	f.bind(c, false)
	c.Flags().BoolVar(&force, "force", false, "replace an existing host")
	return c
}

func hostEditCmd() *cobra.Command {
	var f hostFlags
	var rename string
	c := &cobra.Command{
		Use:     "edit NAME",
		Short:   "Edit a host (only flags you pass are changed)",
		Example: `  komando host edit web1 --add-tag canary --label env=prod --sudo-ref secret:web1-sudo`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res *store.Host
			err := store.Update(func(s *store.State) error {
				h, ok := s.Hosts[args[0]]
				if !ok {
					return out.NotFound("host", args[0])
				}
				fl := cmd.Flags()
				set := func(name string, dst *string, v string) {
					if fl.Changed(name) {
						*dst = v
					}
				}
				set("address", &h.Address, f.address)
				set("user", &h.User, f.user)
				set("key", &h.Key, f.key)
				set("identity", &h.Identity, f.identity)
				set("password-ref", &h.PasswordRef, f.passwordRef)
				set("sudo-ref", &h.SudoRef, f.sudoRef)
				set("jump", &h.Jump, f.jump)
				set("notes", &h.Notes, f.notes)
				if fl.Changed("port") {
					h.Port = f.port
				}
				if fl.Changed("protected") {
					h.Protected = f.protected
				}
				if h.Key != "" {
					if _, ok := s.Keys[h.Key]; !ok {
						return out.NotFound("key", h.Key)
					}
				}
				h.Groups = dedupe(append(remove(h.Groups, f.rmGroups), f.addGroups...))
				h.Tags = dedupe(append(remove(h.Tags, f.rmTags), f.addTags...))
				if err := applyKV(&h.Labels, f.labels); err != nil {
					return err
				}
				if err := applyKV(&h.Env, f.env); err != nil {
					return err
				}
				for _, u := range f.unset {
					switch u {
					case "user":
						h.User = ""
					case "key":
						h.Key = ""
					case "identity":
						h.Identity = ""
					case "password-ref":
						h.PasswordRef = ""
					case "sudo-ref":
						h.SudoRef = ""
					case "jump":
						h.Jump = ""
					case "notes":
						h.Notes = ""
					case "port":
						h.Port = 0
					case "protected":
						h.Protected = false
					default:
						return out.Usage("cannot unset %q", u)
					}
				}
				if rename != "" && rename != h.Name {
					if err := validName("host", rename); err != nil {
						return err
					}
					if kind, ok := s.NameTaken(rename); ok {
						return nameTaken(kind, rename)
					}
					delete(s.Hosts, h.Name)
					old := h.Name
					h.Name = rename
					s.Hosts[rename] = h
					for _, o := range s.Hosts { // keep jump references valid
						if o.Jump != "" {
							parts := strings.Split(o.Jump, ",")
							for i, p := range parts {
								if strings.TrimSpace(p) == old {
									parts[i] = rename
								}
							}
							o.Jump = strings.Join(parts, ",")
						}
					}
					for _, c := range s.Conns {
						if c.Via == old {
							c.Via = rename
						}
					}
				}
				h.UpdatedAt = time.Now().UTC()
				res = h
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "host.edit", []string{res.Name}, "", true, nil)
			out.P.Print("host.edit", res, nil)
			return nil
		},
	}
	f.bind(c, true)
	c.Flags().StringVar(&rename, "rename", "", "rename the host")
	return c
}

func applyKV(m *map[string]string, pairs []string) error {
	kv, err := parseKV(pairs)
	if err != nil {
		return err
	}
	if len(kv) == 0 {
		return nil
	}
	if *m == nil {
		*m = map[string]string{}
	}
	for k, v := range kv {
		if v == "" {
			delete(*m, k)
		} else {
			(*m)[k] = v
		}
	}
	if len(*m) == 0 {
		*m = nil
	}
	return nil
}

type hostRow struct {
	Name      string   `json:"name"`
	Address   string   `json:"address"`
	Port      int      `json:"port"`
	User      string   `json:"user,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Jump      string   `json:"jump,omitempty"`
	Protected bool     `json:"protected,omitempty"`
}

type hostList struct {
	Count int       `json:"count"`
	Hosts []hostRow `json:"hosts"`
}

func (l hostList) Text() string {
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tUSER\tGROUPS\tTAGS\tJUMP\tPROTECTED")
	for _, h := range l.Hosts {
		fmt.Fprintf(tw, "%s\t%s:%d\t%s\t%s\t%s\t%s\t%v\n", h.Name, h.Address, h.Port, dash(h.User), dash(strings.Join(h.Groups, ",")), dash(strings.Join(h.Tags, ",")), dash(h.Jump), h.Protected)
	}
	tw.Flush()
	return sb.String()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func hostListCmd() *cobra.Command {
	var target string
	c := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List hosts (optionally filtered by a target selector)",
		Example: "  komando host list --target @web,tag:prod",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			hosts := st.SortedHosts()
			if target != "" {
				if hosts, err = resolveTargets(st, target); err != nil {
					return err
				}
			}
			l := hostList{Hosts: []hostRow{}}
			for _, h := range hosts {
				l.Hosts = append(l.Hosts, hostRow{h.Name, h.Address, h.EffectivePort(), h.User, h.Groups, h.Tags, h.Jump, h.Protected})
			}
			l.Count = len(l.Hosts)
			out.P.Print("host.list", l, nil)
			return nil
		},
	}
	c.Flags().StringVar(&target, "target", "", "selector filter (@group, tag:x, glob, ...)")
	return c
}

func hostShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Show full host configuration (secrets are references, never values)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			h, ok := st.Hosts[args[0]]
			if !ok {
				return out.NotFound("host", args[0])
			}
			out.P.Print("host.show", h, nil)
			return nil
		},
	}
}

func hostRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm NAME...",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove host(s) from the inventory (does not touch the server)",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := store.Update(func(s *store.State) error {
				for _, n := range args {
					if _, ok := s.Hosts[n]; !ok {
						return out.NotFound("host", n)
					}
					for _, c := range s.SortedConns() {
						if c.Via == n {
							return out.Errf(out.ExitConflict, "HOST_IN_USE",
								fmt.Sprintf("change it first: `komando conn edit %s --via OTHER` (or --unset via)", c.Name),
								"host %q is the --via host of conn %q", n, c.Name)
						}
					}
				}
				for _, n := range args {
					delete(s.Hosts, n)
				}
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "host.rm", args, "", true, nil)
			out.P.Print("host.rm", map[string]any{"removed": args}, nil)
			return nil
		},
	}
}

// --- import / export -------------------------------------------------------

func hostImportCmd() *cobra.Command {
	var sshConfig, jsonFile string
	var groups []string
	var overwrite bool
	c := &cobra.Command{
		Use:   "import",
		Short: "Import hosts from ~/.ssh/config or a komando JSON export",
		Example: `  komando host import --ssh-config ~/.ssh/config --group imported
  komando host import --json fleet.json --overwrite`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var hosts []*store.Host
			switch {
			case jsonFile != "":
				b, err := readFileOrStdin(jsonFile)
				if err != nil {
					return err
				}
				var exp struct {
					Hosts []*store.Host `json:"hosts"`
				}
				if err := json.Unmarshal(b, &exp); err != nil {
					// accept a raw array too, or a full envelope from `host export`
					var env struct {
						Data struct {
							Hosts []*store.Host `json:"hosts"`
						} `json:"data"`
					}
					if err2 := json.Unmarshal(b, &hosts); err2 != nil {
						if err3 := json.Unmarshal(b, &env); err3 != nil {
							return out.Usage("cannot parse %s: %v", jsonFile, err)
						}
						hosts = env.Data.Hosts
					}
				} else {
					hosts = exp.Hosts
					if hosts == nil {
						var env struct {
							Data struct {
								Hosts []*store.Host `json:"hosts"`
							} `json:"data"`
						}
						_ = json.Unmarshal(b, &env)
						hosts = env.Data.Hosts
					}
				}
			default:
				if sshConfig == "" {
					home, _ := os.UserHomeDir()
					sshConfig = filepath.Join(home, ".ssh", "config")
				}
				var err error
				hosts, err = parseSSHConfig(sshConfig)
				if err != nil {
					return err
				}
			}
			added, skipped := []string{}, []string{}
			err := store.Update(func(s *store.State) error {
				now := time.Now().UTC()
				for _, h := range hosts {
					if h == nil || h.Name == "" || h.Address == "" {
						continue
					}
					_, isConn := s.Conns[h.Name]
					if _, ok := s.Hosts[h.Name]; isConn || ok && !overwrite {
						skipped = append(skipped, h.Name)
						continue
					}
					h.Groups = dedupe(append(h.Groups, groups...))
					if h.CreatedAt.IsZero() {
						h.CreatedAt = now
					}
					h.UpdatedAt = now
					s.Hosts[h.Name] = h
					added = append(added, h.Name)
				}
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "host.import", added, "", true, nil)
			out.P.Print("host.import", map[string]any{"imported": added, "skipped_existing": skipped}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&sshConfig, "ssh-config", "", "OpenSSH config file (default ~/.ssh/config)")
	c.Flags().StringVar(&jsonFile, "json", "", "komando JSON export file ('-' for stdin)")
	c.Flags().StringSliceVarP(&groups, "group", "g", nil, "add imported hosts to group(s)")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace existing hosts with the same name")
	return c
}

func readFileOrStdin(p string) ([]byte, error) {
	if p == "-" {
		return readAllStdin()
	}
	return os.ReadFile(p)
}

// parseSSHConfig understands Host, HostName, User, Port, IdentityFile,
// ProxyJump and Include. Wildcard Host patterns become defaults.
func parseSSHConfig(path string) ([]*store.Host, error) {
	type block struct {
		patterns []string
		opts     map[string]string
	}
	var blocks []*block
	var read func(p string, depth int) error
	read = func(p string, depth int) error {
		if depth > 5 {
			return nil
		}
		f, err := os.Open(expandHome(p))
		if err != nil {
			if depth == 0 {
				return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "", "cannot open %s: %v", p, err)
			}
			return nil
		}
		defer f.Close()
		var cur *block
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, val := splitDirective(line)
			switch strings.ToLower(key) {
			case "include":
				for _, inc := range strings.Fields(val) {
					inc = expandHome(inc)
					if !filepath.IsAbs(inc) {
						inc = filepath.Join(filepath.Dir(expandHome(path)), inc)
					}
					matches, _ := filepath.Glob(inc)
					for _, m := range matches {
						_ = read(m, depth+1)
					}
				}
			case "host":
				cur = &block{patterns: strings.Fields(val), opts: map[string]string{}}
				blocks = append(blocks, cur)
			case "match":
				cur = nil
			default:
				if cur != nil {
					k := strings.ToLower(key)
					if _, set := cur.opts[k]; !set { // first value wins, like ssh
						cur.opts[k] = strings.Trim(val, `"`)
					}
				}
			}
		}
		return sc.Err()
	}
	if err := read(path, 0); err != nil {
		return nil, err
	}
	var hosts []*store.Host
	for _, b := range blocks {
		for _, pat := range b.patterns {
			if strings.ContainsAny(pat, "*?!") {
				continue
			}
			opts := map[string]string{}
			// later wildcard blocks only fill unset values (ssh: first match wins)
			for _, ob := range blocks {
				if !blockMatches(ob.patterns, pat) {
					continue
				}
				for k, v := range ob.opts {
					if _, ok := opts[k]; !ok {
						opts[k] = v
					}
				}
			}
			name := pat
			if !nameRe.MatchString(name) {
				continue
			}
			h := &store.Host{Name: name, Address: opts["hostname"], User: opts["user"], Jump: opts["proxyjump"]}
			if h.Address == "" {
				h.Address = pat
			}
			if p, err := strconv.Atoi(opts["port"]); err == nil {
				h.Port = p
			}
			if id := opts["identityfile"]; id != "" {
				h.Identity = expandHome(id)
			}
			if h.Jump == "none" {
				h.Jump = ""
			}
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

func blockMatches(patterns []string, host string) bool {
	matched := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		if ok, _ := filepath.Match(p, host); ok {
			if neg {
				return false
			}
			matched = true
		}
	}
	return matched
}

func splitDirective(line string) (string, string) {
	if i := strings.IndexAny(line, " \t="); i > 0 {
		return line[:i], strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
	}
	return line, ""
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

func hostExportCmd() *cobra.Command {
	var target string
	c := &cobra.Command{
		Use:   "export",
		Short: "Export hosts as JSON (re-importable with `host import --json`)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			hosts := st.SortedHosts()
			if target != "" {
				if hosts, err = resolveTargets(st, target); err != nil {
					return err
				}
			}
			out.P.Print("host.export", map[string]any{"hosts": hosts}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&target, "target", "", "selector filter")
	return c
}

// --- connectivity ----------------------------------------------------------

type testResult struct {
	Host          string     `json:"host"`
	OK            bool       `json:"ok"`
	LatencyMS     int64      `json:"latency_ms,omitempty"`
	ServerVersion string     `json:"server_version,omitempty"`
	RemoteUser    string     `json:"remote_user,omitempty"`
	Hostname      string     `json:"hostname,omitempty"`
	SudoNoPasswd  *bool      `json:"sudo_nopasswd,omitempty"`
	Error         *out.Error `json:"error,omitempty"`
}

func hostTestCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "test TARGET",
		Aliases: []string{"ping"},
		Short:   "Check SSH reachability + auth for one or many hosts",
		Example: "  komando host test all",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			hosts, err := resolveTargets(st, args[0])
			if err != nil {
				return err
			}
			res := fanout(cmd.Context(), st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
				t0 := time.Now()
				o, _, err := sshx.Output(ctx, c, `printf '%s\n%s\n' "$(id -un)" "$(hostname)"; sudo -n true >/dev/null 2>&1 && echo sudo-ok || echo sudo-no`, 20*time.Second)
				if err != nil {
					return nil, err
				}
				lines := strings.Split(o, "\n")
				r := testResult{OK: true, LatencyMS: time.Since(t0).Milliseconds(), ServerVersion: string(c.ServerVersion())}
				if len(lines) >= 3 {
					r.RemoteUser, r.Hostname = lines[0], lines[1]
					b := lines[2] == "sudo-ok"
					r.SudoNoPasswd = &b
				}
				return r, nil
			})
			return printTestResults(res)
		},
	}
	return c
}

func printTestResults(res []outcome) error {
	data := struct {
		Results []testResult `json:"results"`
		Summary fleetSummary `json:"summary"`
	}{}
	worst := 0
	for _, o := range res {
		var r testResult
		if o.Err != nil {
			e := toErr(o.Err)
			r = testResult{Host: o.Host.Name, Error: e}
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, o.Host.Name)
			worst = worse(worst, e.Exit)
		} else {
			r = o.Value.(testResult)
			r.Host = o.Host.Name
			data.Summary.OK++
		}
		data.Results = append(data.Results, r)
	}
	data.Summary.Total = len(res)
	return finish("host.test", data, data.Summary, worst)
}

func hostTrustCmd() *cobra.Command {
	var reset bool
	c := &cobra.Command{
		Use:   "trust NAME",
		Short: "Pin (or re-pin with --reset) a host's SSH key in komando's known_hosts",
		Long:  "Fetches the host key directly (not through jump hosts) and stores it. Use --reset after a legitimate server rebuild.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			h, err := singleHost(st, args[0])
			if err != nil {
				return err
			}
			addr := net.JoinHostPort(h.Address, strconv.Itoa(h.EffectivePort()))
			removed := 0
			if reset {
				if removed, err = sshx.ForgetHost(addr); err != nil {
					return err
				}
			}
			var key ssh.PublicKey
			if h.Jump == "" {
				key, err = sshx.ScanHostKey(cmd.Context(), addr, sshOpts(st).ConnectTimeout)
				if err != nil {
					return out.Errf(out.ExitConnect, "KEYSCAN_FAILED", "", "cannot fetch host key from %s: %v", addr, err)
				}
				if !g.dryRun {
					if err := sshx.TrustKey(addr, key); err != nil {
						return err
					}
				}
			} else {
				// behind a jump: connect with accept-new to record the key
				o := sshOpts(st)
				o.HostKeyPolicy = "accept-new"
				c, err := sshx.Dial(cmd.Context(), st, h, o)
				if err != nil {
					return err
				}
				c.Close()
			}
			res := map[string]any{"host": h.Name, "address": addr, "removed_entries": removed}
			if key != nil {
				res["key_type"] = key.Type()
				res["fingerprint"] = ssh.FingerprintSHA256(key)
			}
			audit(st, "host.trust", []string{h.Name}, "", true, nil)
			out.P.Print("host.trust", res, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&reset, "reset", false, "forget the previously pinned key first")
	return c
}

func hostSSHArgsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh-command NAME",
		Short: "Print the equivalent OpenSSH command line for a host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			h, err := singleHost(st, args[0])
			if err != nil {
				return err
			}
			parts := []string{"ssh", "-o", "UserKnownHostsFile=" + sshx.KnownHostsPath()}
			if h.EffectivePort() != 22 {
				parts = append(parts, "-p", strconv.Itoa(h.EffectivePort()))
			}
			if h.Identity != "" {
				parts = append(parts, "-i", h.Identity)
			} else if k, ok := st.Keys[h.Key]; ok {
				parts = append(parts, "-i", k.Path)
			}
			if h.Jump != "" {
				var js []string
				for _, j := range strings.Split(h.Jump, ",") {
					if jh, ok := st.Hosts[strings.TrimSpace(j)]; ok {
						s := jh.Address
						if jh.User != "" {
							s = jh.User + "@" + s
						}
						if jh.EffectivePort() != 22 {
							s += ":" + strconv.Itoa(jh.EffectivePort())
						}
						js = append(js, s)
					} else {
						js = append(js, j)
					}
				}
				parts = append(parts, "-J", strings.Join(js, ","))
			}
			dest := h.Address
			if h.User != "" {
				dest = h.User + "@" + dest
			}
			parts = append(parts, dest)
			out.P.Print("host.ssh-command", sshCmdResult{Argv: parts, Command: strings.Join(parts, " ")}, nil)
			return nil
		},
	}
}

type sshCmdResult struct {
	Argv    []string `json:"argv"`
	Command string   `json:"command"`
}

func (r sshCmdResult) Text() string { return r.Command }

// --- groups ----------------------------------------------------------------

func groupCmd() *cobra.Command {
	c := &cobra.Command{Use: "group", Aliases: []string{"groups"}, Short: "List groups and manage membership"}
	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List groups and tags with their member hosts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			groups, tags := map[string][]string{}, map[string][]string{}
			for _, h := range st.SortedHosts() {
				for _, gr := range h.Groups {
					groups[gr] = append(groups[gr], h.Name)
				}
				for _, t := range h.Tags {
					tags[t] = append(tags[t], h.Name)
				}
			}
			out.P.Print("group.list", map[string]any{"groups": groups, "tags": tags}, nil)
			return nil
		},
	})
	member := func(use string, addTo bool) *cobra.Command {
		return &cobra.Command{
			Use:   use + " GROUP TARGET",
			Short: map[bool]string{true: "Add hosts matching TARGET to GROUP", false: "Remove hosts matching TARGET from GROUP"}[addTo],
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				var changed []string
				err := store.Update(func(s *store.State) error {
					hosts, err := resolveTargets(s, args[1])
					if err != nil {
						return err
					}
					for _, h := range hosts {
						if h2, ok := s.Hosts[h.Name]; ok {
							if addTo {
								h2.Groups = dedupe(append(h2.Groups, args[0]))
							} else {
								h2.Groups = remove(h2.Groups, []string{args[0]})
							}
							changed = append(changed, h.Name)
						}
					}
					return nil
				})
				if err != nil {
					return err
				}
				out.P.Print("group."+use, map[string]any{"group": args[0], "hosts": changed}, nil)
				return nil
			},
		}
	}
	c.AddCommand(member("add", true), member("remove", false))
	return c
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var res []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		res = append(res, s)
	}
	sort.Strings(res)
	return res
}

func remove(in, drop []string) []string {
	d := map[string]bool{}
	for _, x := range drop {
		d[x] = true
	}
	var res []string
	for _, s := range in {
		if !d[s] {
			res = append(res, s)
		}
	}
	return res
}
