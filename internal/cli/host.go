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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func validName(kind, n string) error {
	if !nameRe.MatchString(n) {
		return out.Usage("invalid %s name %q (letters, digits, . _ -; max 63)", kind, n)
	}
	if (kind == "host" || kind == "conn" || kind == "vpn") && strings.EqualFold(n, "all") {
		return out.Usage("%q cannot be a %s name: as a target it means everything", n, kind)
	}
	return nil
}

type hostFlags struct {
	address, user, key, identity, passwordRef, sudoRef, jump, notes string
	proxyCommand                                                    string
	ssm                                                             bool
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
	fl.StringVar(&f.passwordRef, "password-ref", "", "password reference: secret:NAME | env:VAR | file:PATH | op://... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME")
	fl.StringVar(&f.sudoRef, "sudo-ref", "", "sudo password reference: secret:NAME | env:VAR | file:PATH | op://... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME")
	fl.StringVar(&f.jump, "via", "", "reach it through these host(s) (bastions), comma-separated chain")
	aliasFlag(fl, "jump", "via")
	fl.StringVar(&f.proxyCommand, "proxy-command", "", "a command on this computer that carries the connection (OpenSSH ProxyCommand; %h %p %r)")
	fl.BoolVar(&f.ssm, "ssm", false, "reach it through AWS Systems Manager: the address is the instance ID (needs the aws CLI and its session-manager-plugin)")
	fl.StringVar(&f.notes, "notes", "", "free-form notes (shown to agents in host show)")
	fl.BoolVar(&f.protected, "protected", false, "require --yes for mutating actions (production safety)")
	if edit {
		fl.StringSliceVar(&f.addGroups, "add-group", nil, "add to group(s)")
		fl.StringSliceVar(&f.rmGroups, "rm-group", nil, "remove from group(s)")
		fl.StringSliceVar(&f.addTags, "add-tag", nil, "add tag(s)")
		fl.StringSliceVar(&f.rmTags, "rm-tag", nil, "remove tag(s)")
		fl.StringSliceVar(&f.labels, "label", nil, "set label KEY=VALUE (empty value removes)")
		fl.StringSliceVar(&f.env, "env", nil, "set env KEY=VALUE exported before commands (empty value removes)")
		fl.StringSliceVar(&f.unset, "unset", nil, "clear fields: user,key,identity,password-ref,sudo-ref,via,proxy-command,notes,port,protected")
	} else {
		fl.StringSliceVarP(&f.groups, "group", "g", nil, "group(s)")
		fl.StringSliceVarP(&f.tags, "tag", "t", nil, "tag(s)")
		fl.StringSliceVar(&f.labels, "label", nil, "label KEY=VALUE (repeatable)")
		fl.StringSliceVar(&f.env, "env", nil, "env KEY=VALUE exported before every command (repeatable)")
	}
}

func hostCmd() *cobra.Command {
	c := &cobra.Command{Use: "host", Aliases: []string{"hosts"}, Short: "Manage the server inventory (add, edit, import ~/.ssh/config, test, trust)"}
	c.AddCommand(hostAddCmd(), hostEditCmd(), alias(listCmdFor("host"), "list kind:host"), hostShowCmd(), hostRmCmd(), hostImportCmd(), hostExportCmd(), alias(testCmdFor("host"), "test"), hostTrustCmd(), hostSSHArgsCmd())
	return c
}

func hostAddCmd() *cobra.Command {
	var f hostFlags
	var force bool
	c := &cobra.Command{
		Use:   "add NAME [user@address[:port]]",
		Short: "Add a host",
		Example: `  komando host add web1 deploy@10.0.0.11 --group web --tag prod --key deploy
  komando host add db1 --address db.internal --user root --via bastion --protected`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := validName("host", name); err != nil {
				return err
			}
			if err := guardProxyCommand(f.proxyCommand); err != nil {
				return err
			}
			h := &store.Host{Name: name, Address: f.address, Port: f.port, User: f.user, Key: f.key, Identity: f.identity,
				PasswordRef: f.passwordRef, SudoRef: f.sudoRef, Via: f.jump, ProxyCommand: f.proxyCommand, Groups: dedupe(f.groups), Tags: dedupe(f.tags),
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
			if f.ssm {
				h.ProxyCommand = ssmProxy
			}
			if err := checkHostRefs(h); err != nil {
				return err
			}
			var err error
			if h.Labels, err = parseKV(f.labels); err != nil {
				return err
			}
			if h.Env, err = parseEnv(f.env); err != nil {
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
				if err := checkNewName(s, "host", name, force); err != nil {
					return err
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
	c.Flags().BoolVar(&force, "overwrite", false, "replace an existing host with the same name")
	aliasFlag(c.Flags(), "force", "overwrite")
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
			if err := guardProxyCommand(f.proxyCommand); err != nil {
				return err
			}
			var res *store.Host
			err := store.Update(func(s *store.State) error {
				h, ok := s.Hosts[args[0]]
				if !ok {
					return out.NotFound("host", args[0])
				}
				wasProtected := h.Protected
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
				set("via", &h.Via, f.jump)
				set("proxy-command", &h.ProxyCommand, f.proxyCommand)
				if f.ssm {
					h.ProxyCommand = ssmProxy
				}
				set("notes", &h.Notes, f.notes)
				if fl.Changed("port") {
					h.Port = f.port
				}
				if fl.Changed("protected") {
					h.Protected = f.protected
				}
				if err := checkHostRefs(h); err != nil {
					return err
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
				if err := checkEnvKeys(h.Env); err != nil {
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
					case "via", "jump":
						h.Via = ""
					case "proxy-command":
						h.ProxyCommand = ""
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
				if wasProtected && !h.Protected {
					if err := guardProtection("host", "turning off protection of", []string{h.Name}); err != nil {
						return err
					}
				}
				if rename != "" && rename != h.Name {
					if err := validName("host", rename); err != nil {
						return err
					}
					if kind, existing, ok := s.FindName(rename); ok && existing != h.Name {
						return nameTaken(kind, existing)
					}
					delete(s.Hosts, h.Name)
					old := h.Name
					h.Name = rename
					s.Hosts[rename] = h
					for _, o := range s.Hosts { // keep --via references valid
						o.Via = renameStep(o.Via, old, rename)
					}
					for _, c := range s.Conns {
						c.Via = renameStep(c.Via, old, rename)
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

// ssmProxy reaches an EC2 instance (the host's address is its ID) through
// AWS Systems Manager, as AWS documents for SSH; the aws CLI picks the
// profile and region from its usual settings (AWS_PROFILE, AWS_REGION).
const ssmProxy = "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"

// guardProxyCommand: a proxy command runs on this computer each time komando
// connects, outside the agent guard's view. It passes the policy filter, and
// from an AI agent it needs a person's yes (--yes, then the window). --ssm
// sets komando's own command and needs neither.
func guardProxyCommand(cmd string) error {
	if cmd == "" {
		return nil
	}
	if hits := policy.Check(cmd, nil); len(hits) > 0 && !dangerOK() {
		return out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "a proxy command only carries the connection, e.g. `aws ssm start-session ...`",
			"--proxy-command matches destructive rules: %s", hits[0].Reason)
	}
	if isAgent() {
		return guardSafety("--proxy-command runs `" + cmd + "` on this computer whenever komando connects")
	}
	return nil
}

// checkHostRefs refuses a password typed where a reference belongs
// (--password-ref hunter2 would be stored and printed as plain text).
func checkHostRefs(h *store.Host) error {
	if h.ProxyCommand != "" && h.Via != "" {
		return out.Usage("a host takes --proxy-command or --via, not both (put the proxy on the first host of the --via chain)")
	}
	for _, r := range []struct{ flag, ref string }{{"--password-ref", h.PasswordRef}, {"--sudo-ref", h.SudoRef}} {
		if r.ref != "" && !vault.ValidRef(r.ref) {
			return out.Usage("invalid %s: it takes a reference, not the password itself (%s); store the password with `komando secret set NAME` first", r.flag, vault.RefHelp())
		}
	}
	return nil
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
		Use:   "rm NAME...",
		Short: "Remove host(s) from the inventory (does not touch the server)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := store.Update(func(s *store.State) error {
				var prot []string
				for _, n := range args {
					if _, ok := s.Hosts[n]; !ok {
						return out.NotFound("host", n)
					}
					if s.Hosts[n].Protected {
						prot = append(prot, n)
					}
					for _, o := range s.SortedHosts() {
						if o.Name != n && slices.Contains(viaChain(o.Via), n) {
							return out.Errf(out.ExitConflict, "HOST_IN_USE",
								fmt.Sprintf("change it first: `komando host edit %s --via OTHER` (or --unset via)", o.Name),
								"host %q is on the --via path of host %q", n, o.Name)
						}
					}
					for _, c := range s.SortedConns() {
						if slices.Contains(viaChain(c.Via), n) {
							return out.Errf(out.ExitConflict, "HOST_IN_USE",
								fmt.Sprintf("change it first: `komando conn edit %s --via OTHER` (or --unset via)", c.Name),
								"host %q is the --via host of conn %q", n, c.Name)
						}
					}
				}
				if err := guardProtection("host", "removing", prot); err != nil {
					return err
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
		Short: "Same as `komando import ssh-config` (hosts only)",
		Example: `  komando host import --ssh-config ~/.ssh/config --group imported
  komando host import --json fleet.json --overwrite`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var hosts []*store.Host
			var notes []string
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
				hosts, notes, err = parseSSHConfig(sshConfig)
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
					if validName("host", h.Name) != nil || checkNewName(s, "host", h.Name, overwrite) != nil {
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
			res := map[string]any{"imported": added, "skipped_existing": skipped}
			if len(notes) > 0 {
				res["notes"] = notes
			}
			out.P.Print("host.import", res, nil)
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
// sshUsed are the ssh_config directives komando turns into host settings.
// sshHarmless change nothing komando needs (its own client already behaves
// that way or the option only tunes OpenSSH). Anything else is reported
// after an import, so a setting is never dropped silently.
var sshUsed = set("hostname user port identityfile proxyjump proxycommand")
var sshHarmless = set(`serveraliveinterval serveralivecountmax addkeystoagent usekeychain identitiesonly
stricthostkeychecking userknownhostsfile globalknownhostsfile loglevel compression controlmaster controlpath
controlpersist connecttimeout tcpkeepalive visualhostkey hashknownhosts preferredauthentications
pubkeyauthentication passwordauthentication kbdinteractiveauthentication updatehostkeys canonicalizehostname
checkhostip batchmode`)

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

// parseSSHConfig reads an OpenSSH config into hosts. notes lists what it
// could not carry over (Match blocks, ProxyCommand, ...), per host.
func parseSSHConfig(path string) (hosts []*store.Host, notes []string, err error) {
	type block struct {
		patterns []string
		opts     map[string]string
		raw      map[string]string // directive names as written, for notes
	}
	var blocks []*block
	matches := 0
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
				cur = &block{patterns: strings.Fields(val), opts: map[string]string{}, raw: map[string]string{}}
				blocks = append(blocks, cur)
			case "match":
				cur = nil
				matches++
			default:
				if cur != nil {
					k := strings.ToLower(key)
					if _, set := cur.opts[k]; !set { // first value wins, like ssh
						cur.opts[k] = strings.Trim(val, `"`)
						cur.raw[k] = key
					}
				}
			}
		}
		return sc.Err()
	}
	if err := read(path, 0); err != nil {
		return nil, nil, err
	}
	if matches > 0 {
		notes = append(notes, fmt.Sprintf("%d Match block(s) skipped: komando cannot evaluate Match; add those settings to the hosts with `komando host edit`", matches))
	}
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
			h := &store.Host{Name: name, Address: opts["hostname"], User: opts["user"], Via: opts["proxyjump"]}
			if pc := opts["proxycommand"]; pc != "" && !strings.EqualFold(pc, "none") && h.Via == "" {
				h.ProxyCommand = pc // your own ssh config: the same program runs as with ssh
			}
			if h.Address == "" {
				h.Address = pat
			}
			if p, err := strconv.Atoi(opts["port"]); err == nil {
				h.Port = p
			}
			if id := opts["identityfile"]; id != "" {
				h.Identity = expandHome(id)
			}
			if h.Via == "none" {
				h.Via = ""
			}
			var dropped []string
			for k := range opts {
				if !sshUsed[k] && !sshHarmless[k] {
					dropped = append(dropped, k)
				}
			}
			if len(dropped) > 0 {
				sort.Strings(dropped)
				notes = append(notes, fmt.Sprintf("%s: not carried over: %s", name, strings.Join(dropped, ", ")))
			}
			hosts = append(hosts, h)
		}
	}
	return hosts, notes, nil
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
		Short: "Hosts only, as JSON for `host import --json` (`komando export` saves everything)",
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

// testHost logs in and checks who we are and whether sudo needs a password.
func testHost(ctx context.Context, c *sshx.Client) (any, error) {
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
}

func hostTrustCmd() *cobra.Command {
	var reset bool
	c := &cobra.Command{
		Use:   "trust NAME",
		Short: "Pin (or re-pin with --reset) a host's SSH key in komando's known_hosts",
		Long:  "Fetches the host key directly (not through --via hosts) and stores it. Use --reset after a legitimate server rebuild.",
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
			if h.Via == "" {
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
			if h.Via != "" {
				var js []string
				for _, j := range strings.Split(h.Via, ",") {
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
			if h.ProxyCommand != "" {
				parts = append(parts, "-o", "ProxyCommand="+h.ProxyCommand) // ssh fills in %h %p itself
			}
			dest := h.Address
			if h.User != "" {
				dest = h.User + "@" + dest
			}
			parts = append(parts, dest)
			line := make([]string, len(parts))
			for i, p := range parts {
				line[i] = p
				if strings.ContainsAny(p, " '\"$") {
					line[i] = sshx.Q(p)
				}
			}
			out.P.Print("host.ssh-command", sshCmdResult{Argv: parts, Command: strings.Join(line, " ")}, nil)
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
		Short: "List groups and tags with their members (servers and conns)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			groups, tags := map[string][]string{}, map[string][]string{}
			add := func(name string, gs, ts []string) {
				for _, gr := range gs {
					groups[gr] = append(groups[gr], name)
				}
				for _, t := range ts {
					tags[t] = append(tags[t], name)
				}
			}
			for _, h := range st.SortedHosts() {
				add(h.Name, h.Groups, h.Tags)
			}
			for _, c := range st.SortedConns() {
				add(c.Name, c.Groups, c.Tags)
			}
			for _, v := range st.SortedVpns() {
				add(v.Name, v.Groups, v.Tags)
			}
			for _, m := range []map[string][]string{groups, tags} {
				for k := range m {
					sort.Strings(m[k])
				}
			}
			out.P.Print("group.list", map[string]any{"groups": groups, "tags": tags}, nil)
			return nil
		},
	})
	member := func(use string, addTo bool) *cobra.Command {
		return &cobra.Command{
			Use:   use + " GROUP TARGET",
			Short: map[bool]string{true: "Add servers and conns matching TARGET to GROUP", false: "Remove servers and conns matching TARGET from GROUP"}[addTo],
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				change := func(gs []string) []string {
					if addTo {
						return dedupe(append(gs, args[0]))
					}
					return remove(gs, []string{args[0]})
				}
				hosts, conns := []string{}, []string{}
				err := store.Update(func(s *store.State) error {
					sel, err := resolveSelection(s, args[1])
					if err != nil {
						return err
					}
					for _, h := range sel.Hosts {
						if h2, ok := s.Hosts[h.Name]; ok { // not ad-hoc
							h2.Groups = change(h2.Groups)
							hosts = append(hosts, h.Name)
						}
					}
					for _, c := range sel.Conns {
						c.Groups = change(c.Groups)
						conns = append(conns, c.Name)
					}
					for _, v := range sel.Vpns {
						v.Groups = change(v.Groups)
						conns = append(conns, v.Name)
					}
					return nil
				})
				if err != nil {
					return err
				}
				out.P.Print("group."+use, map[string]any{"group": args[0], "hosts": hosts, "conns": conns}, nil)
				return nil
			},
		}
	}
	c.AddCommand(member("add", true), member("rm", false))
	return c
}

// renameStep replaces a renamed host in a --via chain.
func renameStep(via, old, now string) string {
	steps := viaChain(via)
	for i, s := range steps {
		if s == old {
			steps[i] = now
		}
	}
	return strings.Join(steps, ",")
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
