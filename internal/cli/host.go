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
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

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
	fl.StringVar(&f.key, "key", "", "name of a key in komando's keychain (see komando key list)")
	fl.StringVar(&f.identity, "identity", "", "path to a private key file")
	fl.StringVar(&f.passwordRef, "password-ref", "", "password reference: secret:NAME | env:VAR | file:PATH | op://... | bw://... | kdbx:... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME")
	fl.StringVar(&f.sudoRef, "sudo-ref", "", "sudo password reference: secret:NAME | env:VAR | file:PATH | op://... | bw://... | kdbx:... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME")
	fl.StringVar(&f.jump, "via", "", "reach it through these servers (bastions) or a VPN first, comma-separated path, e.g. vpn1,bastion")
	aliasFlag(fl, "jump", "via")
	fl.StringVar(&f.proxyCommand, "proxy-command", "", "a command on this computer that carries the connection (OpenSSH ProxyCommand; %h %p %r)")
	fl.BoolVar(&f.ssm, "ssm", false, "reach it through AWS Systems Manager: the address is the instance ID (komando speaks Session Manager itself when the aws CLI or its plugin is not installed)")
	fl.StringVar(&f.notes, "notes", "", "free-form notes (shown to agents in host show)")
	fl.BoolVar(&f.protected, "protected", false, "require --yes for any change to the server or to this entry (production safety)")
	if edit {
		fl.StringSliceVar(&f.addGroups, "add-group", nil, "add to group(s)")
		fl.StringSliceVar(&f.rmGroups, "rm-group", nil, "remove from group(s)")
		fl.StringSliceVar(&f.addTags, "add-tag", nil, "add tag(s)")
		shortAlias(fl, "group", "g", "add-group")
		shortAlias(fl, "tag", "t", "add-tag")
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
	c := &cobra.Command{Use: "host", Aliases: []string{"hosts"}, Short: "Manage the server inventory (add, edit, rename, import, test, trust)"}
	c.AddCommand(hostAddCmd(), hostEditCmd(), hostMvCmd(), alias(listCmdFor("host"), "list kind:host"), hostShowCmd(), hostRmCmd(), hostImportCmd(), hostExportCmd(), alias(testCmdFor("host"), "test"), hostTrustCmd(), hostSSHArgsCmd())
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
				a, err := parseAddressArg(args[1])
				if err != nil {
					return err
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
				return out.Errf(out.ExitUsage, "USAGE", "e.g. komando host add "+name+" deploy@10.0.0.5, or --address 10.0.0.5",
					"address required: pass user@address[:port] or --address")
			}
			h.Address = normAddr(h.Address)
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
			res := hostResult{Host: h}
			replaced := false
			err = store.Update(func(s *store.State) error {
				if err := checkNewName(s, "host", name, force); err != nil {
					return err
				}
				_, replaced = s.Hosts[name]
				if h.Key != "" {
					if _, ok := s.Keys[h.Key]; !ok {
						return keyNotFound(s, h.Key)
					}
				}
				if err := checkHost(s, h); err != nil {
					return err
				}
				if twin := protectedTwinHost(s, h); twin != "" && !h.Protected {
					h.Protected = true
					res.Warnings = append(res.Warnings, sameTwinWarning("server", name, twin))
				}
				s.Hosts[name] = h
				return nil
			})
			if err != nil {
				return err
			}
			res.Action = addVerb(replaced)
			audit(nil, "host.add", []string{name}, "", true, map[string]any{"action": res.Action})
			out.P.Print("host.add", res, nil)
			return nil
		},
	}
	f.bind(c, false)
	c.Flags().BoolVar(&force, "overwrite", false, "replace an existing host with the same name")
	aliasFlag(c.Flags(), "force", "overwrite")
	return c
}

// addVerb says what an add did, or would do under --dry-run.
func addVerb(replaced bool) string {
	v := map[bool]string{false: "added", true: "replaced"}[replaced]
	if g.dryRun {
		v = map[bool]string{false: "would_add", true: "would_replace"}[replaced]
	}
	return v
}

// parseAddressArg reads user@address[:port] for host add.
func parseAddressArg(arg string) (*store.Host, error) {
	if strings.HasPrefix(arg, "@") {
		return nil, out.Errf(out.ExitUsage, "USAGE", "write user@address, or leave the user out: "+strings.TrimPrefix(arg, "@"), "empty user before @ in %q", arg)
	}
	a, err := sshx.ParseAdhoc(arg)
	if err != nil {
		return nil, out.Errf(out.ExitUsage, "USAGE", "write it as user@address[:port], e.g. deploy@10.0.0.5:2222", "invalid address %q", arg)
	}
	return a, nil
}

func hostEditCmd() *cobra.Command {
	var f hostFlags
	var rename string
	c := &cobra.Command{
		Use:   "edit NAME|TARGET...",
		Short: "Edit one or more hosts (only flags you pass are changed)",
		Long: `Changes only the settings you pass. Give one name, several names, or a
selector (@group, tag:prod, 'web-*') to change many servers at once.
Changing the login (--user, --key, --password-ref, --sudo-ref, --via, ...)
of protected servers, or turning their protection off, needs --yes: one yes
covers every server in the command, and the question lists them all. Try
--dry-run first to see which servers would change.`,
		Example: `  komando host edit web1 --add-tag canary --label env=prod --sudo-ref secret:web1-sudo
  komando host edit web1 -g web -t prod          # -g/-t add a group/tag
  komando host edit db1 --via bastion --yes      # db1 is protected
  komando host edit @ubuntu --sudo-ref secret:ubuntu-sudo --dry-run
  komando host edit web1 web2 web3 --user deploy`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fl := cmd.Flags()
			if len(changedFlags(cmd)) == 0 {
				return out.Errf(out.ExitUsage, "USAGE", "pass what to change, e.g. komando host edit "+args[0]+" --user deploy (see --help)", "nothing to change")
			}
			if err := editConflicts(fl, f.unset, map[string]string{"user": "user", "key": "key", "identity": "identity", "password-ref": "password-ref",
				"sudo-ref": "sudo-ref", "via": "via", "jump": "via", "proxy-command": "proxy-command", "notes": "notes", "port": "port", "protected": "protected"},
				[][2][]string{{f.addGroups, f.rmGroups}, {f.addTags, f.rmTags}}); err != nil {
				return err
			}
			if err := guardProxyCommand(f.proxyCommand); err != nil {
				return err
			}
			var res hostResult
			var many hostEditResult
			single := false
			err := store.Update(func(s *store.State) error {
				hosts, err := pickHosts(s, args)
				if err != nil {
					return err
				}
				_, ferr := findHost(s, args[0])
				single = len(args) == 1 && ferr == nil
				if !single {
					for _, flag := range []string{"address", "rename"} {
						if fl.Changed(flag) {
							return out.Errf(out.ExitUsage, "USAGE", "edit the servers one at a time for this, e.g. komando host edit "+hosts[0].Name+" --"+flag+" ...",
								"--%s gives one server a value no other server should share; it takes one NAME, not %d servers", flag, len(hosts))
						}
					}
				}
				type edit struct {
					h      *store.Host
					before []byte
				}
				var edits []edit
				var off, login []string
				for _, h := range hosts {
					before, _ := json.Marshal(h)
					conn := *h // the connection settings before the edit
					if err := applyHostEdit(h, &f, fl); err != nil {
						return editErr(err, h.Name, single)
					}
					if h.Key != "" {
						if _, ok := s.Keys[h.Key]; !ok {
							return keyNotFound(s, h.Key)
						}
					}
					if conn.Protected && !h.Protected {
						off = append(off, h.Name)
					}
					if conn.Protected && hostConnChanged(&conn, h) {
						login = append(login, h.Name)
					}
					edits = append(edits, edit{h, before})
				}
				if err := guardHostEdit(hosts, off, login, single); err != nil {
					return err
				}
				if rename != "" && rename != hosts[0].Name {
					if _, err := renameHost(s, hosts[0].Name, rename); err != nil {
						return err
					}
				}
				for _, e := range edits {
					h := e.h
					if err := checkHost(s, h); err != nil {
						return editErr(err, h.Name, single)
					}
					var warnings []string
					if !h.Protected {
						if twin := protectedTwinHost(s, h); twin != "" {
							h.Protected = true
							warnings = append(warnings, sameTwinWarning("server", h.Name, twin))
						}
					}
					after, _ := json.Marshal(h)
					ch := string(e.before) != string(after)
					if ch {
						h.UpdatedAt = time.Now().UTC()
						many.Changed = append(many.Changed, h.Name)
					} else {
						many.Unchanged = append(many.Unchanged, h.Name)
					}
					if h.Protected {
						many.Protected = append(many.Protected, h.Name)
					}
					many.Hosts = append(many.Hosts, h)
					many.Warnings = append(many.Warnings, warnings...)
					res.Host, res.Changed, res.Warnings = h, &ch, warnings
				}
				return nil
			})
			if err != nil {
				return err
			}
			if single {
				if *res.Changed {
					audit(nil, "host.edit", []string{res.Name}, "", true, map[string]any{"flags": changedFlags(cmd)})
				}
				out.P.Print("host.edit", res, nil)
				return nil
			}
			if len(many.Changed) > 0 {
				audit(nil, "host.edit", many.Changed, "", true, map[string]any{"flags": changedFlags(cmd), "targets": args})
			}
			many.Changed, many.Unchanged = orEmpty(many.Changed), orEmpty(many.Unchanged)
			out.P.Print("host.edit", many, nil)
			return nil
		},
	}
	f.bind(c, true)
	c.Flags().StringVar(&rename, "rename", "", "rename the host")
	_ = c.Flags().MarkDeprecated("rename", "use `komando host mv OLD NEW`")
	return c
}

// hostEditResult is what host edit prints for several servers.
type hostEditResult struct {
	Changed   []string      `json:"changed"`             // names of the servers the edit changed
	Unchanged []string      `json:"unchanged"`           // already as asked
	Protected []string      `json:"protected,omitempty"` // which of them are protected
	Hosts     []*store.Host `json:"hosts"`               // every server, after the edit
	Warnings  []string      `json:"warnings,omitempty"`
}

func (r hostEditResult) Text() string {
	verb := "changed"
	if g.dryRun {
		verb = "would change"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: %s\n", verb, dash(strings.Join(r.Changed, ", ")))
	if len(r.Unchanged) > 0 {
		fmt.Fprintf(&sb, "unchanged: %s\n", strings.Join(r.Unchanged, ", "))
	}
	if len(r.Protected) > 0 {
		fmt.Fprintf(&sb, "protected: %s\n", strings.Join(r.Protected, ", "))
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&sb, "warning: %s\n", w)
	}
	return sb.String()
}

// editErr names the server an edit of several failed on.
func editErr(err error, name string, single bool) error {
	if single {
		return err
	}
	if e, ok := err.(*out.Error); ok {
		c := *e
		c.Message = name + ": " + c.Message
		return &c
	}
	return fmt.Errorf("%s: %w", name, err)
}

// guardHostEdit asks once for every protected server whose protection the
// edit turns off (off) or whose login it changes (login). With several
// servers the question lists all of them and marks the protected ones.
func guardHostEdit(hosts []*store.Host, off, login []string, single bool) error {
	var names []string
	for _, h := range hosts {
		if slices.Contains(off, h.Name) || slices.Contains(login, h.Name) {
			names = append(names, h.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	action := "changing where or how komando logs in to"
	switch {
	case len(login) == 0:
		action = "turning off protection of"
	case len(off) > 0:
		action = "turning off protection of, or changing the login of,"
	}
	if single {
		return guardProtection("host", action, names)
	}
	all := hostNames(hosts)
	return guardProtectionWhy("host", action, names,
		fmt.Sprintf("this edit changes %d servers: %s (protected: %s)", len(all), strings.Join(all, ", "), strings.Join(names, ", ")))
}

// applyHostEdit applies the edit flags to h.
func applyHostEdit(h *store.Host, f *hostFlags, fl *pflag.FlagSet) error {
	set := func(name string, dst *string, v string) {
		if fl.Changed(name) {
			*dst = v
		}
	}
	set("address", &h.Address, normAddr(f.address))
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
	h.Groups = dedupe(append(removeFold(h.Groups, f.rmGroups), f.addGroups...))
	h.Tags = dedupe(append(removeFold(h.Tags, f.rmTags), f.addTags...))
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
			return out.Errf(out.ExitUsage, "USAGE", "--unset takes: user, key, identity, password-ref, sudo-ref, via, proxy-command, notes, port, protected",
				"cannot unset %q", u)
		}
	}
	return checkHostRefs(h)
}

// hostConnChanged: the edit changes which server komando reaches or how it
// logs in.
func hostConnChanged(a, b *store.Host) bool {
	return !sameAddress(a.Address, b.Address) || a.Port != b.Port || a.User != b.User || a.Key != b.Key || a.Identity != b.Identity ||
		a.PasswordRef != b.PasswordRef || a.SudoRef != b.SudoRef || a.Via != b.Via || a.ProxyCommand != b.ProxyCommand
}

// editConflicts refuses an edit that sets and unsets the same field, or
// adds and removes the same group or tag. fields maps flag names to the
// --unset word that clears them.
func editConflicts(fl *pflag.FlagSet, unset []string, fields map[string]string, addRm [][2][]string) error {
	for flag, word := range fields {
		if fl.Lookup(flag) != nil && fl.Changed(flag) && slices.Contains(unset, word) {
			return out.Errf(out.ExitUsage, "USAGE", "pass one of them", "--%s and --unset %s contradict each other", flag, word)
		}
	}
	for _, p := range addRm {
		for _, a := range p[0] {
			if slices.ContainsFunc(p[1], func(r string) bool { return strings.EqualFold(r, a) }) {
				return out.Errf(out.ExitUsage, "USAGE", "pass one of them", "%q is both added and removed", a)
			}
		}
	}
	return nil
}

// changedFlags lists the command's own flags that were given, for checks
// and the audit log (names only: values may be references).
func changedFlags(cmd *cobra.Command) []string {
	var names []string
	cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			names = append(names, f.Name)
		}
	})
	return names
}

// removeFold is remove, ignoring case (group and tag selectors do).
func removeFold(in, drop []string) []string {
	var res []string
	for _, s := range in {
		if !slices.ContainsFunc(drop, func(d string) bool { return strings.EqualFold(d, s) }) {
			res = append(res, s)
		}
	}
	return res
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
		return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "a proxy command only carries the connection, e.g. `aws ssm start-session ...`",
			"--proxy-command matches destructive rules: %s", hits[0].Reason))
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
			h, err := findHost(st, args[0])
			if err != nil {
				return err
			}
			out.P.Print("host.show", h, nil)
			return nil
		},
	}
}

func hostRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm NAME|TARGET...",
		Short: "Remove host(s) from the inventory (does not touch the server)",
		Example: `  komando host rm web3
  komando host rm @old --dry-run     # what a selector would remove
  komando host rm 'tmp-*'`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var names []string
			err := store.Update(func(s *store.State) error {
				var prot []string
				batch := map[string]bool{}
				hosts, err := pickHosts(s, args)
				if err != nil {
					return err
				}
				for _, h := range hosts {
					names = append(names, h.Name)
					batch[h.Name] = true
					if h.Protected {
						prot = append(prot, h.Name)
					}
				}
				for _, n := range names {
					for _, o := range s.SortedHosts() {
						// a host removed in the same command does not count
						if !batch[o.Name] && slices.Contains(viaChain(o.Via), n) {
							return out.Errf(out.ExitConflict, "HOST_IN_USE",
								fmt.Sprintf("change it first: `komando host edit %s --via OTHER` (or --unset via), or remove both together", o.Name),
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
				for _, n := range names {
					delete(s.Hosts, n)
				}
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "host.rm", names, "", true, nil)
			out.P.Print("host.rm", rmResult{Removed: names}, nil)
			return nil
		},
	}
}

// --- import / export -------------------------------------------------------

func readFileOrStdin(p string) ([]byte, error) {
	if p == "-" {
		return readAllStdin()
	}
	return readLocalFile(p)
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
				return localFileErr("FILE_NOT_FOUND", err, "")
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
					if len(matches) == 0 {
						notes = append(notes, "Include "+inc+": no such file")
					}
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
				if !strings.HasPrefix(pat, "!") {
					notes = append(notes, "Host "+pat+": a pattern, not one server; its settings were used as defaults for the servers it matches")
				}
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
				notes = append(notes, fmt.Sprintf("Host %s: not a name komando can use (letters, digits, . _ -)", pat))
				continue
			}
			// HostName may use %h (the name typed) and %% (a literal %)
			hostname := strings.NewReplacer("%h", pat, "%%", "%").Replace(opts["hostname"])
			h := &store.Host{Name: name, Address: hostname, User: opts["user"], Via: opts["proxyjump"]}
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
		Long: `Fetches the server's host key and stores it in komando's known_hosts, like
ssh-keyscan plus ssh-keygen -R. The key is fetched the way komando reaches
the server: directly, or through its --via servers, VPN or proxy command.

A key that is already pinned is left as it is. If a different key is
pinned, the server may be an impostor (HOSTKEY_MISMATCH): check the new
fingerprint another way, then replace the pin with --reset. Replacing a pin
needs --yes (an AI agent also needs a person's yes on the screen). With
--dry-run nothing is fetched or changed; it only counts the pinned entries
--reset would replace.`,
		Example: `  komando host trust web1
  komando host trust web1 --reset --dry-run   # how many pinned keys would go
  komando host trust web1 --reset --yes       # after a real rebuild`,
		Args: cobra.ExactArgs(1),
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
			replacing := func(what string) error {
				if err := guardSafety("replacing the pinned host key of " + h.Name + " (" + what + ")"); err != nil {
					return err
				}
				if protectedHost(st, h) {
					return guardProtection("host", "replacing the pinned host key of", []string{h.Name})
				}
				return nil
			}
			if g.dryRun {
				res := map[string]any{"host": h.Name, "address": addr, "would_fetch_from": keyFetchPath(st, h)}
				if reset {
					n := countPinned(addr)
					res["would_remove_entries"] = n
					if n > 0 {
						if err := replacing("a key may be replaced"); err != nil {
							return err
						}
					}
				}
				out.P.Print("host.trust", res, nil)
				return nil
			}
			key, err := sshx.FetchHostKey(cmd.Context(), st, h, sshOpts(st))
			if err != nil {
				if oe, ok := err.(*out.Error); ok && oe.Code != "CONNECT_FAILED" {
					return oe // a jump host's key or login, a timeout, a VPN: its own words
				}
				return out.Errf(out.ExitConnect, "KEYSCAN_FAILED", "check the address and port with `komando host show "+h.Name+"`", "cannot fetch host key from %s: %v", addr, err)
			}
			fp := ssh.FingerprintSHA256(key)
			pins, err := sshx.PinnedKeys(addr)
			if err != nil {
				return err
			}
			same, other := false, []string{}
			for _, k := range pins {
				if sshx.SameKey(k, key) {
					same = true
				} else {
					other = append(other, ssh.FingerprintSHA256(k))
				}
			}
			switch {
			case len(other) > 0 && !same && !reset:
				// never pin a second key next to the old one: both would be accepted
				e := sshx.HostKeyMismatch(h.Name)
				e.Message += fmt.Sprintf("; pinned %s, the server now shows %s", strings.Join(other, ", "), fp)
				return e
			case len(other) > 0 && !same:
				if err := replacing("old " + strings.Join(other, ", ") + ", new " + fp); err != nil {
					return err
				}
			}
			removed, err := sshx.PinHostKey(addr, key, reset)
			if err != nil {
				return err
			}
			res := map[string]any{"host": h.Name, "address": addr, "removed_entries": removed, "key_type": key.Type(), "fingerprint": fp}
			if same && removed == 0 {
				res["already_pinned"] = true
			}
			audit(st, "host.trust", []string{h.Name}, "", true, map[string]any{"reset": reset, "removed_entries": removed, "fingerprint": fp})
			out.P.Print("host.trust", res, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&reset, "reset", false, "replace the previously pinned key (needs --yes)")
	return c
}

// countPinned counts the known_hosts lines for addr, as PinHostKey would
// replace them, without changing the file.
func countPinned(addr string) int {
	b, err := os.ReadFile(sshx.KnownHostsPath())
	if err != nil {
		return 0
	}
	norm := knownhosts.Normalize(addr)
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && slices.Contains(strings.Split(f[0], ","), norm) {
			n++
		}
	}
	return n
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

// keyFetchPath says how `host trust` reaches h for its key: the way komando
// reaches it (directly, through a VPN, a proxy command or jump hosts).
func keyFetchPath(st *store.State, h *store.Host) string {
	vpn, hops, err := sshx.Route(st, h)
	if err != nil || len(hops) == 0 {
		return "through --via " + h.Via
	}
	var parts []string
	if vpn != nil {
		parts = append(parts, "VPN "+vpn.Name)
	}
	if len(hops) == 1 && h.ProxyCommand != "" {
		parts = append(parts, "its proxy command")
	}
	if len(hops) > 1 {
		var names []string
		for _, j := range hops[:len(hops)-1] {
			names = append(names, j.Name)
		}
		if hops[0].ProxyCommand != "" {
			names[0] += " (by its proxy command)"
		}
		parts = append(parts, "jump host "+strings.Join(names, ", "))
	}
	if len(parts) == 0 {
		return "the server directly"
	}
	return "through " + strings.Join(parts, ", then ")
}
