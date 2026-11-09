package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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
	fl.StringVar(&f.key, "key", "", "name of a key in komando's key list (see komando key list)")
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
	c := &cobra.Command{Use: "host", Aliases: []string{"hosts"}, Short: "Manage servers: add, edit, rename, import, test, trust"}
	c.AddCommand(hostAddCmd(), hostEditCmd(), hostMvCmd(), alias(listCmdFor("host"), "list kind:host"), hostShowCmd(), hostRmCmd(), hostImportCmd(), hostExportCmd(), alias(testCmdFor("host"), "test"), hostTrustCmd(), hostSSHArgsCmd())
	return c
}

func hostAddCmd() *cobra.Command {
	var f hostFlags
	var force, askPw bool
	c := &cobra.Command{
		Use:   "add NAME [user@address[:port]]",
		Short: "Add a server to the list",
		Example: `  komando host add web1 deploy@10.0.0.11 --group web --tag prod --key deploy
  komando host add db1 --address db.internal --user root --via bastion --protected
  komando host add vps1 root@203.0.113.20 --ask-password   # type its password now (hidden)`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHostAdd(cmd, args, &f, force, askPw)
		},
	}
	f.bind(c, false)
	askPasswordFlag(c, &askPw)
	c.Flags().BoolVar(&force, "overwrite", false, "replace an existing host with the same name")
	aliasFlag(c.Flags(), "force", "overwrite")
	return c
}

// runHostAdd is the work of `hostAddCmd`.
func runHostAdd(cmd *cobra.Command, args []string, f *hostFlags, force, askPw bool) error {
	name := args[0]
	if err := validName("host", name); err != nil {
		return err
	}
	if err := guardProxyCommand(f.proxyCommand); err != nil {
		return err
	}
	undoPw := func() {}
	if askPw {
		ref, undo, err := askPassword(cmd, "host", name)
		if err != nil {
			return err
		}
		f.passwordRef, undoPw = ref, undo
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
		if err := guardHostSends([]*store.Host{h}, s.Hosts); err != nil {
			return err // s.Hosts holds the server it replaces, if any
		}
		if twin := protectedTwinHost(s, h); twin != "" && !h.Protected {
			h.Protected = true
			res.Warnings = append(res.Warnings, sameTwinWarning("server", name, twin))
		}
		s.Hosts[name] = h
		return nil
	})
	if err != nil {
		undoPw()
		return err
	}
	res.Action = addVerb(replaced)
	res.Warnings = append(res.Warnings, missingSecretWarnings(h.PasswordRef, h.SudoRef)...)
	res.Next = "komando test " + name
	audit(nil, "host.add", []string{name}, "", true, map[string]any{"action": res.Action})
	out.P.Print("host.add", res, nil)
	return nil
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
	var askPw bool
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
  komando host edit web1 web2 web3 --user deploy
  komando host edit vps1 --ask-password          # type a new password (hidden)`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHostEdit(cmd, args, &f, rename, askPw)
		},
	}
	f.bind(c, true)
	askPasswordFlag(c, &askPw)
	c.Flags().StringVar(&rename, "rename", "", "rename the host")
	_ = c.Flags().MarkDeprecated("rename", "use `komando host mv OLD NEW`")
	return c
}

// runHostEdit is the work of `hostEditCmd`.
func runHostEdit(cmd *cobra.Command, args []string, f *hostFlags, rename string, askPw bool) error {
	fl := cmd.Flags()
	undoPw, err := hostEditChecks(cmd, args, f, askPw)
	if err != nil {
		return err
	}
	var res hostResult
	var many hostEditResult
	single := false
	err = store.Update(func(s *store.State) error {
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
		olds := map[string]*store.Host{} // the connection settings before the edit
		for _, h := range hosts {
			before, _ := json.Marshal(h)
			conn := *h
			olds[h.Name] = &conn
			if err := applyHostEdit(h, f, fl); err != nil {
				return editErr(err, h.Name, single)
			}
			if h.Key != "" {
				if _, ok := s.Keys[h.Key]; !ok {
					return keyNotFound(s, h.Key)
				}
			}
			edits = append(edits, edit{h, before})
		}
		if err := guardHostEdit(hosts, olds, single); err != nil {
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
		undoPw()
		return err
	}
	return printHostEdit(cmd, args, single, res, many)
}

// hostEditChecks are host edit's checks before it changes anything, and
// --ask-password; undo takes back a secret it stored when the edit fails.
func hostEditChecks(cmd *cobra.Command, args []string, f *hostFlags, askPw bool) (undo func(), err error) {
	fl := cmd.Flags()
	undo = func() {}
	if len(changedFlags(cmd)) == 0 {
		return undo, out.Errf(out.ExitUsage, "USAGE", "pass what to change, e.g. komando host edit "+args[0]+" --user deploy (see --help)", "nothing to change")
	}
	if err := editConflicts(fl, f.unset, map[string]string{"user": "user", "key": "key", "identity": "identity", "password-ref": "password-ref",
		"sudo-ref": "sudo-ref", "via": "via", "jump": "via", "proxy-command": "proxy-command", "notes": "notes", "port": "port", "protected": "protected"},
		[][2][]string{{f.addGroups, f.rmGroups}, {f.addTags, f.rmTags}}); err != nil {
		return undo, err
	}
	if err := guardProxyCommand(f.proxyCommand); err != nil {
		return undo, err
	}
	if !askPw {
		return undo, nil
	}
	if len(args) != 1 {
		return undo, out.Usage("--ask-password gives one server its password: name one server")
	}
	ref, undo, err := askPassword(cmd, "host", args[0])
	if err != nil {
		return undo, err
	}
	_ = fl.Set("password-ref", ref)
	return undo, nil
}

// printHostEdit prints what host edit changed: one server, or many.
func printHostEdit(cmd *cobra.Command, args []string, single bool, res hostResult, many hostEditResult) error {
	fl := cmd.Flags()
	if single {
		if fl.Changed("password-ref") || fl.Changed("sudo-ref") {
			res.Warnings = append(res.Warnings, missingSecretWarnings(res.PasswordRef, res.SudoRef)...)
		}
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
// For an AI agent the same window also asks about the secrets the edit
// sends to a new place (guardHostSends). olds holds each server's settings
// before the edit.
func guardHostEdit(hosts []*store.Host, olds map[string]*store.Host, single bool) error {
	var names, off, login []string
	for _, h := range hosts {
		o := olds[h.Name]
		if o.Protected && !h.Protected {
			off = append(off, h.Name)
		}
		if o.Protected && hostConnChanged(o, h) {
			login = append(login, h.Name)
		}
		if slices.Contains(off, h.Name) || slices.Contains(login, h.Name) {
			names = append(names, h.Name)
		}
	}
	action := "changing where or how komando logs in to"
	switch {
	case len(login) == 0:
		action = "turning off protection of"
	case len(off) > 0:
		action = "turning off protection of, or changing the login of,"
	}
	why := fmt.Sprintf("%s protected %s: %s", action, nouns(len(names), "host"), strings.Join(names, ", "))
	if !single {
		all := hostNames(hosts)
		why = fmt.Sprintf("this edit changes %d servers: %s (protected: %s)", len(all), strings.Join(all, ", "), strings.Join(names, ", "))
	}
	if len(names) == 0 {
		return guardHostSends(hosts, olds)
	}
	if err := guardHostSends(hosts, olds, why); err != nil {
		return err
	}
	if single {
		return guardProtection("host", action, names)
	}
	return guardProtectionWhy("host", action, names, why)
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
		return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "a proxy command only carries the connection, e.g. `aws ssm start-session ...`; if this one is intended, --allow-dangerous lets it through",
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

// keptHostKeys lists the removed servers (name -> address) whose key is
// still pinned and whose address no server left in the inventory uses.
// host rm never removes a pin by itself: rm plus add would then get past a
// HOSTKEY_MISMATCH without a person's yes.
func keptHostKeys(s *store.State, gone map[string]string) []string {
	used := map[string]bool{}
	for _, h := range s.Hosts {
		used[trustAddr(h)] = true
	}
	var kept []string
	for n, addr := range gone {
		if !used[addr] && countPinned(addr) > 0 {
			kept = append(kept, n)
		}
	}
	sort.Strings(kept)
	return kept
}

func hostRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm NAME|TARGET...",
		Short: "Remove servers from the inventory (the servers are not touched)",
		Example: `  komando host rm web3
  komando host rm @old --dry-run     # what a selector would remove
  komando host rm 'tmp-*'`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var names, kept, unused []string
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
				gone := map[string]string{} // name -> address
				var refs []string
				for _, n := range names {
					h := s.Hosts[n]
					gone[n] = trustAddr(h)
					refs = append(refs, h.PasswordRef, h.SudoRef)
					for _, v := range h.Env {
						refs = append(refs, v)
					}
					delete(s.Hosts, n)
				}
				kept = keptHostKeys(s, gone)
				unused = unusedSecrets(s, refs)
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "host.rm", names, "", true, nil)
			res := rmResult{Removed: names, HostKeysKept: kept, SecretsUnused: unused}
			if len(kept) > 0 {
				res.Note = "the pinned host keys of " + strings.Join(kept, ", ") + " stay in komando's known_hosts, so a server added again at the same address must show the same key. " +
					"If it was rebuilt, add it again and replace the pin with `komando host trust NAME --reset` (a person confirms the new key)"
			}
			out.P.Print("host.rm", res, nil)
			return nil
		},
	}
}
