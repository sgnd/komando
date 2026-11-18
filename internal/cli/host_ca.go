package cli

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Host certificate authorities (C38b): a CA a person trusts vouches for
// the host keys of the servers its patterns match.

// hostCARow is one CA as people and the apps see it.
type hostCARow struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	Hosts       []string  `json:"hosts"`
	AddedAt     time.Time `json:"added_at"`
	AddedBy     string    `json:"added_by,omitempty"`
	WouldMatch  []string  `json:"would_match,omitempty"` // add --dry-run: the servers it matches now
}

func caRow(c sshx.HostCA) hostCARow {
	r := hostCARow{Name: c.Name, Hosts: c.Hosts, AddedAt: c.AddedAt, AddedBy: c.AddedBy}
	if k := c.PublicKey(); k != nil {
		r.Type, r.Fingerprint = k.Type(), ssh.FingerprintSHA256(k)
	}
	return r
}

func hostCACmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "ca",
		Short: "Trust servers through the CA that signs their host keys",
		Long: `A host CA vouches for the host keys of the servers its patterns match, as an
@cert-authority line in known_hosts does. A server that shows a host
certificate from a trusted CA, for the name komando dials, is trusted
without a pin. Adding a CA trusts every server it ever signs, so only a
person at a terminal can add one. Removing one, and putting a key on the
never-trust list, anyone may do.`,
	}
	c.AddCommand(hostCAListCmd(), hostCAAddCmd(), hostCARmCmd(), hostCARevokeCmd())
	return c
}

func hostCAListCmd() *cobra.Command {
	var limit int
	c := &cobra.Command{
		Use:     "list",
		Short:   "List the trusted server CAs",
		Example: `  komando host ca list`,
		Args:    cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			cas, err := sshx.HostCAs(cmd.Context())
			if err != nil {
				return err
			}
			rows := []hostCARow{}
			for _, c := range cas {
				if limit > 0 && len(rows) == limit {
					break
				}
				rows = append(rows, caRow(c))
			}
			cl.out.Print("host.ca.list", map[string]any{"items": rows}, nil)
			return nil
		}),
	}
	c.Flags().IntVarP(&limit, "limit", "n", 0, "the first N CAs (0 = all)")
	return c
}

// caLine is one @cert-authority or @revoked line of a known_hosts file.
type caLine struct {
	revoked bool
	hosts   []string
	key     ssh.PublicKey
}

// parseKnownHostsCAs reads the @cert-authority and @revoked lines of b.
func parseKnownHostsCAs(b []byte) ([]caLine, error) {
	var out []caLine
	for n, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		marker, rest, _ := strings.Cut(line, " ")
		if marker != "@cert-authority" && marker != "@revoked" {
			continue
		}
		pats, keyPart, _ := strings.Cut(strings.TrimSpace(rest), " ")
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyPart))
		if err != nil {
			return nil, out1Errf("line %d: the key does not parse: %v", n+1, err)
		}
		ln := caLine{revoked: marker == "@revoked", key: k}
		if !ln.revoked {
			ln.hosts = strings.Split(pats, ",")
		}
		out = append(out, ln)
	}
	if len(out) == 0 {
		return nil, out1Errf("the file has no @cert-authority or @revoked line")
	}
	return out, nil
}

func out1Errf(format string, a ...any) error {
	return out.Errf(out.ExitUsage, "USAGE", "give a known_hosts file with @cert-authority lines, or --key and --hosts", format, a...)
}

// caPatterns checks and normalises host patterns.
func caPatterns(raw []string) ([]string, error) {
	var pats []string
	for _, p := range raw {
		if strings.HasPrefix(p, "!") {
			return nil, out.Errf(out.ExitUsage, "USAGE", "list only the domains the CA may vouch for", "negated pattern %q: komando takes only positive name patterns", p)
		}
		n, err := sshx.CheckCAPattern(p)
		if err != nil {
			return nil, out.Errf(out.ExitUsage, "CA_HOSTS_INVALID", "name the domains the CA may vouch for, at least two fixed labels: --hosts '*.corp.example' or '10.1.2.*'", "%v", err)
		}
		pats = append(pats, n)
	}
	if len(pats) == 0 {
		return nil, out.Errf(out.ExitUsage, "CA_HOSTS_INVALID", "add --hosts '*.corp.example' (the domains the CA may vouch for)", "a server CA needs the server names it may vouch for")
	}
	sort.Strings(pats)
	return pats, nil
}

// caMatches are the servers in the inventory that the patterns match now.
func caMatches(st *store.State, c sshx.HostCA) []string {
	var names []string
	for _, h := range st.Hosts {
		if c.Matches(h.Address) {
			names = append(names, h.Name)
		}
	}
	sort.Strings(names)
	return names
}

func hostCAAddCmd() *cobra.Command {
	var keyFile, from string
	var hosts []string
	c := &cobra.Command{
		Use:   "add NAME",
		Short: "Trust a CA for the servers its patterns match",
		Long: `Trusts the CA in --key (a .pub file) for the host names in --hosts, or reads
the @cert-authority lines of a known_hosts file (--from); its @revoked lines
go on the never-trust list. A pattern names at least the domain
(*.corp.example, web*.corp.example, 10.1.2.*): '*' and '*.com' are refused.
--dry-run shows the patterns as they are kept and the servers they match
now. Only a person at a terminal can add a CA: it trusts every server it
ever signs.`,
		Example: `  komando host ca add corp --key ~/corp-ca.pub --hosts '*.corp.example' --dry-run
  komando host ca add corp --from ~/.ssh/known_hosts`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := validName("server CA", name); err != nil {
				return err
			}
			if (keyFile == "") == (from == "") {
				return out.Errf(out.ExitUsage, "USAGE", "give --key FILE.pub with --hosts, or --from KNOWN_HOSTS", "`komando host ca add` takes a CA key or a known_hosts file, one of them")
			}
			var lines []caLine
			if from != "" {
				if len(hosts) > 0 {
					return out.Errf(out.ExitUsage, "USAGE", "the patterns of --from come from its lines; drop --hosts", "--hosts and --from do not go together")
				}
				b, err := readLocalFile(cl, from)
				if err != nil {
					return err
				}
				if lines, err = parseKnownHostsCAs(b); err != nil {
					return err
				}
			} else {
				b, err := readLocalFile(cl, keyFile)
				if err != nil {
					return err
				}
				k, _, _, _, err := ssh.ParseAuthorizedKey(b)
				if err != nil {
					return out.Errf(out.ExitUsage, "KEY_INVALID", "give the CA's public key file (.pub)", "%s is not a public key: %v", keyFile, err)
				}
				lines = []caLine{{key: k, hosts: hosts}}
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			var cas []sshx.HostCA
			var revoke []ssh.PublicKey
			for _, l := range lines {
				if l.revoked {
					revoke = append(revoke, l.key)
					continue
				}
				pats, err := caPatterns(l.hosts)
				if err != nil {
					return err
				}
				n := name
				if len(cas) > 0 {
					n = name + "-" + strconv.Itoa(len(cas)+1)
				}
				cas = append(cas, sshx.HostCA{Name: n, Key: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(l.key))), Hosts: pats, AddedAt: time.Now().UTC(), AddedBy: actor(cl)})
			}
			rows := []hostCARow{}
			for _, c := range cas {
				r := caRow(c)
				r.WouldMatch = caMatches(st, c)
				rows = append(rows, r)
			}
			res := map[string]any{"items": rows, "revoked": len(revoke)}
			if cl.flags.dryRun {
				res["action"] = "would_add"
				cl.out.Print("host.ca.add", res, nil)
				return nil
			}
			if cl.isAgent() || !cl.interactive() {
				return out.Errf(out.ExitPolicy, "NEEDS_PERSON", "a person runs `komando host ca add` in their own terminal, after checking the CA's fingerprint",
					"adding a server CA trusts every server it signs, so only a person at a terminal can do it").NoFlag()
			}
			if err := sshx.RevokeHostKeys(revoke); err != nil {
				return err
			}
			for i, c := range cas {
				if err := sshx.AddHostCA(cmd.Context(), c); err != nil {
					if errors.Is(err, sshx.ErrHostCAExists) {
						return out.Errf(out.ExitConflict, "CA_EXISTS", "choose another name, or `komando host ca rm "+c.Name+"` first", "server CA %q already exists", c.Name)
					}
					return err
				}
				rows[i].WouldMatch = nil
				audit(cl, st, "host.ca.add", nil, "", true, map[string]any{"ca": c.Name, "fingerprint": rows[i].Fingerprint, "hosts": c.Hosts})
			}
			res["action"] = "added"
			cl.out.Print("host.ca.add", res, nil)
			return nil
		}),
	}
	c.Flags().StringVar(&keyFile, "key", "", "the CA's public key file (.pub)")
	c.Flags().StringSliceVar(&hosts, "hosts", nil, "server name patterns the CA may vouch for (*.corp.example,10.1.2.*)")
	c.Flags().StringVar(&from, "from", "", "a known_hosts file: read its @cert-authority and @revoked lines")
	return c
}

func hostCARmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm NAME",
		Short:   "Stop trusting a server CA",
		Long:    `Stops trusting the CA: its servers are checked against their pins again.`,
		Example: `  komando host ca rm corp`,
		Args:    cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			cas, err := sshx.HostCAs(cmd.Context())
			if err != nil {
				return err
			}
			var found *sshx.HostCA
			for i := range cas {
				if cas[i].Name == args[0] {
					found = &cas[i]
				}
			}
			if found == nil {
				return out.Errf(out.ExitNotFound, "CA_NOT_FOUND", "see the CAs with `komando host ca list`", "no server CA named %q", args[0])
			}
			res := map[string]any{"name": found.Name, "action": "would_remove"}
			if !cl.flags.dryRun {
				if err := sshx.RemoveHostCA(cmd.Context(), found.Name); err != nil {
					return err
				}
				res["action"] = "removed"
				audit(cl, nil, "host.ca.rm", nil, "", true, map[string]any{"ca": found.Name, "fingerprint": caRow(*found).Fingerprint})
			}
			cl.out.Print("host.ca.rm", res, nil)
			return nil
		}),
	}
}

func hostCARevokeCmd() *cobra.Command {
	var keyFile string
	c := &cobra.Command{
		Use:   "revoke --key FILE.pub",
		Short: "Never trust a host key or a CA key again",
		Long: `Puts the key in FILE.pub on the never-trust list (an @revoked line): no
server is reached with it as its host key, no certificate it signed or holds
is trusted, and it cannot be pinned or added as a CA.`,
		Example: `  komando host ca revoke --key old-ca.pub`,
		Args:    cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if keyFile == "" {
				return out.Errf(out.ExitUsage, "USAGE", "add --key FILE.pub", "`komando host ca revoke` needs the key to revoke")
			}
			b, err := readLocalFile(cl, keyFile)
			if err != nil {
				return err
			}
			k, _, _, _, err := ssh.ParseAuthorizedKey(b)
			if err != nil {
				return out.Errf(out.ExitUsage, "KEY_INVALID", "give a public key file (.pub)", "%s is not a public key: %v", keyFile, err)
			}
			res := map[string]any{"fingerprint": ssh.FingerprintSHA256(k), "action": "would_revoke"}
			if !cl.flags.dryRun {
				if err := sshx.RevokeHostKeys([]ssh.PublicKey{k}); err != nil {
					return err
				}
				res["action"] = "revoked"
				audit(cl, nil, "host.ca.revoke", nil, "", true, map[string]any{"fingerprint": res["fingerprint"]})
			}
			cl.out.Print("host.ca.revoke", res, nil)
			return nil
		}),
	}
	c.Flags().StringVar(&keyFile, "key", "", "the public key file (.pub) never to trust")
	return c
}

// hostCAChecks are doctor's lines about the trusted host CAs.
func hostCAChecks(cl *call, st *store.State, add func(name string, ok, warn bool, detail string)) {
	cas, err := sshx.HostCAs(context.Background())
	if err != nil || len(cas) == 0 {
		return
	}
	for _, c := range cas {
		r := caRow(c)
		var prot []string
		for _, n := range caMatches(st, c) {
			if protectedHost(st, st.Hosts[n]) {
				prot = append(prot, n)
			}
		}
		k := c.PublicKey()
		rev, _ := sshx.HostKeyRevoked(k)
		switch {
		case k == nil || rev:
			add("host_ca:"+c.Name, false, true, "server CA "+c.Name+" is revoked or unreadable and trusts nothing: `komando host ca rm "+c.Name+"`")
		case len(prot) > 0:
			add("host_ca:"+c.Name, false, true, "server CA "+c.Name+" ("+r.Fingerprint+") vouches for protected servers "+strings.Join(prot, ", ")+": one key decides who they are. Keep it only if that CA is guarded as well as those servers")
		case time.Since(c.AddedAt) > 2*365*24*time.Hour:
			add("host_ca:"+c.Name, false, true, "server CA "+c.Name+" was added more than 2 years ago: check it is still the CA in use, and rotate it with the servers' owners")
		default:
			add("host_ca:"+c.Name, true, false, "server CA "+c.Name+" ("+r.Fingerprint+") vouches for "+strings.Join(c.Hosts, ", "))
		}
	}
}
