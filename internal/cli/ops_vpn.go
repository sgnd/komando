package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// vpnDialCheck is how long `vpn status` waits for an address to answer.
const vpnDialCheck = 1500 * time.Millisecond

// vpnReachable reports, for the kinds komando does not run itself (socks
// and system), whether the VPN answers right now, and how that was seen.
func vpnReachable(v *store.Vpn) (up bool, detail string) {
	addr, what := "", ""
	switch v.Kind {
	case "socks":
		addr, what = v.Address, "SOCKS proxy "+v.Address
	case "proxy":
		if u, err := netx.ProxyURL(v.Address); err == nil {
			addr = u.Host
			if u.Port() == "" {
				addr += map[bool]string{true: ":443", false: ":80"}[u.Scheme == "https"]
			}
		}
		what = "HTTP proxy " + v.Address
	case "system":
		if v.Check == "" {
			return false, "no --check address to test"
		}
		addr, what = v.Check, v.Check
	default:
		return false, ""
	}
	c, err := net.DialTimeout("tcp", addr, vpnDialCheck)
	if err != nil {
		return false, what + " does not answer"
	}
	c.Close()
	return true, what + " answers"
}

type vpnStatusData struct {
	Vpns []vpnStatusRow `json:"vpns"`
}

func (d vpnStatusData) Text() string {
	rows := [][]string{}
	for _, r := range d.Vpns {
		up := "no"
		if r.Up {
			up = "yes"
		}
		since := ""
		if !r.Since.IsZero() {
			since = humanAge(time.Since(r.Since))
		}
		rows = append(rows, []string{r.Name, r.Kind, up, since, strings.Join(r.UsedBy, ","), r.Detail})
	}
	return textTable([]string{"name", "kind", "up", "since", "used by", "detail"}, rows)
}

// vpnStatusRows builds the status of every VPN; the address checks run
// at the same time, so the command stays quick.
func vpnStatusRows(st *store.State) []vpnStatusRow {
	vpns := st.SortedVpns()
	rows := make([]vpnStatusRow, len(vpns))
	var wg sync.WaitGroup
	for i, v := range vpns {
		r := vpnStatusRow{Name: v.Name, Kind: v.Kind, MFA: v.MFA, UsedBy: vpnUsers(st, v.Name)}
		if s := st.Sessions[v.Name]; s != nil && netx.SessionAlive(s) {
			r.Up, r.Since, r.LastUsed, r.Socks = true, s.StartedAt, s.LastUsed, s.Socks
			r.Detail = "session running"
		} else if v.Kind == "socks" || v.Kind == "proxy" || v.Kind == "system" {
			wg.Add(1)
			go func(i int, v *store.Vpn) {
				defer wg.Done()
				rows[i].Up, rows[i].Detail = vpnReachable(v)
			}(i, v)
		} else if v.Kind == "wireguard" {
			r.Detail = "connects for each command"
		} else {
			r.Detail = "not connected"
			r.LastEnd, r.LastLog = lastSessionEnd(v.Name, oneOf(v.Kind, "l2tp", "ipsec", "ikev2"))
		}
		rows[i] = r
	}
	wg.Wait()
	return rows
}

// lastSessionEnd is why the VPN's last background session ended or did
// not start, as its log says ("ENDED ..." or "ERROR ..."), cleaned for output.
// With tail, it also returns the log's last lines (only for kinds whose
// logs komando writes itself and keeps free of secrets).
func lastSessionEnd(name string, tail bool) (string, []string) {
	dir, err := vpnDir()
	if err != nil {
		return "", nil
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".log"))
	if err != nil {
		return "", nil
	}
	last := ""
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if i := strings.Index(line, "ENDED "); i >= 0 && (i == 0 || line[i-1] == ' ') {
			last = line[i+len("ENDED "):]
			if i > 0 { // the time it ended
				last = strings.TrimSpace(line[:i]) + ": " + last
			}
		} else if strings.HasPrefix(line, "ERROR ") {
			last = strings.TrimPrefix(line, "ERROR ")
		}
		if len(line) > 300 {
			line = line[:300]
		}
		lines = append(lines, cleanText(line))
	}
	if len(last) > 300 {
		last = last[:300]
	}
	if !tail || last == "" {
		lines = nil
	} else if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	return cleanText(last), lines
}

// refWarnings checks, at add time, that the secret references a VPN uses
// can be read here; the cheap kinds only (external managers may prompt).
func refWarnings(refs ...string) []string {
	var w []string
	for _, ref := range refs {
		if ref == "" || !(strings.HasPrefix(ref, "secret:") || strings.HasPrefix(ref, "env:") || strings.HasPrefix(ref, "file:")) {
			continue
		}
		if _, err := vault.Resolve(ref); err != nil {
			w = append(w, ref+" cannot be read yet ("+err.Error()+"); "+netx.SecretHint(ref))
		}
	}
	return w
}

// socksTunnel finds the `komando tunnel` that serves a SOCKS address.
func socksTunnel(st *store.State, addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	for _, t := range st.Tunnels {
		if t.Kind == "dynamic" && (t.Spec == addr || t.Spec == port || strings.HasSuffix(t.Spec, ":"+port)) {
			return t.ID
		}
	}
	return ""
}

func vpnEditCmd() *cobra.Command {
	var check, address, service, user, passwordRef, notes, server, pskRef, localID, remoteID string
	var groups, tags []string
	var mfa bool
	c := &cobra.Command{
		Use:   "edit NAME",
		Short: "Change a VPN's check address, proxy, login or notes",
		Long: `Changes the common settings of a VPN. To give a WireGuard or OpenVPN VPN a
new config file, add it again with --overwrite.`,
		Example: `  komando vpn edit office --check 10.0.0.5:22
  komando vpn edit lab --address 127.0.0.1:1081
  komando vpn edit client-x --password-ref secret:client-x-new
  komando vpn edit kantor --server vpn2.kantor.id --psk-ref secret:kantor-psk-2`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			changed := false
			for _, n := range []string{"check", "address", "service", "user", "password-ref", "notes", "group", "tag", "mfa", "server", "psk-ref", "id", "remote-id"} {
				changed = changed || f.Changed(n)
			}
			if !changed {
				return out.Usage("nothing to change: give at least one of --check, --address, --service, --server, --user, --password-ref, --psk-ref, --id, --remote-id, --mfa, --notes, --group, --tag")
			}
			if check != "" {
				if _, _, err := net.SplitHostPort(check); err != nil {
					return out.Usage("--check must be host:port")
				}
			}
			if passwordRef != "" && !vault.ValidRef(passwordRef) {
				return out.Usage("invalid --password-ref %q: %s", passwordRef, vault.RefHelp())
			}
			if pskRef != "" && !vault.ValidRef(pskRef) {
				return out.Usage("invalid --psk-ref %q: %s", pskRef, vault.RefHelp())
			}
			var res *store.Vpn
			apply := func(s *store.State) error {
				cur, ok := s.Vpns[args[0]]
				if !ok {
					return out.NotFound("vpn", args[0])
				}
				v := *cur
				only := func(flag string, kinds ...string) error {
					if f.Changed(flag) && !oneOf(v.Kind, kinds...) {
						return out.Usage("--%s is not used by %s VPNs", flag, v.Kind)
					}
					return nil
				}
				for flag, kinds := range map[string][]string{"address": {"socks", "proxy"}, "service": {"system"},
					"server": {"l2tp", "ipsec", "ikev2"}, "psk-ref": {"l2tp", "ipsec", "ikev2"}, "id": {"ipsec", "ikev2"}, "remote-id": {"ikev2"}} {
					if err := only(flag, kinds...); err != nil {
						return err
					}
				}
				if v.Kind == "wireguard" && (f.Changed("password-ref") || f.Changed("user")) {
					return out.Usage("WireGuard keys come from its config: add it again with --config and --overwrite")
				}
				if f.Changed("address") {
					var err error
					if v.Address, err = vpnAddress(v.Kind, address); err != nil {
						return err
					}
				}
				if f.Changed("check") {
					if check == "" && oneOf(v.Kind, "system", "openvpn") {
						return out.Usage("%s VPNs need --check", v.Kind)
					}
					v.Check = check
				}
				if f.Changed("service") {
					v.Service = service
				}
				if f.Changed("server") {
					if server == "" || strings.HasPrefix(server, "-") || strings.Contains(server, "/") {
						return out.Usage("--server must be a host name or address (host or host:port)")
					}
					v.Server = server
				}
				if f.Changed("psk-ref") {
					if pskRef == "" && v.Kind != "ikev2" {
						return out.Usage("%s VPNs need --psk-ref", v.Kind)
					}
					v.PSKRef = pskRef
				}
				if f.Changed("id") {
					v.LocalID = localID
				}
				if f.Changed("remote-id") {
					v.RemoteID = remoteID
				}
				if f.Changed("user") {
					v.User = user
				}
				if f.Changed("password-ref") {
					v.KeyRef = passwordRef
				}
				if f.Changed("mfa") {
					v.MFA = mfa
				}
				if f.Changed("notes") {
					v.Notes = notes
				}
				if f.Changed("group") {
					v.Groups = dedupe(groups)
				}
				if f.Changed("tag") {
					v.Tags = dedupe(tags)
				}
				v.UpdatedAt = time.Now().UTC()
				res = &v
				if !g.dryRun {
					s.Vpns[v.Name] = &v
				}
				return nil
			}
			if g.dryRun {
				st, err := loadState()
				if err != nil {
					return err
				}
				if err := apply(st); err != nil {
					return err
				}
				out.P.Print("vpn.edit", map[string]any{"would_change": res}, nil)
				return nil
			}
			if err := store.Update(apply); err != nil {
				return err
			}
			audit(nil, "vpn.edit", []string{args[0]}, "", true, nil)
			data := map[string]any{"vpn": res}
			if w := refWarnings(res.KeyRef, res.PSKRef); len(w) > 0 {
				data["warnings"] = w
			}
			out.P.Print("vpn.edit", data, nil)
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&check, "check", "", "host:port reachable only through this VPN")
	f.StringVar(&address, "address", "", "socks: host:port of the proxy")
	f.StringVar(&service, "service", "", "system: the VPN's name in your computer's settings")
	f.StringVar(&server, "server", "", "l2tp, ipsec, ikev2: the VPN server")
	f.StringVar(&pskRef, "psk-ref", "", "l2tp, ipsec, ikev2: the pre-shared key (ipsec: the group password)")
	f.StringVar(&localID, "id", "", "ipsec: the group name; ikev2: your identity")
	f.StringVar(&remoteID, "remote-id", "", "ikev2: the server's identity")
	f.StringVar(&user, "user", "", "user name for the VPN login")
	f.StringVar(&passwordRef, "password-ref", "", "password as secret:NAME | env:VAR | file:PATH | op://... | bw://... | kdbx:... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME")
	f.BoolVar(&mfa, "mfa", false, "the login needs a person (MFA, SSO)")
	f.StringVar(&notes, "notes", "", "free-form notes")
	f.StringSliceVarP(&groups, "group", "g", nil, "group(s), replacing the current ones")
	f.StringSliceVarP(&tags, "tag", "t", nil, "tag(s), replacing the current ones")
	return c
}
