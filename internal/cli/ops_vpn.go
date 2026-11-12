package cli

import (
	"fmt"
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
	if len(d.Vpns) == 0 {
		return noneYet("VPNs", "vpn add NAME KIND", "kinds in `komando vpn --help`")
	}
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
		rows = append(rows, []string{r.Name, r.Kind, up, since, usedByText(r.UsedBy), r.Detail})
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
			rows[i] = r // before the check fills it, not after (a lost answer read "no")
			wg.Add(1)
			go func(i int, v *store.Vpn) {
				defer wg.Done()
				rows[i].Up, rows[i].Detail = vpnReachable(v)
			}(i, v)
			continue
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

// vpnEditFlags are vpn edit's flags.
type vpnEditFlags struct {
	check, address, service, user, passwordRef, notes, server, pskRef, localID, remoteID, portal, ca string
	addGroups, rmGroups, addTags, rmTags, labels, unset                                              []string
	mfa, legacyCrypto, allowPAP, protected                                                           bool
}

func (e *vpnEditFlags) bind(c *cobra.Command) {
	f := c.Flags()
	f.StringVar(&e.check, "check", "", "host:port reachable only through this VPN")
	f.StringVar(&e.address, "proxy-address", "", "SOCKS: host:port of the proxy; proxy: host:port or http(s)://host:port")
	withRetiredAddress(c)
	f.StringVar(&e.service, "service", "", "System VPN: its name in your computer's settings")
	f.StringVar(&e.server, "server", "", "L2TP, IPsec, IKEv2: the VPN server")
	f.StringVar(&e.portal, "portal", "", "GlobalProtect, Fortinet, AnyConnect, Pulse, F5: the VPN server or portal")
	f.StringVar(&e.ca, "ca", "", "IKEv2: the CA certificate (PEM) that signed the server's certificate; \"\" for a public one")
	f.StringVar(&e.pskRef, "psk-ref", "", "L2TP, IPsec, IKEv2: the pre-shared key (IPsec: the group password)")
	f.StringVar(&e.localID, "id", "", "IPsec: the group name; IKEv2: your identity")
	f.StringVar(&e.remoteID, "remote-id", "", "IKEv2: the server's identity")
	f.StringVar(&e.user, "user", "", "user name for the VPN login")
	f.StringVar(&e.passwordRef, "password-ref", "", "password as secret:NAME | env:VAR | file:PATH | op://... | bw://... | kdbx:... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME | azure-kv:VAULT/NAME")
	f.BoolVar(&e.mfa, "mfa", false, "the login needs a person (MFA, SSO)")
	f.BoolVar(&e.legacyCrypto, "legacy-crypto", false, "L2TP, IPsec: also offer 3DES and DH groups 2 and 5, for old servers (weak; turning it on needs a person's yes)")
	f.BoolVar(&e.allowPAP, "allow-pap", false, "L2TP: let the server pick PAP, which hands it your password itself (turning it on needs a person's yes)")
	f.StringVar(&e.notes, "notes", "", "free-form notes")
	f.StringSliceVar(&e.addGroups, "add-group", nil, "put it in these groups (comma-separated)")
	f.StringSliceVar(&e.rmGroups, "rm-group", nil, "take it out of these groups")
	f.StringSliceVar(&e.addTags, "add-tag", nil, "add these tags (comma-separated)")
	f.StringSliceVar(&e.rmTags, "rm-tag", nil, "remove these tags")
	shortAlias(f, "group", "g", "add-group")
	shortAlias(f, "tag", "t", "add-tag")

}

// vpnOptIns sets --legacy-crypto and --allow-pap on v (vpn add and edit).
// They weaken the VPN's login, so turning one on needs a person's yes
// (guardSafety); turning it off does not.
func vpnOptIns(v *store.Vpn, changed func(string) bool, legacy, pap bool) error {
	for flag, kinds := range map[string][]string{"legacy-crypto": {"l2tp", "ipsec"}, "allow-pap": {"l2tp"}} {
		if changed(flag) && !oneOf(v.Kind, kinds...) {
			return out.Usage("--%s is not used by %s VPNs", flag, v.Kind)
		}
	}
	if changed("legacy-crypto") {
		if legacy && !v.LegacyCrypto {
			if err := guardSafety("allowing old, weak IKEv1 ciphers (3DES, DH groups 2 and 5) for VPN " + v.Name); err != nil {
				return err
			}
		}
		v.LegacyCrypto = legacy
	}
	if changed("allow-pap") {
		if pap && !v.AllowPAP {
			if err := guardSafety("letting VPN " + v.Name + " log in with PAP, which hands the server your password itself"); err != nil {
				return err
			}
		}
		v.AllowPAP = pap
	}
	return nil
}

// usedByText is a USED BY cell that fits a table: "48 (app-01, app-02, +46)".
func usedByText(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ",")
	}
	return fmt.Sprintf("%d (%s, %s, +%d)", len(names), names[0], names[1], len(names)-2)
}
