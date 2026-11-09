package cli

import (
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// `host ssh-command` prints the OpenSSH command that reaches a host the way
// komando does. A --via path becomes nested ProxyCommands rather than -J:
// ssh -J does not pass -i or UserKnownHostsFile on to the jump hosts, so
// the printed command would fail there.

func hostSSHArgsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh-command NAME",
		Short: "Print the equivalent OpenSSH command line for a host",
		Long: `Prints the ssh command that reaches the host with the same address, user, key,
known_hosts file and --via path komando uses. Hosts behind --via servers get
a ProxyCommand per hop (ssh -W), so every hop uses its own key. A SOCKS VPN
becomes nc -X 5; VPNs that run inside komando cannot be used by OpenSSH:
use ` + "`komando shell NAME`" + ` for those.`,
		Example: `  komando host ssh-command web1
  $(komando host ssh-command web1 -o text)      # open a shell with OpenSSH`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			h, err := singleHost(st, args[0])
			if err != nil {
				return err
			} else if h.WinRM() {
				return notOnWindows("an ssh command for a WinRM server", []string{h.Name})
			}
			parts, err := sshCommandFor(st, h)
			if err != nil {
				return err
			}
			out.P.Print("host.ssh-command", sshCmdResult{Argv: parts, Command: shellLine(parts)}, nil)
			return nil
		},
	}
}

type sshCmdResult struct {
	Argv    []string `json:"argv"`
	Command string   `json:"command"`
}

func (r sshCmdResult) Text() string { return r.Command }

// shellLine joins argv for a shell, quoting what needs it.
func shellLine(parts []string) string {
	line := make([]string, len(parts))
	for i, p := range parts {
		line[i] = p
		if p == "" || strings.ContainsAny(p, " '\"$\\|&;<>()*?[]{}!`~#") {
			line[i] = sshx.Q(p)
		}
	}
	return strings.Join(line, " ")
}

// sshPath is the VPN (or nil) and the hops [via..., h] to reach h, the way
// sshx.Dial resolves them: each step's own --via comes first.
func sshPath(st *store.State, h *store.Host, seen map[string]bool) (*store.Vpn, []*store.Host, error) {
	if seen[h.Name] {
		return nil, nil, out.Errf(out.ExitError, "VIA_CYCLE", "fix the --via setting with `komando host edit "+h.Name+" --via ...`", "--via loop at %q", h.Name)
	}
	seen[h.Name] = true
	var vpn *store.Vpn
	var hops []*store.Host
	for _, step := range viaChain(h.Via) {
		if v, ok := st.Vpns[step]; ok {
			if vpn != nil || len(hops) > 0 {
				return nil, nil, out.Errf(out.ExitUsage, "VIA_ORDER", "put the VPN first in --via", "%s: a VPN can only be the first step of a --via path", h.Name)
			}
			vpn = v
			continue
		}
		jh, ok := st.Hosts[step]
		if !ok {
			a, err := sshx.ParseAdhoc(step)
			if err != nil || !strings.Contains(step, "@") {
				return nil, nil, out.Errf(out.ExitNotFound, "VIA_NOT_FOUND", "fix it with `komando host edit "+h.Name+" --via ...`", "%s: no server or VPN named %q", h.Name, step)
			}
			jh = a
		}
		sv, sub, err := sshPath(st, jh, seen)
		if err != nil {
			return nil, nil, err
		}
		if sv != nil {
			if vpn != nil || len(hops) > 0 {
				return nil, nil, out.Errf(out.ExitUsage, "VIA_ORDER", "a path can use one VPN, as its first step", "%s: the --via path reaches VPN %s after another step", h.Name, sv.Name)
			}
			vpn = sv
		}
		hops = append(hops, sub...)
	}
	return vpn, append(hops, h), nil
}

// hopOptions are the ssh options to log in to one hop.
func hopOptions(st *store.State, h *store.Host) []string {
	o := []string{"-o", "UserKnownHostsFile=" + sshx.KnownHostsPath()}
	if h.EffectivePort() != 22 {
		o = append(o, "-p", strconv.Itoa(h.EffectivePort()))
	}
	if h.Identity != "" {
		o = append(o, "-i", expandHome(h.Identity))
	} else if k, ok := st.Keys[h.Key]; ok {
		o = append(o, "-i", k.Path)
	}
	return o
}

func hopDest(st *store.State, h *store.Host) string {
	user := h.User
	if user == "" {
		user = st.Settings.DefaultUser
	}
	if user != "" {
		return user + "@" + h.Address
	}
	return h.Address
}

// escapePct protects a ProxyCommand from one round of ssh's % expansion
// when it is nested inside another ProxyCommand.
func escapePct(s string) string { return strings.ReplaceAll(s, "%", "%%") }

// vpnProxy is the ProxyCommand that goes through a VPN, or "" when the
// computer itself routes it (a system VPN).
func vpnProxy(st *store.State, v *store.Vpn) (string, error) {
	socks := ""
	switch {
	case v.Kind == "system":
		return "", nil
	case v.Kind == "proxy" && v.User == "" && v.KeyRef == "" && strings.HasPrefix(v.Address, "http://"):
		return "nc -X connect -x " + strings.TrimPrefix(v.Address, "http://") + " %h %p", nil
	case v.Kind == "socks" && v.User == "" && v.KeyRef == "":
		socks = v.Address
	default:
		if s := st.Sessions[v.Name]; s != nil && s.Socks != "" && s.SocksUser == "" {
			socks = s.Socks // a VPN kept up with `komando vpn up`
		}
	}
	if socks == "" {
		return "", out.Errf(out.ExitUsage, "VPN_NOT_FOR_OPENSSH",
			"use `komando shell HOST` (it opens the VPN itself), or connect the VPN on this computer and leave it out of --via",
			"VPN %s (%s) runs inside komando; OpenSSH cannot use it", v.Name, v.Kind)
	}
	return "nc -X 5 -x " + socks + " %h %p", nil
}

// sshCommandFor builds the ssh argv for h.
func sshCommandFor(st *store.State, h *store.Host) ([]string, error) {
	vpn, hops, err := sshPath(st, h, map[string]bool{})
	if err != nil {
		return nil, err
	}
	// proxy carries the connection to the current hop: a shell command for
	// ssh's ProxyCommand, with %h %p meaning that hop
	proxy := hops[0].ProxyCommand
	if vpn != nil {
		if proxy != "" {
			return nil, out.Errf(out.ExitUsage, "PROXY_NOT_FIRST", "a path starts with a VPN or a proxy command, not both", "%s has a proxy command but is reached through VPN %s", hops[0].Name, vpn.Name)
		}
		if proxy, err = vpnProxy(st, vpn); err != nil {
			return nil, err
		}
	}
	for i := 1; i < len(hops); i++ {
		if hops[i].ProxyCommand != "" {
			return nil, out.Errf(out.ExitUsage, "PROXY_NOT_FIRST", "a proxy command can only start a path; put that host first in --via",
				"%s has a proxy command but is reached through another hop", hops[i].Name)
		}
		prev := hops[i-1]
		p := append([]string{"ssh"}, hopOptions(st, prev)...)
		if proxy != "" {
			p = append(p, "-o", "ProxyCommand="+escapePct(proxy))
		}
		p = append(p, "-W", net.JoinHostPort(hops[i].Address, strconv.Itoa(hops[i].EffectivePort())), hopDest(st, prev))
		proxy = shellLine(p)
	}
	parts := append([]string{"ssh"}, hopOptions(st, h)...)
	if proxy != "" {
		parts = append(parts, "-o", "ProxyCommand="+proxy) // ssh fills in %h %p itself
	}
	return append(parts, hopDest(st, h)), nil
}
