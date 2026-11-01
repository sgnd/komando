package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `komando vpn` keeps the networks that targets are reached through. A VPN
// is used by putting its name first in a --via path; komando opens it inside
// its own process for that command only (docs/design/network.md).

func vpnCmd() *cobra.Command {
	var kinds []string
	for k, d := range netx.Kinds {
		kinds = append(kinds, fmt.Sprintf("  %-10s %s", k, d))
	}
	sort.Strings(kinds)
	c := &cobra.Command{
		Use:   "vpn",
		Short: "VPNs to reach servers and databases through (WireGuard, SOCKS, or your computer's own VPN)",
		Long: `Add a VPN once, then use it as the first step of --via:

  komando vpn add office wireguard --config ~/Downloads/office.conf
  komando host add db1 admin@10.0.0.5 --via office
  komando conn add app-db postgres://app@10.0.0.9/app --via office,bastion

WireGuard runs inside komando, only for the commands that need it, so
several VPNs work at the same time and your computer's network never
changes.

Kinds:
` + strings.Join(kinds, "\n"),
	}
	c.AddCommand(vpnAddCmd(), vpnShowCmd(), vpnRmCmd(),
		alias(listCmdFor("vpn"), "list kind:vpn"), alias(testCmdFor("vpn"), "test"))
	return c
}

func vpnAddCmd() *cobra.Command {
	var config, address, user, passwordRef, check, notes string
	var groups, tags []string
	var overwrite bool
	c := &cobra.Command{
		Use:   "add NAME KIND",
		Short: "Add a VPN (wireguard, socks or system)",
		Example: `  komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
  komando vpn add lab socks --address 127.0.0.1:1080
  komando vpn add corp system --check 10.20.0.1:443`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, kind := args[0], strings.ToLower(args[1])
			if err := validName("vpn", name); err != nil {
				return err
			}
			if _, ok := netx.Kinds[kind]; !ok {
				return out.Usage("unknown VPN kind %q (wireguard, socks or system)", kind)
			}
			if check != "" {
				if _, _, err := net.SplitHostPort(check); err != nil {
					return out.Usage("--check must be host:port")
				}
			}
			v := &store.Vpn{Name: name, Kind: kind, Check: check, Groups: dedupe(groups), Tags: dedupe(tags), Notes: notes}
			secrets := map[string]string{}
			switch kind {
			case "wireguard":
				if config == "" {
					return out.Usage("wireguard needs --config FILE (the .conf file your VPN provider gives you)")
				}
				b, err := os.ReadFile(expandHome(config))
				if err != nil {
					return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "give the path of the .conf file", "%v", err)
				}
				clean, priv, psk, err := netx.StripWGKeys(string(b))
				if err != nil {
					return out.Errf(out.ExitUsage, "VPN_CONFIG", "check the file is a WireGuard (wg-quick) config", "%s: %v", config, err)
				}
				v.Config, v.KeyRef = clean, "secret:"+name+"-key"
				secrets[name+"-key"] = priv
				if psk != "" {
					v.PSKRef = "secret:" + name + "-psk"
					secrets[name+"-psk"] = psk
				}
			case "socks":
				if _, _, err := net.SplitHostPort(address); err != nil {
					return out.Usage("socks needs --address host:port of the proxy")
				}
				v.Address, v.User, v.KeyRef = address, user, passwordRef
				if user != "" && passwordRef == "" {
					return out.Usage("--user needs --password-ref secret:NAME (the proxy's password)")
				}
			case "system":
				if check == "" {
					return out.Usage("system needs --check host:port: something that answers only while the VPN is connected")
				}
			}
			if kind != "socks" && (address != "" || user != "") {
				return out.Usage("--address and --user are for socks")
			}
			if kind != "wireguard" && config != "" {
				return out.Usage("--config is for wireguard")
			}
			now := time.Now().UTC()
			v.CreatedAt, v.UpdatedAt = now, now
			if g.dryRun {
				out.P.Print("vpn.add", v, nil)
				return nil
			}
			err := store.Update(func(s *store.State) error {
				return checkNewName(s, "vpn", name, overwrite)
			})
			if err != nil {
				return err
			}
			for n, val := range secrets {
				if err := vault.Set(n, val); err != nil {
					return err
				}
			}
			if err := store.Update(func(s *store.State) error {
				if err := checkNewName(s, "vpn", name, overwrite); err != nil {
					return err
				}
				s.Vpns[name] = v
				return nil
			}); err != nil {
				return err
			}
			audit(nil, "vpn.add", []string{name}, "", true, map[string]any{"kind": kind})
			res := map[string]any{"vpn": v}
			if kind == "wireguard" {
				res["note"] = "the private key is now in the vault (" + v.KeyRef + "); " + config + " still holds it, so delete that file if you no longer need it"
			}
			out.P.Print("vpn.add", res, nil)
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&config, "config", "", "wireguard: the wg-quick .conf file (keys go to the vault)")
	f.StringVar(&address, "address", "", "socks: host:port of the proxy")
	f.StringVar(&user, "user", "", "socks: user name, if the proxy needs one")
	f.StringVar(&passwordRef, "password-ref", "", "socks: the proxy password as secret:NAME | env:VAR | file:PATH")
	f.StringVar(&check, "check", "", "host:port reachable only through this VPN, used by `komando test`")
	f.StringSliceVarP(&groups, "group", "g", nil, "group(s)")
	f.StringSliceVarP(&tags, "tag", "t", nil, "tag(s)")
	f.StringVar(&notes, "notes", "", "free-form notes")
	f.BoolVar(&overwrite, "overwrite", false, "replace a VPN with the same name")
	return c
}

func vpnShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Show a VPN (keys stay in the vault)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			v, ok := st.Vpns[args[0]]
			if !ok {
				return out.NotFound("vpn", args[0])
			}
			out.P.Print("vpn.show", map[string]any{"vpn": v, "used_by": vpnUsers(st, v.Name)}, nil)
			return nil
		},
	}
}

func vpnRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm NAME",
		Short: "Remove a VPN from komando (its keys stay in the vault until `komando secret rm`)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := store.Update(func(s *store.State) error {
				if _, ok := s.Vpns[args[0]]; !ok {
					return out.NotFound("vpn", args[0])
				}
				if users := vpnUsers(s, args[0]); len(users) > 0 {
					return out.Errf(out.ExitConflict, "VPN_IN_USE", "change their --via first", "VPN %s is on the --via path of %s", args[0], strings.Join(users, ", "))
				}
				delete(s.Vpns, args[0])
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "vpn.rm", []string{args[0]}, "", true, nil)
			out.P.Print("vpn.rm", map[string]any{"removed": args[0]}, nil)
			return nil
		},
	}
}

// vpnUsers lists the servers and conns whose --via path names the VPN.
func vpnUsers(st *store.State, name string) []string {
	var users []string
	for _, h := range st.SortedHosts() {
		if slices.Contains(viaChain(h.Via), name) {
			users = append(users, h.Name)
		}
	}
	for _, c := range st.SortedConns() {
		if slices.Contains(viaChain(c.Via), name) {
			users = append(users, c.Name)
		}
	}
	return users
}

// vpnWhere is a VPN's address for `komando list`.
func vpnWhere(v *store.Vpn) string {
	switch v.Kind {
	case "wireguard":
		if c, err := netx.ParseWG(v.Config); err == nil && c.Peers[0].Endpoint != "" {
			return c.Peers[0].Endpoint
		}
	case "socks":
		return v.Address
	}
	return dash(v.Check)
}

// testVpn opens the VPN and, when it has --check, connects to that address
// through it.
func testVpn(ctx context.Context, st *store.State, v *store.Vpn) targetTest {
	r := targetTest{Name: v.Name, Kind: "vpn"}
	t0 := time.Now()
	timeout := sshOpts(st).ConnectTimeout
	dial, closer, err := netx.Open(ctx, v, timeout)
	if err != nil {
		r.Error = toErr(err)
		return r
	}
	defer closer.Close()
	detail := map[string]any{"kind": v.Kind}
	if v.Check != "" && v.Kind != "system" { // system already checked it in Open
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		c, err := dial(cctx, "tcp", v.Check)
		if err != nil {
			r.Error = toErr(err)
			return r
		}
		c.Close()
		detail["checked"] = v.Check
	} else if v.Check == "" {
		detail["note"] = "no --check address, so only the configuration was checked"
	}
	r.OK, r.LatencyMS, r.Detail = true, time.Since(t0).Milliseconds(), detail
	return r
}
