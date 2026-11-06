package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

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
