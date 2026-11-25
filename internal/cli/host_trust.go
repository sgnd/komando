package cli

import (
	"context"
	"encoding/base64"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Host connectivity tests.

type testResult struct {
	Host          string `json:"host"`
	OK            bool   `json:"ok"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`
	RemoteUser    string `json:"remote_user,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	SudoNoPasswd  *bool  `json:"sudo_nopasswd,omitempty"`
	Admin         *bool  `json:"admin,omitempty"` // Windows: the login is an administrator
	OS            string `json:"os,omitempty"`    // windows, for a Windows server
}

// testHost logs in and checks who we are and whether sudo needs a password.
func testHost(ctx context.Context, c *sshx.Client) (any, error) {
	if c.Host.Windows() {
		return testWindowsHost(ctx, c)
	}
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
	var fingerprint string
	c := &cobra.Command{
		Use:   "trust TARGET",
		Short: "Pin the SSH host keys of servers (--reset after a rebuild)",
		Long: `Fetches the server's host key and stores it in komando's known_hosts, like
ssh-keyscan plus ssh-keygen -R. The key is fetched the way komando reaches
the server: directly, or through its --via servers, VPN or proxy command.

A key that is already pinned is left as it is. If a different key is
pinned, the server may be an impostor (HOSTKEY_MISMATCH): check the new
fingerprint another way, then replace the pin with --reset. Only a person
at a terminal replaces a pin: komando shows the old and the new key and
asks once; an AI agent or a script gets NEEDS_PERSON, whatever flags it
adds. With --dry-run nothing is fetched or changed; it only counts the
pinned entries --reset would replace.

TARGET can be many servers (@group, tag:, 'web*', a,b): after a rebuild of
a whole group, --reset replaces all their keys after a single yes, which names
every server with its new key. Each server is in results, with its old and
new fingerprint; a server whose key changed is refused without --reset,
the others are pinned.

With --fingerprint SHA256:..., the key is pinned only when the server shows
that key: compare-then-pin in one step, for a fingerprint read from the
server's console or a cloud provider. Any other key stops with
HOSTKEY_MISMATCH and nothing is pinned. It takes one server, and the
fingerprint of the key type the server offers (key_type in the answer).`,
		Example: `  komando host trust web1
  komando host trust web1 --reset --dry-run   # how many pinned keys would go
  komando host trust web1 --reset             # after a real rebuild (a person, at a terminal)
  komando host trust @web                 # pin new servers; changed keys are refused
  komando host trust @web --reset         # after rebuilding the whole group: one yes
  komando host trust web1 --fingerprint SHA256:pVt2...  # pin only this key`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			hosts, err := resolveTargets(cl, st, args[0])
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("fingerprint") {
				if err := checkTrustFingerprint(fingerprint, hosts); err != nil {
					return err
				}
			}
			if reset && !cl.dryRun() && (cl.isAgent() || !cl.interactive()) {
				if err := pinsNeedAPerson(cl, st, hosts); err != nil {
					return err // before anything is fetched, as the dry run says
				}
			}
			return trustHosts(cl, cmd.Context(), st, hosts, reset, fingerprint)
		}),
	}
	c.Flags().BoolVar(&reset, "reset", false, "replace the key pinned before (a person at a terminal only)")
	c.Flags().StringVar(&fingerprint, "fingerprint", "", "pin only if the server shows the key with this SHA256: fingerprint (one server)")
	return c
}

// replacePin is the one stop before a pinned host key is replaced (S-7.2
// T4, OD-9): a changed key may be an attack (AGENTS rule 8), so only a
// person at a terminal replaces one, after one question that says what
// changes and which of the servers are protected. An AI agent or a script
// gets NEEDS_PERSON, which no flag lifts; a dry run records it and goes on.
func replacePin(cl *call, names, prot []string, what string) error {
	if cl.isAgent() || !cl.interactive() {
		return cl.policyStop(out.Errf(out.ExitPolicy, "NEEDS_PERSON",
			"report it to the user: once they have checked the new key another way, they run `komando host trust "+strings.Join(names, ",")+" --reset` in their own terminal",
			"%s: only a person at a terminal replaces a pinned host key (a changed key may be an attack)", what).NoFlag())
	}
	if cl.dryRun() {
		return nil
	}
	cl.askedAbout = names
	q := what + ". Replace it?"
	if len(prot) > 0 {
		q = strings.Join(prot, ", ") + " (protected): " + q
	}
	if !confirmYes(cl, q) {
		return promptNo()
	}
	return nil
}

// pinsNeedAPerson stops an AI agent or a script that asks --reset for
// servers with a pinned key: --reset is there to replace one, which only a
// person does (OD-9). Servers with no pin yet go on (a first pin).
func pinsNeedAPerson(cl *call, st *store.State, hosts []*store.Host) error {
	var names, prot []string
	for _, h := range hosts {
		if countPinned(trustAddr(h)) > 0 {
			names = append(names, h.Name)
			if protectedHost(st, h) {
				prot = append(prot, h.Name)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	return replacePin(cl, names, prot, "replacing the pinned host key of "+term.JoinAnd(names))
}

// countPinned counts the pins for addr, as PinHostKey would replace them,
// without changing them.
func countPinned(addr string) int {
	n, _ := sshx.CountPinned(addr)
	return n
}

// renameStep replaces a renamed host in a --via chain.
func renameStep(via, old, now string) string {
	steps := inventory.ViaChain(via)
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

// guardFirstPin: with host_key_policy strict, a server's first key is
// pinned only after someone checked it, so an AI agent's first pin needs a
// person's yes, and the window shows each server's fingerprint to compare
// with what the server's owner sees. Under accept-new the first login pins
// it anyway. what is "NAME SHA256:..." per server.
func guardFirstPin(cl *call, st *store.State, what []string) error {
	if len(what) == 0 || !cl.isAgent() || (st.Settings.HostKeyPolicy != "strict" && cl.flags.hostKeyPolicy != "strict") {
		return nil
	}
	return guardSafety(cl, "pinning a first host key while host keys are strict (compare it with what the server's owner sees): "+strings.Join(what, ", "))
}

// checkTrustFingerprint: --fingerprint is one key's SHA256 fingerprint, as
// ssh-keygen -lf prints it (SHA256: and 43 characters of base64), for one
// server.
func checkTrustFingerprint(fp string, hosts []*store.Host) error {
	b64, ok := strings.CutPrefix(fp, "SHA256:")
	if _, err := base64.RawStdEncoding.DecodeString(b64); !ok || len(b64) != 43 || err != nil {
		return out.Errf(out.ExitUsage, "USAGE", "give the fingerprint as `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` prints it on the server, for example --fingerprint SHA256:pVt2...",
			"--fingerprint %q is not a SHA256 fingerprint (SHA256: and 43 characters)", fp)
	}
	if len(hosts) != 1 {
		return out.Errf(out.ExitUsage, "USAGE", "name one server with --fingerprint: komando host trust NAME --fingerprint SHA256:...",
			"--fingerprint is one server's key, and the target names %s", countOf(len(hosts), "server"))
	}
	return nil
}
