package cli

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func init() {
	// HOSTKEY_MISMATCH tells a person how to check and re-trust the key;
	// an agent or a script is told to report it
	sshx.PersonAtTerminal = func() bool { return interactive() }
}

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
the others are pinned.`,
		Example: `  komando host trust web1
  komando host trust web1 --reset --dry-run   # how many pinned keys would go
  komando host trust web1 --reset             # after a real rebuild (a person, at a terminal)
  komando host trust @web                 # pin new servers; changed keys are refused
  komando host trust @web --reset         # after rebuilding the whole group: one yes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			hosts, err := resolveTargets(st, args[0])
			if err != nil {
				return err
			}
			if reset && !g.dryRun && (isAgent() || !interactive()) {
				if err := pinsNeedAPerson(st, hosts); err != nil {
					return err // before anything is fetched, as the dry run says
				}
			}
			return trustHosts(cmd.Context(), st, hosts, reset)
		},
	}
	c.Flags().BoolVar(&reset, "reset", false, "replace the key pinned before (a person at a terminal only)")
	return c
}

// replacePin is the one stop before a pinned host key is replaced (S-7.2
// T4, OD-9): a changed key may be an attack (AGENTS rule 8), so only a
// person at a terminal replaces one, after one question that says what
// changes and which of the servers are protected. An AI agent or a script
// gets NEEDS_PERSON, which no flag lifts; a dry run records it and goes on.
func replacePin(names, prot []string, what string) error {
	if isAgent() || !interactive() {
		return policyStop(out.Errf(out.ExitPolicy, "NEEDS_PERSON",
			"report it to the user: once they have checked the new key another way, they run `komando host trust "+strings.Join(names, ",")+" --reset` in their own terminal",
			"%s: only a person at a terminal replaces a pinned host key (a changed key may be an attack)", what).NoFlag())
	}
	if g.dryRun {
		return nil
	}
	askedAbout = names
	q := what + ". Replace it?"
	if len(prot) > 0 {
		q = strings.Join(prot, ", ") + " (protected): " + q
	}
	if !confirmYes(q) {
		return promptNo()
	}
	return nil
}

// pinsNeedAPerson stops an AI agent or a script that asks --reset for
// servers with a pinned key: --reset is there to replace one, which only a
// person does (OD-9). Servers with no pin yet go on (a first pin).
func pinsNeedAPerson(st *store.State, hosts []*store.Host) error {
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
	return replacePin(names, prot, "replacing the pinned host key of "+joinAnd(names))
}

// countPinned counts the pins for addr, as PinHostKey would replace them,
// without changing them.
func countPinned(addr string) int {
	n, _ := sshx.CountPinned(addr)
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

// guardFirstPin: with host_key_policy strict, a server's first key is
// pinned only after someone checked it, so an AI agent's first pin needs a
// person's yes, and the window shows each server's fingerprint to compare
// with what the server's owner sees. Under accept-new the first login pins
// it anyway. what is "NAME SHA256:..." per server.
func guardFirstPin(st *store.State, what []string) error {
	if len(what) == 0 || !isAgent() || (st.Settings.HostKeyPolicy != "strict" && g.hostKeyPolicy != "strict") {
		return nil
	}
	return guardSafety("pinning a first host key while host keys are strict (compare it with what the server's owner sees): " + strings.Join(what, ", "))
}
