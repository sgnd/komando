package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
)

// komando prompt prints a short note for a person's shell prompt, such as
// "vpn:office tun:2", or nothing. The prompt runs it on every Enter, so it
// only reads the state file: no lock, no writes, no other programs, no
// network (docs/design/session-status.md). In particular it never calls
// netx.LiveSession, which marks a VPN as used and would keep it up forever.

func promptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "prompt",
		Short: "A short note for your shell prompt: VPNs and tunnels that are up",
		Long: `Prints what komando keeps running in the background, for your shell prompt:
"vpn:office tun:2" when the VPN office is up and two tunnels run, nothing when
nothing runs. It only reads komando's state file and never fails, so it is safe
to run on every prompt. It is a quick hint; ` + "`komando status`" + ` is the full check.

zsh (also with oh-my-zsh), in ~/.zshrc:
  setopt PROMPT_SUBST
  RPROMPT='$(komando prompt)'

bash, in ~/.bashrc:
  PS1='$(p=$(komando prompt); [ -n "$p" ] && echo "[$p] ")'"$PS1"

starship, in ~/.config/starship.toml:
  [custom.komando]
  command = "komando prompt"
  when = true`,
		Args: cobra.NoArgs,
		// not the root's checks: they reap idle VPNs and check the audit
		// log, which is work and writes on every prompt
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		Run: func(*cobra.Command, []string) {
			fmt.Print(promptText(time.Now()))
		},
	}
}

// promptText is the note with a newline, or "" when nothing runs or the
// state cannot be read: a broken prompt is worse than a missing note. It
// reads runtime.pids: the prompt never opens the store (no keychain, no
// passphrase on each Enter), so it counts running VPNs and tunnels without
// naming them.
func promptText(now time.Time) string {
	p, err := store.ReadRuntimePIDs()
	if err != nil {
		return ""
	}
	idle, _ := time.ParseDuration(store.DefaultSettings().VpnIdle)
	vpns, tunnels := 0, 0
	for _, v := range p.Vpns {
		if netx.Alive(v.PID) && (idle <= 0 || now.Sub(v.LastUsed) <= idle) {
			vpns++
		}
	}
	for _, pid := range p.Tunnels {
		if alive(pid) {
			tunnels++
		}
	}
	var parts []string
	if vpns > 0 {
		parts = append(parts, "vpn:"+strconv.Itoa(vpns))
	}
	if tunnels > 0 {
		parts = append(parts, "tun:"+strconv.Itoa(tunnels))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ") + "\n"
}
