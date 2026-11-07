package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
// state cannot be read: a broken prompt is worse than a missing note.
func promptText(now time.Time) string {
	b, err := os.ReadFile(store.Path("state.json"))
	if err != nil {
		return ""
	}
	var st store.State
	if json.Unmarshal(b, &st) != nil {
		return ""
	}
	if st.Settings.VpnIdle == "" {
		st.Settings.VpnIdle = store.DefaultSettings().VpnIdle
	}
	idle, _ := time.ParseDuration(st.Settings.VpnIdle)
	var vpns []string
	for name, s := range st.Sessions {
		// the process is checked only by its pid: a container would need
		// `docker inspect`, too slow for a prompt
		if s == nil || s.Container == "" && !netx.Alive(s.PID) {
			continue
		}
		if idle > 0 && now.Sub(s.LastUsed) > idle {
			continue // closed at the next komando command
		}
		vpns = append(vpns, cleanText(name))
	}
	sort.Strings(vpns)
	tunnels := 0
	for _, t := range st.Tunnels {
		if t != nil && alive(t.PID) {
			tunnels++
		}
	}
	var parts []string
	if len(vpns) > 0 {
		parts = append(parts, "vpn:"+strings.Join(vpns, ","))
	}
	if tunnels > 0 {
		parts = append(parts, "tun:"+strconv.Itoa(tunnels))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ") + "\n"
}
