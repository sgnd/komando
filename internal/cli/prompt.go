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
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
)

// `komando status --short` prints a short note for a person's shell prompt,
// such as "vpn:office tun:2", or nothing. The prompt runs it on every Enter,
// so it only reads the state file: no lock, no writes, no other programs, no
// network (docs/design/session-status.md). In particular it never calls
// netx.LiveSession, which marks a VPN as used and would keep it up forever.

// promptCmd is the old name of `status --short`, kept for one release. Its
// note goes to stderr only when a person typed it: inside $(komando prompt)
// stdout is not a terminal, and a note there would be drawn on every prompt.
func promptCmd() *cobra.Command {
	c := &cobra.Command{
		Use:  "prompt",
		Args: cobra.NoArgs,
		// not the root's checks, as for status --short
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		Run: func(cmd *cobra.Command, _ []string) {
			if term.IsTerminal(int(os.Stdout.Fd())) {
				sayOldName(cmd)
			}
			fmt.Print(promptText(time.Now()))
		},
	}
	markOldName(c, "status --short")
	return c
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
		// the process is checked only by its pid: fast enough for a prompt
		if s == nil || !netx.Alive(s.PID) {
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
