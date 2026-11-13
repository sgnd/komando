package cli

import (
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
)

// `komando status --short` prints a short note for a person's shell prompt,
// such as "vpn:1 tun:2", or nothing. The prompt runs it on every Enter,
// so it only reads the state file: no lock, no writes, no other programs, no
// network (docs/features/commands.md). In particular it never calls
// netx.LiveSession, which marks a VPN as used and would keep it up forever.

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
