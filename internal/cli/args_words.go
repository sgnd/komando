package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
)

// What each Use word means (S-4.2) beyond its name: which kinds a TARGET
// picks for a command, so the prompt label says so ("Target (servers)")
// and Tab and the picker offer only those (C-A04).

// targetKinds is what TARGET picks for c, in words: "servers", "clusters",
// "servers or file storage", "conns", "VPNs", or "" for any kind. It reads
// c's key (risk_keys.go), not its path.
func targetKinds(c *cobra.Command) string {
	k := cmdKeys[cmdID(c)]
	switch {
	case k.typ == "cluster":
		return "clusters"
	case k.typ == "" && k.verb == "copy":
		return "servers or file storage"
	case k.typ == "conn":
		return "conns"
	case k.typ == "vpn":
		return "VPNs"
	case k.typ == "host", k.typ == "snippet", k.typ == "credential" && k.area != "":
		return "servers"
	case k == safetyKey{"cert", "", ""}:
		return "servers" // cert check itself takes any host name or URL
	}
	return ""
}

// targetPick is the picker list for a TARGET of these kinds.
func targetPick(kinds string) string {
	switch kinds {
	case "servers":
		return "host"
	case "clusters":
		return "cluster"
	case "servers or file storage":
		return "files"
	case "conns":
		return "conn"
	case "VPNs":
		return "vpn"
	}
	return "target"
}

// keepTargets leaves out the names Tab offers for TARGET that are not of
// kinds; selectors (@group, tag:, all, kind:) stay, since they pick the
// right ones when the command runs.
func keepTargets(names []string, kinds string) []string {
	if kinds == "" {
		return names
	}
	st, err := store.Load()
	if err != nil {
		return names
	}
	var keep []string
	for _, n := range names {
		bare := strings.TrimPrefix(n[strings.LastIndex(n, ",")+1:], "!")
		_, isHost := st.Hosts[bare]
		c, isConn := st.Conns[bare]
		_, isVpn := st.Vpns[bare]
		ok := true
		switch kinds {
		case "servers":
			ok = !isConn && !isVpn
		case "clusters":
			ok = !isHost && !isVpn && (!isConn || connFamily(c) == "cluster")
		case "servers or file storage":
			ok = !isVpn && (!isConn || connFamily(c) == "storage")
		case "conns":
			ok = !isHost && !isVpn
		case "VPNs":
			ok = !isHost && !isConn
		}
		if ok {
			keep = append(keep, n)
		}
	}
	return keep
}
