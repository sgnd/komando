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
// "servers or file storage", "conns", "VPNs", or "" for any kind.
func targetKinds(c *cobra.Command) string {
	if commandFamily(c) == "cluster" {
		return "clusters"
	}
	switch cmdID(c) {
	case "upload", "download", "cp", "sync":
		return "servers or file storage"
	case "list", "test", "export", "group.add", "group.rm", "cert.check", "rename":
		return ""
	}
	top := c
	for top.HasParent() && top.Parent().HasParent() {
		top = top.Parent()
	}
	switch top.Name() {
	case "conn":
		return "conns"
	case "vpn":
		return "VPNs"
	case "host", "key", "tunnel", "recipe", "logs", "facts":
		return "servers"
	}
	if top.GroupID == "servers" {
		return "servers"
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
