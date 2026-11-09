package cli

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

// A command on a target that is this computer runs here: exec on localhost
// is a shell, `logs --file`, `fs cat` and `fs ls` read any file here (a
// private key whose lines MaskSecrets cannot tell from data), a sqlite conn
// is a file here (VACUUM INTO, ATTACH and db restore write any file), and a
// database, cache or cluster at 127.0.0.1 runs programs or reads and writes
// files here (COPY TO PROGRAM, pg_read_file, CONFIG SET dir, a hostPath
// volume). So every key, read-only too, is refused every command, reads
// included, on a file conn or a target at a loopback address
// (gateLocalAddr). A change whose target the gate cannot find is refused
// too; a read with one it cannot find runs when the name is no loopback
// address (a website for cert check, a typo that fails anyway). This
// computer under another name cannot be told apart (safety.md).
//
// gateTargetArgs reads the targets of the changes whose target is not where
// their Use line says (gateUseTargets). Jobs were started through the gate;
// VPNs are no target.
var gateTargetArgs = map[string]func(args []string) []string{
	"recipe.run": argAt(1), "key.deploy": argAt(1), "key.revoke": argAt(1),
	"cp": gateRemoteSides, "sync": gateRemoteSides, "registry.copy": gateRemoteSides,
	"job.kill": argAt(-1), "job.rm": argAt(-1), "vpn.up": argAt(-1), "vpn.down": argAt(-1),
}

// argAt reads argument i as the target (none when i < 0).
func argAt(i int) func(args []string) []string {
	return func(a []string) []string { return a[min(max(i, 0), len(a)):min(max(i+1, 0), len(a))] }
}

// gateRemoteSides are the TARGET of each TARGET:PATH (CONN:IMAGE) argument.
func gateRemoteSides(args []string) []string {
	var res []string
	for _, a := range args {
		if t, _, remote := splitArg(a); remote {
			res = append(res, t)
		}
	}
	return res
}

// gateUseTargets are the arguments c's Use line names TARGET or CONN
// (`logs TARGET`, `cat TARGET PATH`, `check TARGET...`, `[TARGET]`). It
// stops at the first flag in the line: the words after it are no position.
func gateUseTargets(c *cobra.Command, args []string) []string {
	var res []string
	for i, w := range strings.Fields(c.Use)[1:] {
		if strings.HasPrefix(strings.TrimLeft(w, "["), "-") || i >= len(args) {
			break
		}
		w = strings.Trim(w, "[]")
		variadic := strings.HasSuffix(w, "...")
		w = strings.TrimSuffix(w, "...")
		if j := strings.LastIndex(w, "|"); j >= 0 {
			w = w[j+1:]
		}
		switch {
		case w != "TARGET" && w != "CONN":
		case variadic:
			return append(res, args[i:]...)
		default:
			res = append(res, args[i])
		}
	}
	return res
}

// gateLocalTarget says why c acts on this computer, or "", for every key.
func gateLocalTarget(c *cobra.Command, name string) string {
	args := c.Flags().Args()
	_, change := gateOnServers[name]
	targets := gateUseTargets(c, args)
	if f, ok := gateTargetArgs[name]; ok {
		targets = f(args)
	} else if change && len(targets) == 0 {
		targets = argAt(0)(args)
	}
	if len(targets) == 0 {
		return ""
	}
	st, err := store.Load()
	if err != nil {
		return "the inventory could not be read"
	}
	for _, e := range targets {
		sel, err := resolveSelection(st, e)
		if err != nil {
			if change || gateLocalAddr(gateArgHost(e)) {
				return fmt.Sprintf("the gate cannot tell where %q is", e)
			}
			continue
		}
		for _, h := range sel.Hosts {
			// An ad hoc target (u@host, an IP) could be this computer under a
			// name nobody listed, so a key reaches only servers a person added.
			if st.Hosts[h.Name] != h {
				return fmt.Sprintf("%q is not in the inventory; a key runs commands only on servers a person added", e)
			}
			if why := gateAt(st, h.Address, h.Via, 0); why != "" {
				return "the server " + h.Name + " is on this computer (" + why + ")"
			}
		}
		for _, cn := range sel.Conns {
			t, err := driver.Parse(cn.URL)
			if err != nil || t.Kind.File {
				return cn.Name + " is a file on this computer (or its URL cannot be read)"
			}
			for _, a := range append(append([]string{t.Address, t.Resolve}, t.Sentinels...), gateURLHosts(cn.URL)...) {
				if why := gateAt(st, a, cn.Via, 0); why != "" {
					return cn.Name + " is on this computer (" + why + ")"
				}
			}
		}
	}
	return ""
}

// gateArgHost is the host an argument names that is not in the inventory:
// https://localhost:8443/x, u@127.0.0.1, [::1]:22 (an empty one is here).
func gateArgHost(a string) string {
	if _, rest, ok := strings.Cut(a, "://"); ok {
		a = rest
	}
	a, _, _ = strings.Cut(a, "/")
	if at := strings.LastIndex(a, "@"); at > 0 {
		a = a[at+1:]
	}
	if a == "" {
		return "localhost"
	}
	return a
}

// gateURLHosts are the other hosts a conn URL names, which its driver may
// connect to instead of the one driver.Parse reads: every host of a list
// (a,b,c) and the host and hostaddr parameters (pgx reads them over the
// URL's host). A socket path (/run/postgresql) or an empty host is on this
// computer, so it comes back as "localhost".
func gateURLHosts(raw string) []string {
	var hosts []string
	if _, rest, ok := strings.Cut(raw, "://"); ok {
		auth, _, _ := strings.Cut(rest, "/")
		auth, _, _ = strings.Cut(auth, "?")
		if at := strings.LastIndex(auth, "@"); at >= 0 {
			auth = auth[at+1:]
		}
		hosts = strings.Split(auth, ",")
	}
	if u, err := url.Parse(raw); err == nil {
		for k, vs := range u.Query() {
			if k = strings.ToLower(k); k != "host" && k != "hostaddr" {
				continue
			}
			for _, v := range vs {
				hosts = append(hosts, strings.Split(v, ",")...)
			}
		}
	}
	for i, h := range hosts {
		if h = strings.TrimSpace(h); h == "" || strings.HasPrefix(h, "/") || strings.HasPrefix(h, "@") {
			hosts[i] = "localhost"
		}
	}
	return hosts
}

// gateAt says why addr, reached through via, may be this computer, or "".
func gateAt(st *store.State, addr, via string, depth int) string {
	if !gateLocalAddr(addr) {
		return ""
	}
	steps := viaChain(via)
	if len(steps) == 0 {
		return addr
	}
	last := steps[len(steps)-1]
	h, err := findHost(st, last)
	if err != nil || depth > 8 {
		return addr + " through " + last // a VPN, or not found
	}
	return gateAt(st, h.Address, h.Via, depth+1)
}

// gateLocalAddr: a name or address, with or without a port, is this
// computer as written: localhost, a loopback or unspecified IP, or this
// computer's name. A number in another form (127.1, 0x7f000001), which a C
// resolver reads its own way, counts too.
func gateLocalAddr(a string) bool {
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	a, zone, _ := strings.Cut(normAddr(a), "%")
	if zone != "" && gateLoopbackZone(zone) {
		return true // fe80::1%lo0: on this computer's loopback
	}
	me, _ := os.Hostname()
	me = normAddr(me)
	short, _, _ := strings.Cut(me, ".")
	if ip := net.ParseIP(a); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return a == "localhost" || strings.HasSuffix(a, ".localhost") || a != "" && (a == me || a == short) ||
		a != "" && a[0] >= '0' && a[0] <= '9' && strings.Trim(a, "0123456789abcdefx.") == ""
}

// gateLoopbackZone: an IPv6 zone that is a loopback interface here (lo,
// lo0, or one this computer marks loopback).
func gateLoopbackZone(zone string) bool {
	if zone == "lo" || zone == "lo0" {
		return true
	}
	i, err := net.InterfaceByName(zone)
	return err == nil && i.Flags&net.FlagLoopback != 0
}
