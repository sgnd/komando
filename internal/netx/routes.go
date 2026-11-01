package netx

import (
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Route is one IPv4 entry of the computer's routing table.
type Route struct {
	Prefix netip.Prefix
	Iface  string
}

// Routes reads the computer's IPv4 routes (netstat on macOS, ip on Linux).
// Only VPNs that change the computer's network (OpenVPN --os-mode, system
// VPNs) need it: the in-process and container kinds never add routes.
func Routes() ([]Route, error) {
	var out []byte
	var err error
	if runtime.GOOS == "darwin" {
		out, err = exec.Command("netstat", "-rn", "-f", "inet").Output()
		if err != nil {
			return nil, err
		}
		return parseNetstat(string(out)), nil
	}
	out, err = exec.Command("ip", "-4", "route").Output()
	if err != nil {
		return nil, err
	}
	return parseIPRoute(string(out)), nil
}

// parseNetstat reads macOS `netstat -rn -f inet`, whose destinations are
// abbreviated: "10.8/24" is 10.8.0.0/24, "127" is 127.0.0.0/8.
func parseNetstat(text string) []Route {
	var routes []Route
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] == "Destination" || f[0] == "default" {
			continue
		}
		if p, ok := netstatPrefix(f[0]); ok {
			routes = append(routes, Route{Prefix: p, Iface: f[3]})
		}
	}
	return routes
}

func netstatPrefix(dest string) (netip.Prefix, bool) {
	addr, bits, hasBits := strings.Cut(dest, "/")
	addr, _, _ = strings.Cut(addr, "%") // link-local scope
	parts := strings.Split(addr, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return netip.Prefix{}, false
	}
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	ip, err := netip.ParseAddr(strings.Join(parts, "."))
	if err != nil {
		return netip.Prefix{}, false
	}
	n := 8 * len(strings.Split(addr, "."))
	if hasBits {
		if n, err = strconv.Atoi(bits); err != nil {
			return netip.Prefix{}, false
		}
	}
	p, err := ip.Prefix(n)
	return p, err == nil
}

// parseIPRoute reads Linux `ip -4 route`.
func parseIPRoute(text string) []Route {
	var routes []Route
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "default" {
			continue
		}
		p, err := netip.ParsePrefix(f[0])
		if err != nil {
			a, err2 := netip.ParseAddr(f[0])
			if err2 != nil {
				continue
			}
			p = netip.PrefixFrom(a, 32)
		}
		iface := ""
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				iface = f[i+1]
			}
		}
		routes = append(routes, Route{Prefix: p.Masked(), Iface: iface})
	}
	return routes
}

// Clashes compares the routes before and after a VPN connected. A new
// route that overlaps one another interface already had means two networks
// claim the same addresses: one of them will not be reachable.
func Clashes(before, after []Route) []string {
	had := map[string]bool{}
	for _, r := range before {
		had[r.Prefix.String()+" "+r.Iface] = true
	}
	var warn []string
	seen := map[string]bool{}
	for _, n := range after {
		if had[n.Prefix.String()+" "+n.Iface] || n.Prefix.Bits() == 32 || n.Prefix.Addr().IsLoopback() {
			continue // not new, a single host, or loopback
		}
		for _, o := range before {
			if o.Iface == n.Iface || o.Prefix.Bits() == 32 || o.Prefix.Addr().IsLoopback() || o.Prefix.Addr().IsLinkLocalUnicast() {
				continue
			}
			if o.Prefix.Overlaps(n.Prefix) {
				msg := fmt.Sprintf("%s (now through %s) overlaps %s, already through %s: addresses there may go the wrong way", n.Prefix, n.Iface, o.Prefix, o.Iface)
				if !seen[msg] {
					seen[msg] = true
					warn = append(warn, msg)
				}
			}
		}
	}
	return warn
}
