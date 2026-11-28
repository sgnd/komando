package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// A command on a target that is this computer runs here: exec on localhost
// is a shell, `logs --file`, `fs cat` and `fs list` read any file here (a
// private key whose lines MaskSecrets cannot tell from data), a sqlite conn
// is a file here (VACUUM INTO, ATTACH and db restore write any file), and a
// database, cache or cluster at 127.0.0.1 runs programs or reads and writes
// files here (COPY TO PROGRAM, pg_read_file, CONFIG SET dir, a hostPath
// volume). So every key, read-only too, is refused every command, reads
// included, on a file conn or a target at a loopback address
// (gateLocalAddr). A target the gate cannot find, or whose name it cannot
// resolve, is refused too, for a read as for a change: the gate fails
// closed. The komando it runs dials only addresses it judged the same way
// (gateDial), so DNS cannot answer this check one address and the
// connection another. This
// computer under another name or address is found by its pinned host key,
// which is one of this computer's own (gateSameHostKey), or by an address
// that is one of this computer's network addresses (gateLocalAddr).
//
// gateTargetArgs reads the targets of the changes whose target is not where
// their Use line says (gateUseTargets). Jobs were started through the gate;
// VPNs are no target.
var gateTargetArgs = map[safetyKey]func(cl *call, args []string) []string{
	{"snippet", "", "exec"}: argAt(1), {"credential", "key", "install"}: argAt(1), {"credential", "key", "uninstall"}: argAt(1),
	{"", "cp", "copy"}: gateRemoteSides, {"", "sync", "copy"}: gateRemoteSides, {"registry", "image", "copy"}: gateRemoteSides,
	{"host", "job", "kill"}: argAt(-1), {"host", "job", "rm"}: argAt(-1), {"vpn", "", "start"}: argAt(-1), {"vpn", "", "stop"}: argAt(-1),
}

// argAt reads argument i as the target (none when i < 0).
func argAt(i int) func(cl *call, args []string) []string {
	return func(_ *call, a []string) []string { return a[min(max(i, 0), len(a)):min(max(i+1, 0), len(a))] }
}

// gateRemoteSides are the TARGET of each TARGET:PATH (CONN:IMAGE) argument.
func gateRemoteSides(cl *call, args []string) []string {
	var res []string
	for _, a := range args {
		if t, _, remote := splitArg(cl, a); remote {
			res = append(res, t)
		}
	}
	return res
}

// gateUseTargets are the arguments c's Use line names TARGET, SERVER or
// CONN, alone or as one choice (`logs TARGET`, `cat SERVER PATH`,
// `[TARGET]`, `rm TARGET...`). It stops at the
// first flag in the line: the words after it are no position.
func gateUseTargets(c *cobra.Command, args []string) []string {
	var res []string
	for i, w := range strings.Fields(c.Use)[1:] {
		if strings.HasPrefix(strings.TrimLeft(w, "["), "-") || i >= len(args) {
			break
		}
		w = strings.Trim(w, "[]")
		variadic := strings.HasSuffix(w, "...")
		w = strings.TrimSuffix(w, "...")
		target := false
		for _, alt := range strings.Split(w, "|") {
			target = target || gateTargetWords[alt]
		}
		switch {
		case !target:
		case variadic:
			return append(res, args[i:]...)
		default:
			res = append(res, args[i])
		}
	}
	return res
}

// gateTargetWords are the Use words that name where a command acts.
var gateTargetWords = map[string]bool{"TARGET": true, "SERVER": true, "CONN": true}

// gateLocalTarget says why c acts on this computer, or "", for every key.
func gateLocalTarget(c *cobra.Command, name string) string {
	cl := callOf(c)
	args := c.Flags().Args()
	_, change := gateOnServers[cmdKeys[name]]
	targets := gateUseTargets(c, args)
	if f, ok := gateTargetArgs[cmdKeys[name]]; ok {
		targets = f(cl, args)
	} else if change && len(targets) == 0 {
		targets = argAt(0)(cl, args)
	}
	if len(targets) == 0 {
		return ""
	}
	st, err := store.Load()
	if err != nil {
		return "the inventory could not be read"
	}
	for _, e := range targets {
		sel, err := resolveSelection(cl, st, e)
		if err != nil {
			return fmt.Sprintf("the gate cannot tell where %q is", e)
		}
		for _, h := range sel.Hosts {
			// An ad hoc target (u@host, an IP) could be this computer under a
			// name nobody listed, so a key reaches only servers a person added.
			if st.Hosts[h.Name] != h {
				return fmt.Sprintf("%q is not in the inventory; a key runs commands only on servers a person added", e)
			}
			if why := gateHostAt(cl, st, "the server "+h.Name, h, 0); why != "" {
				return why
			}
			if gateSameHostKey(h) {
				return "the server " + h.Name + " is on this computer (its host key is this computer's own)"
			}
		}
		for _, cn := range sel.Conns {
			t, err := driver.Parse(cn.URL)
			if err != nil || t.Kind.File {
				return cn.Name + " is a file on this computer (or its URL cannot be read)"
			}
			dials := append([]string{t.Address}, t.Sentinels...)
			if t.Resolve != "" {
				// the dial goes to Resolve (pinDial): the name counts only as written
				if gateLocalAsWritten(t.Address) {
					return cn.Name + " is on this computer (" + t.Address + ")"
				}
				dials[0] = t.Resolve
			}
			for i, a := range append(dials, gateURLHosts(cn.URL)...) {
				if why := gateAt(cl, st, cn.Name, a, cn.Via, i < len(dials), 0); why != "" {
					return why
				}
			}
		}
	}
	return ""
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

// gateAt says why subject, at addr reached through via, may be this
// computer, or "". With strict, a name the gate cannot resolve may be too,
// unless a jump host that is not this computer resolves it. The other
// hosts a URL names are not strict (an s3 URL names its bucket there):
// the dial judges each address it connects to (gateDial).
func gateAt(cl *call, st *store.State, subject, addr, via string, strict bool, depth int) string {
	here, err := gateLocalAddr(addr)
	if !strict {
		err = nil
	}
	if !here && err == nil {
		return ""
	}
	at := addr
	steps := inventory.ViaChain(via)
	if len(steps) > 0 {
		last := steps[len(steps)-1]
		h, ferr := findHost(cl, st, last)
		if ferr == nil && depth <= 8 {
			return gateHostAt(cl, st, subject, h, depth+1)
		}
		at += " through " + last // a VPN, or not found
	}
	if err != nil {
		return "the gate cannot resolve " + at
	}
	return subject + " is on this computer (" + at + ")"
}

// gateHostAt is gateAt for subject reached as the server or jump host h. A
// host with a proxy command is reached by that program, which resolves
// what it names (an SSM instance ID resolves nowhere): a lookup error does
// not count, only an address that is here.
func gateHostAt(cl *call, st *store.State, subject string, h *store.Host, depth int) string {
	if h.ProxyCommand != "" {
		return gateAt(cl, st, subject, h.Address, "", false, depth)
	}
	return gateAt(cl, st, subject, h.Address, h.Via, true, depth)
}

// gateLocalAddr: a name or address, with or without a port, is this
// computer: localhost, a loopback or unspecified IP, one of this
// computer's addresses, or this computer's name, as written or as the
// name resolves (ip6-localhost, localtest.me: any address it resolves to
// counts). A number in another form (127.1, 0x7f000001), which a C
// resolver reads its own way, counts too. err: the name does not resolve,
// so the gate cannot tell (C655).
func gateLocalAddr(a string) (bool, error) {
	if gateLocalAsWritten(a) {
		return true, nil
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	a = inventory.NormAddr(a)
	if a == "" || net.ParseIP(a) != nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := gateLookup(ctx, a)
	if err == nil && len(ips) == 0 {
		err = errGateNoAddress
	}
	return slices.ContainsFunc(ips, gateLocalIP), err
}

var errGateNoAddress = errors.New("the name has no address")

// gateLookup resolves a name for the gate (gateLocalAddr, gateDial); tests
// answer for it.
var gateLookup = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// gateLocalIP is gateHereIP; tests whose servers listen on loopback swap it.
var gateLocalIP = gateHereIP

// gateHereIP: ip is this computer: loopback, unspecified, one of its
// network addresses, an address that reaches it too (gateGroupIP), one
// only its own link or cloud answers (gateNearIP), an IPv6 address that
// carries such an IPv4 address, or one whose IPv4 address the gate cannot
// read (gateOpaqueIP).
func gateHereIP(ip net.IP) bool {
	if v4 := gateCarriedIPv4(ip); v4 != nil && gateHereIP(v4) {
		return true
	}
	return ip.IsLoopback() || ip.IsUnspecified() || gateNearIP(ip) || gateGroupIP(ip) || gateOpaqueIP(ip) || gateOwnIP(ip)
}

// gateCarriedIPv4 is the IPv4 address a translator connects to for ip:
// NAT64's well-known prefix (64:ff9b::/96) or SIIT (::ffff:0:0/96); nil
// for any other address.
func gateCarriedIPv4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return nil
	}
	if p := [12]byte(ip16[:12]); p == [12]byte{0, 0x64, 0xff, 0x9b} || p == [12]byte{8: 0xff, 9: 0xff} {
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	}
	return nil
}

// gateOpaqueIP: ip leads to an IPv4 address the gate cannot read: 6to4
// (2002::/16) and Teredo (2001::/32) go through a relay, and local NAT64
// (64:ff9b:1::/48) puts it where only its network's prefix length says.
func gateOpaqueIP(ip net.IP) bool {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return false
	}
	return [2]byte(ip16[:2]) == [2]byte{0x20, 0x02} || [4]byte(ip16[:4]) == [4]byte{0x20, 0x01} ||
		[6]byte(ip16[:6]) == [6]byte{0, 0x64, 0xff, 0x9b, 0, 1}
}

// gateNearIP: ip answers only on this computer's own link (169.254.0.0/16,
// fe80::/10), or is a cloud's metadata service, which hands out this
// machine's own credentials: for a key both are here.
func gateNearIP(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || gateAWSNet.Contains(ip) || slices.ContainsFunc(gateMetadataIPs, ip.Equal)
}

// gateAWSNet is AWS's own IPv6 services on the instance (metadata at ::254,
// the EKS Pod Identity agent at ::23, "Set up the Amazon EKS Pod Identity
// Agent", and the rest of the range).
var gateAWSNet = &net.IPNet{IP: net.ParseIP("fd00:ec2::"), Mask: net.CIDRMask(32, 128)}

// gateMetadataIPs are the other cloud metadata services outside
// 169.254.0.0/16: Google over IPv6, Oracle over IPv6 (its own pages name
// only 169.254.169.254: refused as a precaution), Alibaba, Azure's wire
// server, Oracle's older one.
var gateMetadataIPs = []net.IP{
	net.ParseIP("fd20:ce::254"), net.ParseIP("fd00:c1::a9fe:a9fe"),
	net.ParseIP("100.100.100.200"), net.ParseIP("168.63.129.16"), net.ParseIP("192.0.0.192"),
}

// gateGroupIP: ip is no one server's: multicast and broadcast reach this
// computer too, 0.0.0.0/8 is this network, and an IPv4-compatible
// address (::127.0.0.1) is read as its IPv4 address by some systems.
func gateGroupIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 0 || ip4.IsMulticast() || ip4.Equal(net.IPv4bcast)
	}
	return ip.IsMulticast() || len(ip) == net.IPv6len && [12]byte(ip[:12]) == [12]byte{}
}

// gateLocalAsWritten is gateLocalAddr without resolving the name. An
// address written with a zone (%en0) counts as here: the zone names a link
// of this computer, and the gate cannot tell where it leads.
func gateLocalAsWritten(a string) bool {
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	a = inventory.NormAddr(a)
	if strings.Contains(a, "%") {
		return true
	}
	if ip := net.ParseIP(a); ip != nil {
		return gateLocalIP(ip)
	}
	me, _ := os.Hostname()
	me = inventory.NormAddr(me)
	short, _, _ := strings.Cut(me, ".")
	return a == "localhost" || strings.HasSuffix(a, ".localhost") || a != "" && (a == me || a == short) ||
		a != "" && a[0] >= '0' && a[0] <= '9' && strings.Trim(a, "0123456789abcdefx.") == ""
}

// gateOwnIP: ip is an address of one of this computer's network
// interfaces (its LAN address), or the broadcast address of one of its
// networks, so a server at it is this computer. Without the list, any address may be.
func gateOwnIP(ip net.IP) bool {
	ifs, err := gateInterfaces()
	if err != nil {
		return true
	}
	return slices.ContainsFunc(ifs, func(i gateIface) bool { return i.holds(ip) || i.broadcasts(ip) })
}

// gateIface is one of this computer's network interfaces as the gate sees it.
type gateIface struct {
	addrs []*net.IPNet
}

func (i gateIface) holds(ip net.IP) bool {
	return slices.ContainsFunc(i.addrs, func(n *net.IPNet) bool { return n.IP.Equal(ip) })
}

// broadcasts: ip is the broadcast address of one of i's IPv4 networks (a
// /31 or /32 has none: its other address is the peer's).
func (i gateIface) broadcasts(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && slices.ContainsFunc(i.addrs, func(n *net.IPNet) bool {
		a, m := n.IP.To4(), n.Mask
		if len(m) == net.IPv6len {
			m = m[12:]
		}
		if ones, bits := m.Size(); a == nil || bits != 32 || ones >= 31 {
			return false
		}
		for k := range a {
			if a[k]|^m[k] != ip4[k] {
				return false
			}
		}
		return true
	})
}

// gateInterfaces lists this computer's network interfaces and their
// addresses; tests answer for it.
var gateInterfaces = func() ([]gateIface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	res := make([]gateIface, 0, len(ifs))
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		var g gateIface
		for _, a := range addrs {
			switch a := a.(type) {
			case *net.IPNet:
				g.addrs = append(g.addrs, a)
			case *net.IPAddr:
				g.addrs = append(g.addrs, &net.IPNet{IP: a.IP, Mask: net.CIDRMask(8*len(a.IP), 8*len(a.IP))})
			}
		}
		res = append(res, g)
	}
	return res, nil
}

// sshdHostKeys are where this computer's own SSH server keeps its public
// host keys; tests point them elsewhere.
var sshdHostKeys = "/etc/ssh/ssh_host_*_key.pub"

// gateSameHostKey: a key pinned for h is one of this computer's own SSH
// host keys, so h is this computer under another name or address (a DNS
// name, a public IP, a port forward). A server never reached has no pin
// and is judged by its address alone.
func gateSameHostKey(h *store.Host) bool {
	files, _ := filepath.Glob(sshdHostKeys)
	if len(files) == 0 {
		return false
	}
	pins, err := sshx.PinnedKeys(net.JoinHostPort(h.Address, strconv.Itoa(h.EffectivePort())))
	if err != nil || len(pins) == 0 {
		return false
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		own, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			continue
		}
		for _, p := range pins {
			if sshx.SameKey(p, own) {
				return true
			}
		}
	}
	return false
}
