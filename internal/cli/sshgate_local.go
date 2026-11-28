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
			if h.ProxyCommand != "" {
				// the program connects and resolves what it names (an SSM
				// instance ID resolves nowhere): a lookup error does not count
				if here, _ := gateLocalAddr(h.Address); here {
					return "the server " + h.Name + " is on this computer (" + h.Address + ")"
				}
			} else if why := gateAt(cl, st, "the server "+h.Name, h.Address, h.Via, true, 0); why != "" {
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
			dials := append([]string{t.Address, t.Resolve}, t.Sentinels...)
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
			return gateAt(cl, st, subject, h.Address, h.Via, true, depth+1)
		}
		at += " through " + last // a VPN, or not found
	}
	if err != nil {
		return "the gate cannot resolve " + at
	}
	return subject + " is on this computer (" + at + ")"
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
	a, _, _ = strings.Cut(inventory.NormAddr(a), "%")
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

// gateLocalIP: ip is this computer: loopback, unspecified, or one of its
// network addresses. Tests whose servers listen on loopback swap it.
var gateLocalIP = func(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified() || gateOwnIP(ip)
}

// gateLocalAsWritten is gateLocalAddr without resolving the name.
func gateLocalAsWritten(a string) bool {
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	a, zone, _ := strings.Cut(inventory.NormAddr(a), "%")
	if zone != "" && gateLoopbackZone(zone) {
		return true // fe80::1%lo0: on this computer's loopback
	}
	me, _ := os.Hostname()
	me = inventory.NormAddr(me)
	short, _, _ := strings.Cut(me, ".")
	if ip := net.ParseIP(a); ip != nil {
		return gateLocalIP(ip)
	}
	return a == "localhost" || strings.HasSuffix(a, ".localhost") || a != "" && (a == me || a == short) ||
		a != "" && a[0] >= '0' && a[0] <= '9' && strings.Trim(a, "0123456789abcdefx.") == ""
}

// gateOwnIP: ip is an address of one of this computer's network
// interfaces (its LAN address, say), so a server at it is this computer.
func gateOwnIP(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() {
		return false // fe80::1 is on every interface: its zone says which (gateLoopbackZone)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
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

// gateLoopbackZone: an IPv6 zone that is a loopback interface here (lo,
// lo0, or one this computer marks loopback).
func gateLoopbackZone(zone string) bool {
	if zone == "lo" || zone == "lo0" {
		return true
	}
	i, err := net.InterfaceByName(zone)
	return err == nil && i.Flags&net.FlagLoopback != 0
}
