package cli

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// gateStubDNS answers for gateLookup: an IP literal, also an IPv6 one with
// a zone, as itself (as Go's resolver does); each name's answers in turn
// (the last one again when they run out), an error for "err.example", and
// NXDOMAIN for every other name. It counts the lookups per name.
func gateStubDNS(t *testing.T, answers map[string][][]net.IP) map[string]int {
	t.Helper()
	saved := gateLookup
	t.Cleanup(func() { gateLookup = saved })
	var mu sync.Mutex
	asked := map[string]int{}
	gateLookup = func(_ context.Context, host string) ([]net.IP, error) {
		mu.Lock()
		defer mu.Unlock()
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		n := asked[host]
		asked[host]++
		if ip, err := netip.ParseAddr(host); err == nil {
			return []net.IP{ip.AsSlice()}, nil
		}
		if host == "err.example" {
			return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
		}
		a, ok := answers[host]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return a[min(n, len(a)-1)], nil
	}
	return asked
}

func ips(s ...string) []net.IP {
	var res []net.IP
	for _, a := range s {
		res = append(res, net.ParseIP(a))
	}
	return res
}

// gateOwn is the LAN address gateStubInterfaces gives this computer.
const gateOwn = "192.168.1.10"

// gateStubInterfaces answers for gateInterfaces: lo0 (with fe80::1 as on
// macOS), en0 and utun3.
func gateStubInterfaces(t *testing.T) {
	t.Helper()
	saved := gateInterfaces
	t.Cleanup(func() { gateInterfaces = saved })
	nets := func(cidrs ...string) []*net.IPNet {
		var res []*net.IPNet
		for _, c := range cidrs {
			ip, n, err := net.ParseCIDR(c)
			if err != nil {
				t.Fatal(err)
			}
			res = append(res, &net.IPNet{IP: ip, Mask: n.Mask})
		}
		return res
	}
	ifs := []gateIface{
		{addrs: nets("127.0.0.1/8", "::1/128", "fe80::1/64")},
		{addrs: nets(gateOwn+"/24", "fe80::aaaa/64", "169.254.7.7/16", "2001:db8::10/64")},
		{addrs: nets("10.9.9.0/31")}, // a point-to-point link: 10.9.9.1 is the peer
	}
	gateInterfaces = func() ([]gateIface, error) { return ifs, nil }
}

// gateHereOrUnknown: the gate refuses a, as here or as a name it cannot resolve.
func gateHereOrUnknown(a string) bool {
	here, err := gateLocalAddr(a)
	return here || err != nil
}

// The gate's own check fails closed (C655): a name it cannot resolve, or
// whose answers hold any address of this computer, counts as here.
func TestGateLocalAddrFailsClosed(t *testing.T) {
	answers := map[string][][]net.IP{
		"web.example":     {ips("203.0.113.5")},
		"two.example":     {ips("203.0.113.5", "203.0.113.6")},
		"mixed.example":   {ips("203.0.113.5", "127.0.0.1")},
		"mixed6.example":  {ips("2001:db8::5", "::1")},
		"mapped.example":  {ips("::ffff:127.0.0.1")},
		"zero.example":    {ips("0.0.0.0")},
		"unspec.example":  {ips("::")},
		"empty.example":   {nil},
		"rebind.example":  {ips("203.0.113.5"), ips("127.0.0.1")},
		"public6.example": {ips("2001:db8::5")},
	}
	gateStubInterfaces(t)
	answers["own.example"] = [][]net.IP{ips(gateOwn)}
	answers["ownll.example"] = [][]net.IP{ips("169.254.7.7")}
	answers["imds.example"] = [][]net.IP{ips("169.254.169.254")}
	answers["router.example"] = [][]net.IP{ips("fe80::bbbb")}
	answers["203.0.113.9%en0"] = [][]net.IP{ips("203.0.113.9")} // only the zone rule refuses it
	gateStubDNS(t, answers)
	want := map[string]bool{
		"own.example": true, "ownll.example": true, "imds.example": true, "router.example": true, "169.254.169.254": true,
		"nx.example": true, "err.example": true, "empty.example": true, // cannot tell
		"mixed.example": true, "mixed6.example": true, "mapped.example": true, "zero.example": true, "unspec.example": true,
		"mixed.example:5432": true,
		// a zone names a link here; the resolver would answer the bare address
		"2001:db8:5::9%en0": true, "[2001:db8:5::9%4]:22": true, "203.0.113.9%en0": true,
		"web.example": false, "two.example": false, "public6.example": false, "web.example:22": false,
		"rebind.example": false, // its first answer: the dial judges its own (TestGateDialJudgesItsOwnLookup)
	}
	for a, w := range want {
		if got := gateHereOrUnknown(a); got != w {
			t.Errorf("%q: %v, want %v", a, got, w)
		}
	}
}

// Through the gate: a key's line naming a server whose address the gate
// cannot resolve is refused, and says so; through a jump host the name is
// the jump host's to resolve, so the jump host's own address decides.
func TestGateUnresolvableAddressRefused(t *testing.T) {
	invHome(t)
	gateInventory(t)
	t.Chdir(t.TempDir())
	err := store.Update(store.Save(), func(st *store.State) error {
		for n, h := range map[string]store.Host{
			"nxhost": {Address: "nx.example"}, "errhost": {Address: "err.example"}, "mixedhost": {Address: "mixed.example"},
			"pubhost": {Address: "web.example"}, "inner": {Address: "db.internal", Via: "bastion"},
			"innerme": {Address: "db.internal", Via: "me"}, "vpninner": {Address: "db.internal", Via: "office"},
			"ssmhost":  {Address: "i-0abc123", ProxyCommand: "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"},
			"pcloop":   {Address: "localhost", ProxyCommand: "nc %h %p"},
			"ssmjump":  {Address: "i-0jump123", ProxyCommand: "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"},
			"innerssm": {Address: "db.internal", Via: "ssmjump"}, "pcjump": {Address: "localhost", ProxyCommand: "nc %h %p"},
			"innerpc": {Address: "db.internal", Via: "pcjump"},
		} {
			h.Name, h.User = n, "u"
			st.Hosts[n] = &h
		}
		st.Conns["pgnx"] = &store.Conn{Name: "pgnx", Kind: "postgres", URL: "postgres://u@nx.example/x"}
		// the bucket sits where a host would: no host to resolve
		st.Conns["s3pub"] = &store.Conn{Name: "s3pub", Kind: "s3", URL: "s3://AKID@nxbucket?endpoint=https://web.example:9000"}
		// ?resolve=: the dial goes to that IP, and the name has no DNS here
		st.Conns["s3res"] = &store.Conn{Name: "s3res", Kind: "s3", URL: "s3://AKID@b?endpoint=https://nx.example:9000&resolve=203.0.113.5"}
		st.Conns["s3resloop"] = &store.Conn{Name: "s3resloop", Kind: "s3", URL: "s3://AKID@b?endpoint=https://nx.example:9000&resolve=127.0.0.1"}
		st.Conns["s3resname"] = &store.Conn{Name: "s3resname", Kind: "s3", URL: "s3://AKID@b?endpoint=https://localhost:9000&resolve=203.0.113.5"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	gateStubDNS(t, map[string][][]net.IP{"web.example": {ips("203.0.113.5")}, "mixed.example": {ips("203.0.113.5", "127.0.0.1")}})
	const R = "SSH_GATE_REFUSED"
	for line, want := range map[string]string{
		"logs nxhost":                         R,
		"logs errhost":                        R,
		"logs mixedhost":                      R,
		"db query pgnx 'select 1'":            R,
		"logs vpninner":                       R, // a name through a VPN: the gate cannot tell where the VPN goes
		"logs innerme":                        R, // the jump host is this computer
		"logs pubhost":                        "",
		"logs inner":                          "", // the jump host bastion resolves it, far from here
		"logs pcloop":                         R,
		"logs ssmhost":                        "", // its proxy command connects: an instance ID resolves nowhere
		"logs innerssm":                       "", // the same for a jump host
		"logs innerpc":                        R,  // a jump host on this computer, through its proxy command
		"storage download s3pub a.txt --to -": "",
		"storage download s3res a.txt --to -": "",
		"storage download s3resloop a.txt --to -": R,
		"storage download s3resname a.txt --to -": R, // the name as written
	} {
		for _, readOnly := range []bool{true, false} {
			if got := gateAnswer(t, line, readOnly); got != want {
				t.Errorf("%q (read-only key %v): %q, want %q", line, readOnly, got, want)
			}
		}
	}
	for line, msg := range map[string]string{
		"logs nxhost":    `the gate cannot resolve nx.example`,
		"logs errhost":   `the gate cannot resolve err.example`,
		"logs mixedhost": `the server mixedhost is on this computer (mixed.example)`,
	} {
		words, err := gateWords(line)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, e := gateCheck(words, gateKey{readOnly: true}); e == nil || !strings.Contains(e.Message, msg) || strings.Contains(e.Message, "no such host") {
			t.Errorf("%s: %+v, want %q", line, e, msg)
		}
	}
}

// gateDialStub records what the gate dialer asks the network for.
type gateDialStub struct {
	mu    sync.Mutex
	asked []string
	fail  map[string]bool
}

func (d *gateDialStub) dial(_ context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked = append(d.asked, network+" "+addr)
	if d.fail[addr] {
		return nil, errors.New("connection refused")
	}
	c, s := net.Pipe()
	s.Close()
	return c, nil
}

// The dialer of a komando run for a key resolves a name once, refuses the
// whole name when the lookup fails or any answer is this computer, and
// connects only to the addresses it judged (C655).
func TestGateDialRefusesHere(t *testing.T) {
	answers := map[string][][]net.IP{
		"mixed.example":  {ips("203.0.113.5", "127.0.0.1")},
		"mapped.example": {ips("::ffff:127.0.0.1")},
		"zero.example":   {ips("0.0.0.0")},
		"unspec.example": {ips("::")},
		"mcast.example":  {ips("203.0.113.5", "239.1.1.1")},
		"empty.example":  {nil},
		"imds.example":   {ips("203.0.113.5", "169.254.169.254")},
		"nat64.example":  {ips("2001:db8::5", "64:ff9b::7f00:1")},
		"ll6.example":    {ips("fe80::5")},
	}
	gateStubInterfaces(t)
	answers["own.example"] = [][]net.IP{ips(gateOwn)}
	gateStubDNS(t, answers)
	refused := map[string]string{
		"own.example:22":        "own.example is this computer",
		gateOwn + ":22":         gateOwn + " is this computer",
		"169.254.7.7:22":        "169.254.7.7 is this computer", // its own link-local IPv4 address
		"[fe80::aaaa]:22":       "fe80::aaaa is this computer",  // its own, with no zone
		"[fe80::aaaa%en0]:22":   "fe80::aaaa%en0 names a network interface",
		"[fe80::aaaa%4]:22":     "fe80::aaaa%4 names a network interface",
		"[fe80::1%1]:22":        "fe80::1%1 names a network interface",
		"[fe80::5%lo0]:22":      "fe80::5%lo0 names a network interface",
		"[::1%en0]:22":          "::1%en0 names a network interface",
		"[fe80::bbbb%en9]:22":   "fe80::bbbb%en9 names a network interface",
		"nx.example:22":         "the gate cannot resolve nx.example",
		"err.example:22":        "the gate cannot resolve err.example",
		"empty.example:22":      "the gate cannot resolve empty.example",
		"mixed.example:22":      "mixed.example is this computer",
		"mapped.example:22":     "mapped.example is this computer",
		"zero.example:22":       "zero.example is this computer",
		"unspec.example:22":     "unspec.example is this computer",
		"127.0.0.1:5432":        "127.0.0.1 is this computer",
		"127.1:5432":            "127.1 is this computer",
		"[::1]:22":              "::1 is this computer",
		"[::ffff:127.0.0.1]:22": "::ffff:127.0.0.1 is this computer",
		"0.0.0.0:22":            "0.0.0.0 is this computer",
		"[::]:22":               ":: is this computer",
		"localhost:6379":        "localhost is this computer",
		"[fe80::1%lo0]:22":      "fe80::1%lo0 names a network interface",
		"224.0.0.1:5353":        "224.0.0.1 is this computer", // multicast reaches this computer too
		"[ff02::1%en0]:22":      "ff02::1%en0 names a network interface",
		"[ff01::1]:22":          "ff01::1 is this computer",
		"255.255.255.255:22":    "255.255.255.255 is this computer",
		"192.168.1.255:22":      "192.168.1.255 is this computer", // en0's broadcast
		"[::127.0.0.1]:22":      "::127.0.0.1 is this computer",   // IPv4-compatible
		"0.1.2.3:22":            "0.1.2.3 is this computer",
		"mcast.example:22":      "mcast.example is this computer",
		// any link-local address, and a cloud's metadata service, which hands
		// out this machine's own credentials
		"169.254.9.9:22":              "169.254.9.9 is this computer",
		"169.254.169.254:80":          "169.254.169.254 is this computer",
		"[::ffff:169.254.169.254]:80": "::ffff:169.254.169.254 is this computer",
		"[fe80::bbbb]:22":             "fe80::bbbb is this computer",
		"[fd00:ec2::254]:80":          "fd00:ec2::254 is this computer",
		"[fd20:ce::254]:80":           "fd20:ce::254 is this computer",
		"[fd00:ec2::23]:80":           "fd00:ec2::23 is this computer",
		"[fd00:ec2::1]:80":            "fd00:ec2::1 is this computer", // all of fd00:ec2::/32 is AWS's
		"[fd00:ec2:0:ffff::123]:80":   "fd00:ec2:0:ffff::123 is this computer",
		"[fd00:c1::a9fe:a9fe]:80":     "fd00:c1::a9fe:a9fe is this computer",
		"100.100.100.200:80":          "100.100.100.200 is this computer",
		"168.63.129.16:80":            "168.63.129.16 is this computer",
		"192.0.0.192:80":              "192.0.0.192 is this computer",
		"imds.example:80":             "imds.example is this computer",
		"ll6.example:22":              "ll6.example is this computer",

		// a zone names a link here, on any address: the gate cannot tell where it leads
		"203.0.113.9%en0:22":   "203.0.113.9%en0 names a network interface",
		"[2001:db8::9%en0]:22": "2001:db8::9%en0 names a network interface",
		"[2001:db8::9%4]:22":   "2001:db8::9%4 names a network interface",
		"web.example%en0:22":   "web.example%en0 names a network interface",

		// an IPv6 address that leads to an IPv4 one: judged by it, or refused
		// when the gate cannot read it
		"[64:ff9b::7f00:1]:22":                      "64:ff9b::7f00:1 is this computer", // NAT64 of 127.0.0.1
		"[64:ff9b::a9fe:a9fe]:80":                   "64:ff9b::a9fe:a9fe is this computer",
		"[64:ff9b::c0a8:10a]:22":                    "64:ff9b::c0a8:10a is this computer", // its own LAN address
		"[::ffff:0:7f00:1]:22":                      "::ffff:0:7f00:1 is this computer",   // SIIT
		"[64:ff9b:1::a00:5]:22":                     "64:ff9b:1::a00:5 is this computer",  // local NAT64
		"[2002:7f00:1::]:22":                        "2002:7f00:1:: is this computer",     // 6to4
		"[2002:cb00:7105::1]:22":                    "2002:cb00:7105::1 is this computer",
		"[2001:0:4136:e378:8000:63bf:3fff:fdd2]:22": "2001:0:4136:e378:8000:63bf:3fff:fdd2 is this computer", // Teredo
		"nat64.example:22":                          "nat64.example is this computer",
	}
	for addr, msg := range refused {
		d := &gateDialStub{}
		_, err := gateDial(d.dial)(context.Background(), "tcp", addr)
		var e *out.Error
		if !errors.As(err, &e) || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, msg) {
			t.Errorf("%s: %v, want SSH_GATE_REFUSED %q", addr, err, msg)
		}
		if len(d.asked) != 0 {
			t.Errorf("%s: dialed %q", addr, d.asked)
		}
	}
	d := &gateDialStub{}
	if _, err := gateDial(d.dial)(context.Background(), "unix", "/run/postgresql/.s.PGSQL.5432"); err == nil || len(d.asked) != 0 {
		t.Errorf("a socket here: %v, dialed %q", err, d.asked)
	}
}

// When this computer cannot list its own addresses, the gate cannot tell
// any address from its own: it refuses them all.
func TestGateDialRefusesWithoutOwnAddresses(t *testing.T) {
	saved := gateInterfaces
	t.Cleanup(func() { gateInterfaces = saved })
	gateInterfaces = func() ([]gateIface, error) { return nil, errors.New("route socket: permission denied") }
	gateStubDNS(t, map[string][][]net.IP{"web.example": {ips("203.0.113.5")}})
	for _, addr := range []string{"web.example:22", "203.0.113.9:22", "[2001:db8::9]:22", "[fe80::1%en0]:22"} {
		if h, _, _ := net.SplitHostPort(addr); !gateHereOrUnknown(h) {
			t.Errorf("%s: the gate check allows it", h)
		}
		d := &gateDialStub{}
		if _, err := gateDial(d.dial)(context.Background(), "tcp", addr); err == nil || len(d.asked) != 0 {
			t.Errorf("%s: %v, dialed %q", addr, err, d.asked)
		}
	}
}

// The dial judges its own lookup, not the gate check's: a name that
// answered public to the check and answers loopback to the dial is
// refused at the dial (it never connects to the check's answer). A public
// name is dialed by the IPs this lookup judged, in order, never by the name
// (which would resolve again).
func TestGateDialJudgesItsOwnLookup(t *testing.T) {
	gateStubInterfaces(t)
	asked := gateStubDNS(t, map[string][][]net.IP{
		"rebind.example": {ips("203.0.113.5"), ips("127.0.0.1")},
		"two.example":    {ips("203.0.113.5", "2001:db8::6")},
	})
	if gateHereOrUnknown("rebind.example") {
		t.Fatal("rebind.example: the gate's first answer is public")
	}
	d := &gateDialStub{}
	if _, err := gateDial(d.dial)(context.Background(), "tcp", "rebind.example:22"); err == nil || len(d.asked) != 0 {
		t.Errorf("rebinding: %v, dialed %q", err, d.asked)
	}
	d = &gateDialStub{fail: map[string]bool{"203.0.113.5:443": true}}
	c, err := gateDial(d.dial)(context.Background(), "tcp", "Two.Example.:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if want := []string{"tcp 203.0.113.5:443", "tcp [2001:db8::6]:443"}; !slices.Equal(d.asked, want) {
		t.Errorf("dialed %q, want %q", d.asked, want)
	}
	if asked["two.example"] != 1 {
		t.Errorf("two.example looked up %d times, want once", asked["two.example"])
	}
	for _, addr := range []string{"203.0.113.9:22", "192.168.2.255:22", "10.9.9.1:22", "[2001:db8::9]:22", "100.64.0.9:22", "[fd00:ec3::253]:22", "[64:ff9b::cb00:7105]:22", "[2001:db8:0:1::9]:22"} {
		d := &gateDialStub{}
		if _, err := gateDial(d.dial)(context.Background(), "tcp", addr); err != nil || !slices.Equal(d.asked, []string{"tcp " + addr}) {
			t.Errorf("%s: %v, dialed %q", addr, err, d.asked)
		}
	}
}

// A dead first address (an IPv6 black hole) gets only its share of the
// time left, so the next address still connects before the context ends.
func TestGateDialSharesTheTime(t *testing.T) {
	gateStubInterfaces(t)
	gateStubDNS(t, map[string][][]net.IP{"dual.example": {ips("2001:db8::6", "203.0.113.5")}})
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		if addr == "[2001:db8::6]:443" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, s := net.Pipe()
		s.Close()
		return c, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	c, err := gateDial(dial)(ctx, "tcp", "dual.example:443")
	if err != nil {
		t.Fatalf("the second address did not get its turn: %v", err)
	}
	c.Close()
}

// Only a run for a key dials through the gate: a person's and an AI
// agent's runs dial as before (no dialer: the default).
func TestGateDialOnlyForKeys(t *testing.T) {
	st := &store.State{}
	for who, env := range map[string]map[string]string{
		"person": {"USER": "ana"}, "agent": {"KOMANDO_AGENT": "x"},
	} {
		cl := newCall(engine.Call{Program: "komando", LookupEnv: envOf(env, &sync.Map{}), Terminal: who == "person"}, nil)
		if gateDialFor(cl, 0) != nil || sshOpts(cl, st).Dial != nil {
			t.Errorf("%s: dials through the gate", who)
		}
	}
	for who, cl := range map[string]*call{
		"key":       newCall(engine.Call{Program: "komando", LookupEnv: envOf(map[string]string{gateEnv: "phone"}, &sync.Map{})}, nil),
		"key shell": newCall(engine.Call{Program: "komando", LookupEnv: envOf(nil, &sync.Map{})}, nil),
	} {
		if who == "key shell" {
			cl.asAgent("phone")
		}
		for name, dial := range map[string]func(context.Context, string, string) (net.Conn, error){
			"gateDialFor": gateDialFor(cl, 0), "sshOpts": sshOpts(cl, st).Dial,
		} {
			if dial == nil {
				t.Errorf("%s: %s has no gate dialer", who, name)
				continue
			}
			var e *out.Error
			if _, err := dial(context.Background(), "tcp", "127.0.0.1:22"); !errors.As(err, &e) || e.Code != "SSH_GATE_REFUSED" {
				t.Errorf("%s: %s dialed 127.0.0.1: %v", who, name, err)
			}
		}
	}
}

// reviewedDialSites are the places in komando's code that open a
// connection from this computer by themselves (gateDialSites), and the
// calls of gateDialFor, per file and function ("" for package level). A
// run for a key dials only through gateDial; a new site, or one moved to
// another function, must say how it stays there before this list changes.
// Why each is safe:
var reviewedDialSites = map[string]int{
	// the gate's dialer, and the two that put it in for a key's run
	"cli/sshgate_dial.go gateDialFor": 1,
	"cli/common.go sshOpts":           1, // sshx's first step
	"cli/conn_access.go openAccess":   1, // a conn without --via
	// the default when the caller gives no dialer; a key's run always gives
	// one (sshOpts, openAccess), so these dial for a person only. An
	// http.Transport here gets the caller's dialer right after it is made.
	"sshx/shared.go openFirst": 1, "cli/conn_resolve.go pinDial": 1, "cli/conn.go testConn": 1,
	"cachex/cachex.go redisDialer": 1, "cachex/memcache.go openMemcache": 1, "queuex/queuex.go dialer": 1,
	"queuex/rabbitmq/rabbitmq.go Open": 1, "queuex/nats/nats.go *Nats.options": 1, "queuex/sqs/sqs.go OpenKeys": 1,
	"queuex/pubsub/pubsub.go Open": 1, "winrm/winrm.go New": 1, "storex/smb.go OpenSMB": 1, "storex/ftp.go OpenFTP": 1,
	"dbx/clickhouse.go openClickHouse": 2, "dbx/bigquery.go openBigQuery": 2, "dbx/snowflake.go openSnowflake": 2,
	"registry/registry.go New": 2, "kube/kube.go New": 1, "kube/spdy.go *Client.dialSPDY": 1,
	"kube/stream.go *Client.dialWS": 1, // takes the transport's dialer: the gate's in a key's run
	// a library handed a host and the caller's dialer: always (Redis, Kafka,
	// NATS, FTP, S3, a socks proxy's way out), or when there is one, which a
	// key's run always gives (Postgres, MySQL, SQL Server, Oracle, Mongo)
	"cachex/cachex.go Open": 3, "queuex/queuex.go Open": 1, "queuex/queuex.go *Kafka.client": 1, "queuex/nats/nats.go Open": 1,
	"storex/ftp.go loginFTP": 1, "storex/storex.go OpenS3Creds": 1, "transport/proxy.go Dial": 1,
	"dbx/dbx.go Open": 2, "dbx/mysql.go openMySQL": 1, "dbx/sqlserver.go openSQLServer": 1,
	"dbx/oracle.go *oracleConnector.Connect": 1, "dbx/mongo.go OpenMongo": 1,
	// minio without the dialer, in no key's run: ListBuckets serves only
	// `import aws` (the gate refuses import), LinkAt signs here and sends nothing
	"storex/storex.go ListBuckets": 1, "storex/storex.go *s3Bucket.LinkAt": 1,
	// a socket on this computer komando itself uses: ssh-agent, a held login
	"sshx/auth.go openAgent": 1, "sshx/held.go dialHeld": 1, "cli/host_sshagent.go ": 1,
	// a VPN's own connection and the dials through it (the C655 residual row)
	"netx/netx.go OpenDirect": 4, "netx/netx.go sessionDialer": 1, "netx/netx.go socksDialer": 2,
	"netx/httpproxy.go openHTTPProxy": 1, "openvpn/client.go Connect": 1, "ipsec/transport.go newTransport": 1,
	"ipsec/transport.go *udpTransport.startNATT": 1, "sslvpn/sslvpn.go dialTLSWith": 1, "sslvpn/sslvpn.go httpClient": 1,
	"cli/vpn_status.go vpnReachable": 1, "cli/vpn_session.go listening": 1,
	// no target a key names: the audit sink, cloud sign-in, a test proxy
	"cli/audit_syslog.go deliver": 2, "transport/http.go HTTP": 1, "cloud/azure.go ": 1, "cloud/ssm.go SSMDial": 1,
	"transport/proxytest/proxytest.go *Proxy.serve": 1,
	// host tunnel start: a change no key runs (gateOnServers)
	"cli/tunnel.go tunnelServeCmd": 1,
}

// Every place that opens a connection by itself is one reviewedDialSites
// lists, by file and function: a new one, or one moved to another
// function, fails here until someone decides how a key's run reaches it
// (C655).
func TestDialSitesAreReviewed(t *testing.T) {
	got := map[string]int{}
	fset := token.NewFileSet()
	err := filepath.WalkDir("..", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, ".."+string(filepath.Separator)))
		for fn, n := range gateDialSites(file) {
			got[rel+" "+fn] += n
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var sites []string
	for s := range got {
		sites = append(sites, s)
	}
	for s := range reviewedDialSites {
		if _, ok := got[s]; !ok {
			sites = append(sites, s)
		}
	}
	sort.Strings(sites)
	for _, s := range sites {
		if got[s] != reviewedDialSites[s] {
			t.Errorf("%q opens connections at %d places, the reviewed count is %d: decide how a key's run reaches it (gateDial), then update reviewedDialSites", s, got[s], reviewedDialSites[s])
		}
	}
}

// gateDialSites counts, per function of file ("" for package level), the
// places that open a connection by themselves or put the gate's dialer in:
// a net, tls or websocket Dialer, an http.Transport or http.Client (a
// literal, new(), a var; a Transport literal only without its own Dial
// field, a Client literal only without its own Transport), a Dial field
// set after to nil or to another package's function, a Transport set after
// to nil, a net or tls Dial call,
// http.DefaultClient, http.DefaultTransport, websocket.DefaultDialer,
// http.Get and the like, a library function that dials the host it is
// handed (gateLibDials), and gateDialFor. An import is read by its path, so
// an alias counts too.
func gateDialSites(file *ast.File) map[string]int {
	imports := map[string]string{} // local name -> path
	for _, im := range file.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		name := gateImportName(path)
		if im.Name != nil {
			name = im.Name.Name
		}
		imports[name] = path
	}
	is := func(e ast.Expr, path string, names ...string) bool {
		s, ok := e.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := s.X.(*ast.Ident)
		return ok && imports[id.Name] == path && (len(names) == 0 || slices.Contains(names, s.Sel.Name))
	}
	const netPkg, tlsPkg, httpPkg, wsPkg = "net", "crypto/tls", "net/http", "github.com/gorilla/websocket"
	dialer := func(e ast.Expr) bool {
		return is(e, netPkg, "Dialer") || is(e, tlsPkg, "Dialer") || is(e, wsPkg, "Dialer") || is(e, httpPkg, "Transport", "Client")
	}
	// own: a dialer or transport the caller made, not nil and not another package's
	own := func(v ast.Expr) bool {
		if id, ok := v.(*ast.Ident); ok {
			return id.Name != "nil"
		}
		s, ok := v.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := s.X.(*ast.Ident)
		return !ok || imports[id.Name] == ""
	}
	// sets: field "Dial" is any Dial* hook; "DialContext" is the plain dial
	// (Dial or DialContext), which every connection uses unless DialTLS* is set
	sets := func(e ast.Expr, field string) bool {
		var name string
		switch k := e.(type) {
		case *ast.Ident:
			name = k.Name
		case *ast.SelectorExpr:
			name = k.Sel.Name
		}
		switch field {
		case "Dial":
			return strings.HasPrefix(name, "Dial")
		case "DialContext":
			return name == "Dial" || name == "DialContext"
		}
		return name == field
	}
	setsOwn := func(field string) func(ast.Expr) bool {
		return func(e ast.Expr) bool {
			kv, ok := e.(*ast.KeyValueExpr)
			return ok && sets(kv.Key, field) && own(kv.Value)
		}
	}
	lib := func(f ast.Expr, args []ast.Expr) bool {
		for path, l := range gateLibDials {
			if is(f, path, l.funcs...) {
				return path != "database/sql" || len(args) == 0 || types.ExprString(args[0]) != `"sqlite"` // a file
			}
		}
		return false
	}
	site := func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			switch {
			case is(n.Type, httpPkg, "Transport"): // its own plain dial, and no Dial* hook of another's
				return !slices.ContainsFunc(n.Elts, setsOwn("DialContext")) || slices.ContainsFunc(n.Elts, func(e ast.Expr) bool {
					kv, ok := e.(*ast.KeyValueExpr)
					return ok && sets(kv.Key, "Dial") && !own(kv.Value)
				})
			case is(n.Type, httpPkg, "Client"):
				return !slices.ContainsFunc(n.Elts, setsOwn("Transport"))
			}
			return dialer(n.Type)
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				if _, ok := l.(*ast.SelectorExpr); ok && i < len(n.Rhs) &&
					(sets(l, "Dial") && !own(n.Rhs[i]) || sets(l, "Transport") && types.ExprString(n.Rhs[i]) == "nil") {
					return true
				}
			}
			return false
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok {
				return id.Name == "gateDialFor" || id.Name == "new" && len(n.Args) == 1 && dialer(n.Args[0])
			}
			s, ok := n.Fun.(*ast.SelectorExpr)
			return ok && (is(s, netPkg) || is(s, tlsPkg)) && strings.HasPrefix(s.Sel.Name, "Dial") ||
				is(n.Fun, httpPkg, "Get", "Head", "Post", "PostForm") || lib(n.Fun, n.Args)
		case *ast.SelectorExpr:
			return is(n, httpPkg, "DefaultClient", "DefaultTransport") || is(n, wsPkg, "DefaultDialer")
		case *ast.ValueSpec:
			return n.Type != nil && len(n.Values) == 0 && dialer(n.Type)
		}
		return false
	}
	res := map[string]int{}
	for _, d := range file.Decls {
		fn := ""
		if f, ok := d.(*ast.FuncDecl); ok {
			fn = f.Name.Name
			if f.Recv != nil && len(f.Recv.List) == 1 {
				fn = types.ExprString(f.Recv.List[0].Type) + "." + fn
			}
		}
		ast.Inspect(d, func(n ast.Node) bool {
			if site(n) {
				res[fn]++
			}
			return true
		})
	}
	return res
}

// gateLibDials are the functions of other libraries that connect to a host
// they are handed, by import path, with the name the package declares.
var gateLibDials = map[string]struct {
	name  string
	funcs []string
}{
	"database/sql":                         {"sql", []string{"Open"}},
	"github.com/go-sql-driver/mysql":       {"mysql", []string{"NewConnector"}},
	"github.com/jackc/pgx/v5":              {"pgx", []string{"Connect", "ConnectConfig"}},
	"github.com/jackc/pgx/v5/pgconn":       {"pgconn", []string{"Connect", "ConnectConfig"}},
	"github.com/jackc/pgx/v5/stdlib":       {"stdlib", []string{"OpenDB"}},
	"github.com/jlaffaye/ftp":              {"ftp", []string{"Dial", "DialTimeout", "Connect"}},
	"github.com/microsoft/go-mssqldb":      {"mssql", []string{"NewConnector", "NewConnectorConfig", "NewConnectorWithAccessTokenProvider"}},
	"github.com/minio/minio-go/v7":         {"minio", []string{"New"}},
	"github.com/nats-io/nats.go":           {"nats", []string{"Connect"}},
	"github.com/rabbitmq/amqp091-go":       {"amqp091", []string{"Dial", "DialConfig", "DialTLS", "DialTLS_ExternalAuth"}},
	"github.com/redis/go-redis/v9":         {"redis", []string{"NewClient", "NewClusterClient", "NewFailoverClient", "NewFailoverClusterClient", "NewRing", "NewSentinelClient", "NewUniversalClient"}},
	"github.com/sijms/go-ora/v2":           {"go_ora", []string{"NewConnection", "NewConnector"}},
	"github.com/twmb/franz-go/pkg/kgo":     {"kgo", []string{"NewClient"}},
	"go.mongodb.org/mongo-driver/v2/mongo": {"mongo", []string{"Connect"}},
	"golang.org/x/crypto/ssh":              {"ssh", []string{"Dial"}},
	"golang.org/x/net/proxy":               {"proxy", []string{"Dial", "FromEnvironment", "FromEnvironmentUsing", "FromURL", "SOCKS5"}},
	"google.golang.org/grpc":               {"grpc", []string{"Dial", "DialContext", "NewClient"}},
}

// gateImportName is the name an import without an alias goes by.
func gateImportName(path string) string {
	if l, ok := gateLibDials[path]; ok {
		return l.name
	}
	return path[strings.LastIndex(path, "/")+1:]
}

// The scan finds each form, under an aliased import too, and names the
// function it is in.
func TestGateDialSitesFindsEachForm(t *testing.T) {
	src := `package x

import (
	"crypto/tls"
	"database/sql"
	stdnet "net"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/jlaffaye/ftp"
	"github.com/minio/minio-go/v7"
	"github.com/nats-io/nats.go"
	"github.com/pion/dtls/v3"
	"github.com/redis/go-redis/v9"
	kafka "github.com/twmb/franz-go/pkg/kgo"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
	"tailscale.com/tsnet"
)

var pkgDialer stdnet.Dialer

func literal()          { _ = &stdnet.Dialer{} }
func newDialer()        { _ = new(stdnet.Dialer) }
func varDialer()        { var d stdnet.Dialer; _ = d }
func dialCall()         { stdnet.Dial("tcp", "a:1") }
func listenUDP()        { stdnet.ListenUDP("udp", nil) }
func listenPacket()     { stdnet.ListenPacket("udp", ":0") }
func dtlsClient()       { dtls.ClientWithOptions(nil, nil) }
func dtlsDial()         { dtls.Dial("udp", nil, nil) }
func tsnetServer()      { _ = &tsnet.Server{} }
func tlsDialer()        { _ = tls.Dialer{} }
func tlsDial()          { tls.Dial("tcp", "a:1", nil) }
func transport()        { _ = &http.Transport{} }
func newTransport()     { _ = new(http.Transport) }
func ownDial(d dialer)  { _ = &http.Transport{DialContext: d} }
func nilDial()          { _ = &http.Transport{DialContext: nil} }
func otherDial()        { _ = &http.Transport{DialContext: proxy.Dial} }
func tlsOnly(d dialer)  { _ = &http.Transport{DialTLSContext: d} }
func ownBoth(d dialer)  { _ = &http.Transport{Dial: d, DialTLSContext: d} }
func mixedTLS(d dialer) { _ = &http.Transport{DialContext: d, DialTLSContext: proxy.Dial} }
func setAfter(d dialer) { t := &http.Transport{DialContext: d}; t.DialContext = nil }
func setOther(t *tr)    { t.Dial = proxy.Dial }
func setNilTr(c *cl)    { c.Transport = nil }
func client()           { _ = &http.Client{} }
func clientNil()        { _ = &http.Client{Transport: nil} }
func clientOwn(t *tr)   { _ = &http.Client{Transport: t} }
func newClient()        { _ = new(http.Client) }
func sshDial()          { ssh.Dial("tcp", "a:22", nil) }
func ftpDial()          { ftp.Dial("a:21") }
func minioNew()         { minio.New("a", nil) }
func redisNew()         { redis.NewClient(nil) }
func mongoConnect()     { mongo.Connect() }
func kgoNew()           { kafka.NewClient() }
func natsConnect()      { nats.Connect("a") }
func sqlOpen()          { sql.Open("pgx", "postgres://a") }
func sqliteOpen()       { sql.Open("sqlite", "f.db") }
func grpcNew()          { grpc.NewClient("a:1") }
func socks()            { proxy.SOCKS5("tcp", "a:1", nil, nil) }
func defaultClient()    { _ = http.DefaultClient }
func defaultTransport() { _ = http.DefaultTransport }
func get()              { http.Get("https://a") }
func wsDialer()         { _ = websocket.Dialer{} }
func wsDefault()        { _ = websocket.DefaultDialer }
func gate()             { gateDialFor(nil, 0) }
func notImported()      { net.Dial("tcp", "a:1") }

type c struct{}

func (*c) method() { _ = &stdnet.Dialer{}; _ = stdnet.JoinHostPort("a", "1") }
`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"": 1, "literal": 1, "newDialer": 1, "varDialer": 1, "dialCall": 1, "listenUDP": 1, "listenPacket": 1, "dtlsClient": 1, "dtlsDial": 1, "tsnetServer": 1, "tlsDialer": 1, "tlsDial": 1,
		"transport": 1, "newTransport": 1, "defaultClient": 1, "defaultTransport": 1, "get": 1, "wsDialer": 1, "wsDefault": 1,
		"gate": 1, "*c.method": 1, "nilDial": 1, "otherDial": 1, "tlsOnly": 1, "mixedTLS": 1, "setAfter": 1, "setOther": 1, "setNilTr": 1, "client": 1, "clientNil": 1,
		"newClient": 1, "sshDial": 1, "ftpDial": 1, "minioNew": 1, "redisNew": 1, "mongoConnect": 1, "kgoNew": 1,
		"natsConnect": 1, "sqlOpen": 1, "grpcNew": 1, "socks": 1}
	if got := gateDialSites(f); !maps.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}
