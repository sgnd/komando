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

// gateStubDNS answers for gateLookup: each name's answers in turn (the
// last one again when they run out), an error for "err.example", and
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

// gateStubInterfaces answers for gateInterfaces: lo0 (index 1, loopback,
// with fe80::1 as on macOS), en0 (index 4) and utun3 (index 9).
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
		{name: "lo0", index: 1, loopback: true, addrs: nets("127.0.0.1/8", "::1/128", "fe80::1/64")},
		{name: "en0", index: 4, addrs: nets(gateOwn+"/24", "fe80::aaaa/64", "169.254.7.7/16", "2001:db8::10/64")},
		{name: "utun3", index: 9, addrs: nets("10.9.9.0/31")}, // a point-to-point link: 10.9.9.1 is the peer
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
	gateStubDNS(t, answers)
	want := map[string]bool{
		"own.example": true, "ownll.example": true, "imds.example": true, "router.example": true, "169.254.169.254": true,
		"nx.example": true, "err.example": true, "empty.example": true, // cannot tell
		"mixed.example": true, "mixed6.example": true, "mapped.example": true, "zero.example": true, "unspec.example": true,
		"mixed.example:5432": true,
		"web.example":        false, "two.example": false, "public6.example": false, "web.example:22": false,
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
		"[fe80::aaaa%en0]:22":   "fe80::aaaa%en0 is this computer",
		"[fe80::aaaa%4]:22":     "fe80::aaaa%4 is this computer", // the zone by number
		"[fe80::1%1]:22":        "fe80::1%1 is this computer",    // 1 is lo0
		"[fe80::5%lo0]:22":      "fe80::5%lo0 is this computer",  // on the loopback link, held or not
		"[::1%en0]:22":          "::1%en0 is this computer",
		"[fe80::bbbb%en9]:22":   "fe80::bbbb%en9 is this computer", // no such interface here
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
		"[fe80::1%lo0]:22":      "fe80::1%lo0 is this computer",
		"224.0.0.1:5353":        "224.0.0.1 is this computer", // multicast reaches this computer too
		"[ff02::1%en0]:22":      "ff02::1%en0 is this computer",
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
	for _, addr := range []string{"203.0.113.9:22", "192.168.2.255:22", "10.9.9.1:22", "[2001:db8::9]:22", "100.64.0.9:22", "[fd00:ec2::253]:22"} {
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
	// a socket on this computer komando itself uses: ssh-agent, a held login
	"sshx/auth.go openAgent": 1, "sshx/held.go dialHeld": 1, "cli/host_sshagent.go ": 1,
	// a VPN's own connection and the dials through it (the C655 residual row)
	"netx/netx.go OpenDirect": 3, "netx/netx.go sessionDialer": 1, "netx/netx.go socksDialer": 1,
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
// a net, tls or websocket Dialer or an http.Transport (a literal, new(), a
// var; a Transport literal only without a Dial field), a net or tls Dial
// call, http.DefaultClient, http.DefaultTransport, websocket.DefaultDialer,
// http.Get and the like, and gateDialFor. An import is read by its path,
// so an alias counts too.
func gateDialSites(file *ast.File) map[string]int {
	imports := map[string]string{} // local name -> path
	for _, im := range file.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		name := path[strings.LastIndex(path, "/")+1:]
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
		return is(e, netPkg, "Dialer") || is(e, tlsPkg, "Dialer") || is(e, wsPkg, "Dialer") || is(e, httpPkg, "Transport")
	}
	ownDial := func(e ast.Expr) bool {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		id, ok := kv.Key.(*ast.Ident)
		return ok && strings.HasPrefix(id.Name, "Dial")
	}
	site := func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if is(n.Type, httpPkg, "Transport") {
				return !slices.ContainsFunc(n.Elts, ownDial)
			}
			return dialer(n.Type)
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok {
				return id.Name == "gateDialFor" || id.Name == "new" && len(n.Args) == 1 && dialer(n.Args[0])
			}
			s, ok := n.Fun.(*ast.SelectorExpr)
			return ok && (is(s, netPkg) || is(s, tlsPkg)) && strings.HasPrefix(s.Sel.Name, "Dial") ||
				is(n.Fun, httpPkg, "Get", "Head", "Post", "PostForm")
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

// The scan finds each form, under an aliased import too, and names the
// function it is in.
func TestGateDialSitesFindsEachForm(t *testing.T) {
	src := `package x

import (
	"crypto/tls"
	stdnet "net"
	"net/http"

	"github.com/gorilla/websocket"
)

var pkgDialer stdnet.Dialer

func literal()          { _ = &stdnet.Dialer{} }
func newDialer()        { _ = new(stdnet.Dialer) }
func varDialer()        { var d stdnet.Dialer; _ = d }
func dialCall()         { stdnet.Dial("tcp", "a:1") }
func tlsDialer()        { _ = tls.Dialer{} }
func tlsDial()          { tls.Dial("tcp", "a:1", nil) }
func transport()        { _ = &http.Transport{} }
func newTransport()     { _ = new(http.Transport) }
func ownDial()          { _ = &http.Transport{DialContext: nil} }
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
	want := map[string]int{"": 1, "literal": 1, "newDialer": 1, "varDialer": 1, "dialCall": 1, "tlsDialer": 1, "tlsDial": 1,
		"transport": 1, "newTransport": 1, "defaultClient": 1, "defaultTransport": 1, "get": 1, "wsDialer": 1, "wsDefault": 1,
		"gate": 1, "*c.method": 1}
	if got := gateDialSites(f); !maps.Equal(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}
