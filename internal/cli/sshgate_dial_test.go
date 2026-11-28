package cli

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

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

// gateOwnAddr is one of this computer's own addresses that is neither
// loopback nor link-local, or "" when it has none.
func gateOwnAddr() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	return ""
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
	own := gateOwnAddr()
	if own != "" {
		answers["own.example"] = [][]net.IP{ips(own)}
	}
	gateStubDNS(t, answers)
	want := map[string]bool{
		"nx.example": true, "err.example": true, "empty.example": true, // cannot tell
		"mixed.example": true, "mixed6.example": true, "mapped.example": true, "zero.example": true, "unspec.example": true,
		"mixed.example:5432": true,
		"web.example":        false, "two.example": false, "public6.example": false, "web.example:22": false,
		"rebind.example": false, // its first answer: the dial judges its own (TestGateDialPinsTheJudgedAnswer)
	}
	if own != "" {
		want["own.example"] = true
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
			"ssmhost": {Address: "i-0abc123", ProxyCommand: "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p"},
			"pcloop":  {Address: "localhost", ProxyCommand: "nc %h %p"},
		} {
			h.Name, h.User = n, "u"
			st.Hosts[n] = &h
		}
		st.Conns["pgnx"] = &store.Conn{Name: "pgnx", Kind: "postgres", URL: "postgres://u@nx.example/x"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	gateStubDNS(t, map[string][][]net.IP{"web.example": {ips("203.0.113.5")}, "mixed.example": {ips("203.0.113.5", "127.0.0.1")}})
	const R = "SSH_GATE_REFUSED"
	for line, want := range map[string]string{
		"logs nxhost":              R,
		"logs errhost":             R,
		"logs mixedhost":           R,
		"db query pgnx 'select 1'": R,
		"logs vpninner":            R, // a name through a VPN: the gate cannot tell where the VPN goes
		"logs innerme":             R, // the jump host is this computer
		"logs pubhost":             "",
		"logs inner":               "", // the jump host bastion resolves it, far from here
		"logs pcloop":              R,
		"logs ssmhost":             "", // its proxy command connects: an instance ID resolves nowhere
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
		"empty.example":  {nil},
	}
	own := gateOwnAddr()
	if own != "" {
		answers["own.example"] = [][]net.IP{ips(own)}
	}
	gateStubDNS(t, answers)
	refused := map[string]string{
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
	}
	if own != "" {
		refused["own.example:22"] = "own.example is this computer"
		refused[net.JoinHostPort(own, "22")] = own + " is this computer"
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

// The address the dial connects to is the one it judged: a name that
// answers a public address to the gate and loopback to the dial is
// refused at the dial, and a public name is dialed by its judged IPs, in
// order, never by the name (which would resolve again).
func TestGateDialPinsTheJudgedAnswer(t *testing.T) {
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
	for _, addr := range []string{"203.0.113.9:22", "[fe80::1%en0]:22", "[2001:db8::9]:22"} {
		d := &gateDialStub{}
		if _, err := gateDial(d.dial)(context.Background(), "tcp", addr); err != nil || !slices.Equal(d.asked, []string{"tcp " + addr}) {
			t.Errorf("%s: %v, dialed %q", addr, err, d.asked)
		}
	}
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
// connection from this computer by themselves (a net.Dialer, a net or tls
// Dial, a websocket.Dialer), and the calls of gateDialFor, per file. A run
// for a key dials only through gateDial; a new site must say how it stays
// there before this count changes. Why each is safe:
var reviewedDialSites = map[string]int{
	// the gate's dialer, and the two that put it in for a key's run
	"cli/sshgate_dial.go": 1,
	"cli/common.go":       1, // sshOpts: sshx's first step
	"cli/conn_access.go":  1, // openAccess: a conn without --via
	// the default when the caller gives no dialer; a key's run always gives
	// one (sshOpts, openAccess), so these dial for a person only
	"sshx/shared.go": 1, "cli/conn_resolve.go": 1, "cli/conn.go": 1,
	"cachex/cachex.go": 1, "cachex/memcache.go": 1, "queuex/queuex.go": 1, "queuex/rabbitmq/rabbitmq.go": 1,
	"queuex/nats/nats.go": 1, "queuex/sqs/sqs.go": 1, "queuex/pubsub/pubsub.go": 1, "winrm/winrm.go": 1,
	"storex/smb.go": 1, "storex/ftp.go": 1, "dbx/clickhouse.go": 1, "dbx/bigquery.go": 1, "dbx/snowflake.go": 1,
	"registry/registry.go": 1, "kube/kube.go": 1, "kube/spdy.go": 1,
	"kube/stream.go": 1, // takes the transport's dialer: the gate's in a key's run
	// a socket on this computer komando itself uses: ssh-agent, a held login
	"sshx/auth.go": 1, "sshx/held.go": 1, "cli/host_sshagent.go": 1,
	// a VPN's own connection and the dials through it (the C655 residual row)
	"netx/netx.go": 5, "netx/httpproxy.go": 1, "openvpn/client.go": 1, "ipsec/transport.go": 2, "sslvpn/sslvpn.go": 1,
	"cli/vpn_status.go": 1, "cli/vpn_session.go": 1,
	// no target a key names: the audit sink, cloud sign-in, a test proxy
	"cli/audit_syslog.go": 2, "transport/http.go": 1, "cloud/azure.go": 1, "cloud/ssm.go": 1, "transport/proxytest/proxytest.go": 1,
	// host tunnel start: a change no key runs (gateOnServers)
	"cli/tunnel.go": 1,
}

// Every place that opens a connection by itself is one reviewedDialSites
// lists: a new one fails here until someone decides how a key's run
// reaches it (C655).
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
		ast.Inspect(file, func(n ast.Node) bool {
			if gateDialSite(n) {
				got[rel]++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for f := range got {
		files = append(files, f)
	}
	for f := range reviewedDialSites {
		if _, ok := got[f]; !ok {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	for _, f := range files {
		if got[f] != reviewedDialSites[f] {
			t.Errorf("%s opens connections at %d places, the reviewed count is %d: decide how a key's run reaches it (gateDial), then update reviewedDialSites", f, got[f], reviewedDialSites[f])
		}
	}
}

// gateDialSite: n opens a connection by itself, or puts the gate's dialer in.
func gateDialSite(n ast.Node) bool {
	sel := func(e ast.Expr) (string, string) {
		s, ok := e.(*ast.SelectorExpr)
		if !ok {
			if id, ok := e.(*ast.Ident); ok {
				return "", id.Name
			}
			return "", ""
		}
		x, _ := s.X.(*ast.Ident)
		if x == nil {
			return "", s.Sel.Name
		}
		return x.Name, s.Sel.Name
	}
	switch n := n.(type) {
	case *ast.CompositeLit:
		pkg, name := sel(n.Type)
		return name == "Dialer" && (pkg == "net" || pkg == "websocket")
	case *ast.CallExpr:
		pkg, name := sel(n.Fun)
		switch pkg {
		case "net":
			return strings.HasPrefix(name, "Dial")
		case "tls":
			return strings.HasPrefix(name, "Dial")
		case "":
			return name == "gateDialFor"
		}
	}
	return false
}
