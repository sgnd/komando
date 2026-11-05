package cli

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// A protected server stays protected however a change reaches it: an
// ad-hoc user@address written another way, or a second inventory name
// (added before it, or imported) for the same address.
func TestProtectedFollowsTheAddressAtRunTime(t *testing.T) {
	cases := []struct{ protected, target string }{
		{"localhost", "root@127.0.0.1"},              // a name and its IP
		{"10.0.0.5", "root@::ffff:10.0.0.5"},         // IPv4-mapped IPv6
		{"2001:db8::1", "root@2001:db8:0:0:0:0:0:1"}, // IPv6 written out
		{"2001:db8::1", "2001:0db8::0001"},           // leading zeros
		{"DB.Example.", "root@db.example"},           // case and the root dot
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			st := &store.State{Hosts: map[string]*store.Host{
				"prod": {Name: "prod", Address: tc.protected, User: "root", Protected: true},
			}}
			m, err := matchSelector(st, tc.target)
			if err != nil || len(m.Hosts) != 1 {
				t.Fatalf("%s: %v %v", tc.target, m, err)
			}
			if err := guard(st, m.Hosts, "systemctl restart postgresql", true); err == nil || toErr(err).Code != "PROTECTED_HOST" {
				t.Errorf("guard: %v", err)
			}
		})
	}
	// inventory addresses (komando stores them without brackets)
	for _, a := range []string{"[::ffff:10.0.0.5]", "0:0:0:0:0:ffff:a00:5", "10.0.0.5."} {
		st := &store.State{Hosts: map[string]*store.Host{"prod": {Name: "prod", Address: "10.0.0.5", Protected: true}}}
		if err := guard(st, []*store.Host{{Name: "alias", Address: a}}, "", true); err == nil {
			t.Errorf("%s is prod", a)
		}
	}
	other := &store.State{Hosts: map[string]*store.Host{"prod": {Name: "prod", Address: "10.0.0.5", Protected: true}}}
	if err := guard(other, []*store.Host{{Name: "x", Address: "10.0.0.6"}}, "", true); err != nil {
		t.Errorf("another server is not protected: %v", err)
	}
}

func TestProtectedTwinsWhateverTheOrder(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "db1", "root@127.0.0.1") // added before the protected name
	mustRun(t, "host", "add", "prod", "root@localhost", "--protected")
	d := mustRun(t, "exec", "db1", "systemctl restart postgresql", "--dry-run")
	if d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("db1 is prod: %v", d)
	}

	// host import marks a second name for a protected server protected, as host add does
	cfg := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(cfg, []byte("Host alias3\n  HostName 127.0.0.1\n  User root\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "host", "import", "--ssh-config", cfg)
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if h := st.Hosts["alias3"]; h == nil || !h.Protected {
		t.Errorf("imported twin of prod: %+v", h)
	}
}

// An import checks every host against the protected ones, but resolves
// each name once: a slow resolver (split DNS, VPN-only names) must not cost
// one lookup per imported host per protected host under the inventory lock.
func TestImportResolvesEachNameOnce(t *testing.T) {
	dnsCache.Clear()
	t.Cleanup(dnsCache.Clear)
	var mu sync.Mutex
	calls := map[string]int{}
	ips := map[string]string{"prod.internal": "10.9.0.1", "alias.internal": "10.9.0.1"}
	old := lookupHost
	lookupHost = func(_ context.Context, host string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls[host]++
		if ip, ok := ips[host]; ok {
			return []string{ip}, nil
		}
		return []string{"10.9.1." + strconv.Itoa(len(calls))}, nil
	}
	t.Cleanup(func() { lookupHost = old })
	st := &store.State{Hosts: map[string]*store.Host{
		"prod": {Name: "prod", Address: "prod.internal", User: "root", Protected: true},
	}, Keys: map[string]*store.Key{}, Vpns: map[string]*store.Vpn{}, Conns: map[string]*store.Conn{}}
	var hosts []*store.Host
	for i := range 20 {
		hosts = append(hosts, &store.Host{Name: "h" + strconv.Itoa(i), Address: "h" + strconv.Itoa(i) + ".internal", User: "root"})
	}
	hosts = append(hosts, &store.Host{Name: "alias", Address: "alias.internal", User: "root"})
	prefetchTwinIPs(st, hosts)
	v, err := vetImportHosts(st, hosts, false)
	if err != nil {
		t.Fatal(err)
	}
	for name, n := range calls {
		if n != 1 {
			t.Errorf("%s looked up %d times", name, n)
		}
	}
	if len(calls) != 22 {
		t.Errorf("%d names looked up, want 22", len(calls))
	}
	for _, h := range v.Add {
		if h.Protected != (h.Name == "alias") {
			t.Errorf("%s protected=%v", h.Name, h.Protected)
		}
	}
}
