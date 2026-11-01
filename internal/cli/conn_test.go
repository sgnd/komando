package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

func testConnState() *store.State {
	s := testState()
	s.Conns = map[string]*store.Conn{}
	add := func(name, url string, groups, tags []string, protected bool) {
		t, err := driver.Parse(url)
		if err != nil {
			panic(err)
		}
		s.Conns[name] = &store.Conn{Name: name, Kind: t.Kind.Name, URL: url, Groups: groups, Tags: tags, Protected: protected}
	}
	add("prod-db", "postgres://app@10.0.0.5/app", []string{"db"}, []string{"prod"}, true)
	add("shop-db", "mysql://shop@db.lan/shop", []string{"db"}, []string{"prod"}, false)
	add("dev-db", "sqlite:///tmp/dev.db", nil, []string{"dev"}, false)
	return s
}

func TestResolveConns(t *testing.T) {
	st := testConnState()
	cases := map[string]string{
		"prod-db":        "prod-db",
		"@db":            "prod-db,shop-db",
		"tag:prod":       "prod-db,shop-db",
		"*-db":           "dev-db,prod-db,shop-db",
		"all,!tag:prod":  "dev-db",
		"@db,!shop-db":   "prod-db",
		"dev-db,prod-db": "dev-db,prod-db",
	}
	for expr, want := range cases {
		cs, err := resolveConns(st, expr)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		var names []string
		for _, c := range cs {
			names = append(names, c.Name)
		}
		if got := strings.Join(names, ","); got != want {
			t.Errorf("%s: got %s want %s", expr, got, want)
		}
	}
	// a server name given to a conn command says which command to use
	if _, err := resolveConns(st, "web-1"); err == nil || toErr(err).Code != "NO_MATCHING_TARGETS" {
		t.Errorf("expected NO_MATCHING_TARGETS, got %v", err)
	}
	if _, err := resolveConns(st, "nope"); err == nil || toErr(err).Code != "CONN_NOT_FOUND" {
		t.Errorf("expected CONN_NOT_FOUND, got %v", err)
	}
	if _, err := resolveConns(st, "@nope"); err == nil || toErr(err).Code != "TARGET_EMPTY" {
		t.Errorf("expected TARGET_EMPTY, got %v", err)
	}
}

func TestGuardConns(t *testing.T) {
	st := testConnState()
	prod, shop := st.Conns["prod-db"], st.Conns["shop-db"]
	destructive := driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"sql-drop"}, Reasons: []string{"drops a table"}}
	cases := []struct {
		name       string
		conns      []*store.Conn
		v          driver.Verdict
		yes, allow bool
		want       string
	}{
		{"read on protected", []*store.Conn{prod}, driver.Verdict{Risk: driver.RiskRead}, false, false, ""},
		{"write on plain", []*store.Conn{shop}, driver.Verdict{Risk: driver.RiskWrite}, false, false, ""},
		{"write on protected", []*store.Conn{shop, prod}, driver.Verdict{Risk: driver.RiskWrite}, false, false, "PROTECTED_TARGET"},
		{"write on protected --yes", []*store.Conn{prod}, driver.Verdict{Risk: driver.RiskWrite}, true, false, ""},
		{"destructive on plain", []*store.Conn{shop}, destructive, false, false, "POLICY_BLOCKED"},
		{"destructive --allow-dangerous", []*store.Conn{shop}, destructive, false, true, ""},
		{"destructive on protected, only --allow-dangerous", []*store.Conn{prod}, destructive, false, true, "PROTECTED_TARGET"},
		{"destructive on protected, both flags", []*store.Conn{prod}, destructive, true, true, ""},
	}
	saved := g
	defer func() { g = saved }()
	for _, c := range cases {
		g.yes, g.allowDangerous = c.yes, c.allow
		err := guardConns(nil, c.conns, c.v)
		got := ""
		if err != nil {
			got = toErr(err).Code
			if toErr(err).Exit != 6 {
				t.Errorf("%s: exit %d, want 6", c.name, toErr(err).Exit)
			}
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestCheckConn(t *testing.T) {
	st := testConnState()
	ok := &store.Conn{Name: "x", URL: "postgres://app@10.0.0.9/app", Via: "web-1", PasswordRef: "secret:x"}
	if _, err := checkConn(st, ok); err != nil || ok.Kind != "postgres" {
		t.Errorf("valid conn rejected: %v (kind %q)", err, ok.Kind)
	}
	bad := map[string]*store.Conn{
		"HOST_NOT_FOUND":   {URL: "postgres://app@db/app", Via: "nope"},
		"USAGE":            {URL: "sqlite:///tmp/a.db", Via: "web-1"},
		"URL_HAS_PASSWORD": {URL: "postgres://app:pw@db/app"},
	}
	for code, c := range bad {
		if _, err := checkConn(st, c); err == nil || toErr(err).Code != code {
			t.Errorf("want %s, got %v", code, err)
		}
	}
	if _, err := checkConn(st, &store.Conn{URL: "postgres://app@db/app", PasswordRef: "hunter2"}); err == nil {
		t.Error("plain password accepted as --password-ref")
	}
	if kind, taken := st.NameTaken("prod-db"); !taken || kind != "conn" {
		t.Errorf("NameTaken(prod-db) = %s,%v", kind, taken)
	}
	if kind, taken := st.NameTaken("web-1"); !taken || kind != "host" {
		t.Errorf("NameTaken(web-1) = %s,%v", kind, taken)
	}
}

func TestSelectionPicksHostsAndConns(t *testing.T) {
	st := testConnState()
	names := func(sel selection) string {
		var n []string
		for _, h := range sel.Hosts {
			n = append(n, h.Name)
		}
		for _, c := range sel.Conns {
			n = append(n, c.Name)
		}
		return strings.Join(n, ",")
	}
	cases := map[string]string{
		"@db":                    "db-1,prod-db,shop-db",
		"tag:prod":               "db-1,web-1,web-2,prod-db,shop-db",
		"tag:prod,!kind:host":    "prod-db,shop-db",
		"kind:db":                "dev-db,prod-db,shop-db",
		"kind:postgres":          "prod-db",
		"kind:host,!@web":        "db-1,dev-1",
		"web-1,prod-db":          "web-1,prod-db",
		"all,!kind:db,!tag:prod": "dev-1",
	}
	for expr, want := range cases {
		sel, err := resolveSelection(st, expr)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		if got := names(sel); got != want {
			t.Errorf("%s: got %s want %s", expr, got, want)
		}
	}
	if _, err := resolveSelection(st, "kind:nosuch"); err == nil || toErr(err).Code != "USAGE" {
		t.Errorf("expected USAGE for an unknown kind, got %v", err)
	}
	if _, err := resolveSelection(st, "prod-bd"); err == nil || !strings.Contains(toErr(err).Hint, `"prod-db"`) {
		t.Errorf("expected a did-you-mean hint, got %v", err)
	}
}

func TestActionCommandsUseWhatTheyCan(t *testing.T) {
	st := testConnState()
	// exec @db runs on the server and skips the databases
	if hs, err := resolveTargets(st, "@db"); err != nil || len(hs) != 1 || hs[0].Name != "db-1" {
		t.Errorf("@db for servers: %v %v", hostNames(hs), err)
	}
	// db query kind:postgres finds the one database
	if c, err := singleConn(st, "kind:postgres", "db"); err != nil || c.Name != "prod-db" {
		t.Errorf("kind:postgres for db: %v %v", c, err)
	}
	// two databases in @db: db query needs exactly one
	if _, err := singleConn(st, "@db", "db"); err == nil || toErr(err).Code != "USAGE" {
		t.Errorf("expected USAGE for two databases, got %v", err)
	}
	// only servers picked: the hint says to use exec
	_, err := singleConn(st, "@web", "db")
	if e := toErr(err); err == nil || e.Code != "NO_MATCHING_TARGETS" || !strings.Contains(e.Hint, "komando exec") {
		t.Errorf("expected NO_MATCHING_TARGETS with an exec hint, got %v", err)
	}
	// a database given to a cache command points to `komando db`
	_, err = singleConn(st, "prod-db", "cache")
	if e := toErr(err); err == nil || e.Code != "NO_MATCHING_TARGETS" || !strings.Contains(e.Hint, "komando db") {
		t.Errorf("expected a hint to use komando db, got %v", err)
	}
}

func TestProtectionFollowsTheAddress(t *testing.T) {
	st := testConnState()
	st.Hosts["web-1"].Protected = true
	adhoc, _, err := matchSelector(st, "root@web-1.lan:22")
	if err != nil || len(adhoc) != 1 {
		t.Fatalf("ad-hoc host: %v %v", adhoc, err)
	}
	if !protectedHost(st, adhoc[0]) {
		t.Error("an ad-hoc host at a protected address must count as protected")
	}
	if protectedHost(st, &store.Host{Name: "x", Address: "web-1.lan", Port: 2222}) {
		t.Error("another port on the same address is a different server")
	}
	// prod-db is protected; a second conn to the same server is too
	alias := &store.Conn{Name: "scratch", Kind: "postgres", URL: "postgres://other@10.0.0.5/otherdb"}
	if !protectedConn(st, alias) {
		t.Error("a conn to a protected database server must count as protected")
	}
	if protectedConn(st, &store.Conn{Name: "x", Kind: "postgres", URL: "postgres://app@10.0.0.6/app"}) {
		t.Error("a different server is not protected")
	}
	if err := guardConns(st, []*store.Conn{alias}, driver.Verdict{Risk: driver.RiskWrite}); err == nil || toErr(err).Code != "PROTECTED_TARGET" {
		t.Errorf("expected PROTECTED_TARGET for the alias, got %v", err)
	}
}
