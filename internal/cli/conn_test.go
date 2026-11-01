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
		s.Conns[name] = &store.Conn{Name: name, URL: url, Groups: groups, Tags: tags, Protected: protected}
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
	// hosts and conns do not leak into each other's selectors
	if _, err := resolveConns(st, "web-1"); err == nil || toErr(err).Code != "CONN_NOT_FOUND" {
		t.Errorf("expected CONN_NOT_FOUND, got %v", err)
	}
	if hs, _ := resolveTargets(st, "@db"); len(hs) != 1 || hs[0].Name != "db-1" {
		t.Errorf("host selector picked up conns: %v", hostNames(hs))
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
		err := guardConns(c.conns, c.v)
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
