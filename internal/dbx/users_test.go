package dbx

import (
	"context"
	"strings"
	"testing"
)

func TestScramVerifier(t *testing.T) {
	v, err := scramVerifier("pencil", []byte("0123456789abcdef"), 4096)
	if err != nil || !strings.HasPrefix(v, "SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg==$") || strings.Count(v, ":") != 2 {
		t.Errorf("verifier %q %v", v, err)
	}
	a, _ := newScram("pencil")
	b, _ := newScram("pencil")
	if a == b {
		t.Error("each verifier has its own salt")
	}
}

func TestUserSQLHidesThePassword(t *testing.T) {
	stmt, shown, err := userSQL(context.Background(), nil, "postgres", "add", UserSpec{Name: "app_ro", Password: "s3cr'et"})
	if err != nil || !strings.HasPrefix(stmt, `create role "app_ro" login password 'SCRAM-SHA-256$`) || strings.Contains(stmt, "s3cr") {
		t.Errorf("postgres %q %v", stmt, err)
	}
	if shown != `create role "app_ro" login password '[hidden]'` {
		t.Errorf("shown %q", shown)
	}
	stmt, shown, _ = userSQL(context.Background(), nil, "mysql", "add", UserSpec{Name: "app", Password: `a'b\c`})
	if stmt != `create user 'app'@'%' identified by 'a''b\\c'` || strings.Contains(shown, "a''b") {
		t.Errorf("mysql %q / %q", stmt, shown)
	}
	for _, bad := range []string{"", "1abc", "a b", `x";drop`, strings.Repeat("a", 64)} {
		if _, _, err := userSQL(context.Background(), nil, "postgres", "rm", UserSpec{Name: bad}); err == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
}

func TestGrantSQL(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		kind string
		g    Grant
		want string
	}{
		{"postgres", Grant{User: "ro", Privs: []string{"select"}, On: "all-tables:public"}, `grant SELECT on all tables in schema "public" to "ro"`},
		{"postgres", Grant{User: "ro", Privs: []string{"SELECT", "insert"}, On: "table:shop.orders"}, `grant SELECT, INSERT on table "shop"."orders" to "ro"`},
		{"postgres", Grant{User: "ro", Privs: []string{"CONNECT"}, On: "database:app", Revoke: true}, `revoke CONNECT on database "app" from "ro"`},
		{"postgres", Grant{User: "ana", Role: "readers"}, `grant "readers" to "ana"`},
		{"mysql", Grant{User: "app", Privs: []string{"SELECT"}, On: "shop.*"}, "grant SELECT on `shop`.* to 'app'@'%'"},
		{"mysql", Grant{User: "app", Host: "10.0.%", Privs: []string{"ALL"}, On: "*.*", Revoke: true}, "revoke ALL on *.* from 'app'@'10.0.%'"},
	} {
		got, err := GrantSQL(ctx, nil, c.kind, c.g)
		if err != nil || got != c.want {
			t.Errorf("%+v: %q %v", c.g, got, err)
		}
	}
	for _, g := range []Grant{
		{User: "ro", Privs: []string{"SELECT; drop table x"}, On: "database:app"},
		{User: "ro", Privs: []string{"SELECT"}, On: "table:a.b.c"},
		{User: "ro", Privs: []string{"SELECT"}, On: "database:a\"b"},
		{User: "ro", Privs: []string{"SELECT"}, On: "view:x"},
	} {
		if _, err := GrantSQL(ctx, nil, "postgres", g); err == nil {
			t.Errorf("accepted %+v", g)
		}
	}
}
