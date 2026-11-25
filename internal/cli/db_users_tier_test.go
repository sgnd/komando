package cli

import (
	"strings"
	"testing"
)

// db grant, db revoke, db user add and db user passwd send the statements
// that `db query` rates sql-privileges: they need the same approval.
func TestDBUserCommandsArePrivilegeChanges(t *testing.T) {
	invHome(t)
	noAgent(t)
	mustRun(t, "conn", "add", "local", "postgres://app@127.0.0.1:1/app")
	for _, args := range [][]string{
		{"db", "grant", "local", "app_ro", "--role", "pg_read_all_data"},
		{"db", "grant", "local", "app_ro", "--privileges", "ALL", "--on", "database:app"},
		{"db", "revoke", "local", "app_ro", "--role", "readers"},
		{"db", "user", "add", "local", "newrole", "--no-login"},
		{"db", "user", "add", "local", "app2", "--password-ref", "credential:p"},
		{"db", "user", "passwd", "local", "postgres", "--password-ref", "credential:p"},
	} {
		_, e := invRun(t, args...)
		if e == nil || e.Code != "POLICY_BLOCKED" {
			t.Errorf("%v: want POLICY_BLOCKED, got %+v", args[1:], e)
		}
	}
}

// An AI agent's --allow-dangerous opens the window, which names the rule.
func TestDBGrantAsksForAnAgent(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "local", "postgres://app@127.0.0.1:1/app")
	texts := windowText(t, false)
	_, e := invRun(t, "db", "grant", "local", "app_ro", "--role", "readers", "--allow-dangerous")
	if e == nil || len(*texts) != 1 || !strings.Contains((*texts)[0], "sql-privileges") {
		t.Errorf("want one window naming sql-privileges and a stop, got %+v, windows %q", e, *texts)
	}
}
