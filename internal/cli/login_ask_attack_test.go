package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// These tests are the attacks of an AI agent that wants the password a
// person types for a login-ask conn or server (and the stored password of
// a conn): each moves where the login goes without changing the address
// komando shows. Each must stop with NEEDS_PERSON (login ask) or
// SECRET_DESTINATION (a stored password), and no fake server may get it.

// A Postgres URL's own settings (host=, port=, hostaddr=, service=,
// sslrootcert=, ...) move the login as the address does: an agent that
// writes them into a login-ask conn's URL gets NEEDS_PERSON, and into a
// stored-password conn's URL SECRET_DESTINATION. Settings that move
// nothing (connect_timeout, application_name) go on.
func TestLoginAskConnURLSettingsAreThePlace(t *testing.T) {
	invHome(t)
	t.Setenv("PW", "stored-pw")
	mustRun(t, "secret", "set", "evilca", "--from-env", "PW")
	mustRun(t, "conn", "add", "pg1", "postgres://app@db.internal:5432/app", "--login", "ask")
	mustRun(t, "conn", "add", "pg2", "postgres://app@db.internal:5432/app", "--password-ref", "env:PW")
	mustRun(t, "conn", "add", "c1", "rediss://default@10.0.0.5:6379/0", "--login", "ask")
	mustRun(t, "conn", "add", "m1", "mongodb://app@10.0.0.5:27017/app", "--login", "ask")
	mustRun(t, "conn", "add", "q1", "amqp://guest@127.0.0.1:5672/", "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")
	base := mustRun(t, "conn", "show", "pg1")["url"].(string)
	for _, c := range []struct{ conn, url string }{
		{"pg1", base + "&host=127.0.0.1&port=5999"},
		{"pg1", base + "&hostaddr=203.0.113.66"},
		{"pg1", base + "&service=evil"},
		{"pg1", base + "&sslrootcert=/tmp/evil.pem"},
		{"pg1", base + "&ca=secret:evilca"},
		{"pg1", strings.Replace(base, "verify-full", "require", 1)},
		{"c1", "rediss://default@10.0.0.5:6379/0?sentinel=m&sentinels=203.0.113.66:26379&sentinel_auth=same"},
		{"m1", "mongodb://app@10.0.0.5:27017,203.0.113.66:27017/app?authMechanism=PLAIN"},
		{"q1", "amqp://guest@127.0.0.1:5672/?management=4444"},
		// ';' joins settings for the MongoDB driver, which url.Query drops
		{"m1", "mongodb://app@10.0.0.5:27017/app?appName=x;tlsInsecure=true"},
		{"m1", "mongodb://app@10.0.0.5:27017/app?appName=x;tlsCAFile=/tmp/evil.pem"},
	} {
		e := wantCode(t, "NEEDS_PERSON", "conn", "edit", c.conn, "--url", c.url)
		if !strings.Contains(e.Hint, "in their own terminal") {
			t.Errorf("%s: %+v", c.url, e)
		}
	}
	base2 := mustRun(t, "conn", "show", "pg2")["url"].(string)
	if e := wantCode(t, "SECRET_DESTINATION", "conn", "edit", "pg2", "--url", base2+"&host=127.0.0.1&port=5999"); !strings.Contains(e.Message, "host=127.0.0.1") {
		t.Errorf("stored password: %+v", e)
	}
	// nothing moves: no stop
	mustRun(t, "conn", "edit", "pg1", "--url", base+"&connect_timeout=5&application_name=report")
	st, _ := store.Load()
	if u := st.Conns["pg1"].URL; strings.Contains(u, "host=") || strings.Contains(u, "sslrootcert") {
		t.Errorf("an edit went through: %s", u)
	}
}

// The password goes only to the host the URL names: Postgres settings
// from this process's environment (an agent sets its own) are not read,
// so PGSSLROOTCERT cannot make komando trust the agent's certificate.
func TestLoginAskPostgresEnvIgnored(t *testing.T) {
	invHome(t)
	const pw = "Person-Typed-PW"
	cert, caFile := evilCert(t)
	port, got := fakePG(t, &cert)
	mustRun(t, "conn", "add", "pg1", "postgres://app@127.0.0.1:"+port+"/app?sslmode=verify-full", "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")
	t.Setenv("PGSSLROOTCERT", caFile)
	loginWindow(t, pw, true, true)
	_, _ = runCache(t, "-o", "json", "db", "query", "pg1", "--", "select 1")
	if v, _ := got.Load().(string); v == pw {
		t.Fatalf("the fake server got the typed password")
	}
}

// WinRM's CA, its auth and its TLS setting are part of where a login-ask
// server's password goes; a secret on the way (a WinRM or conn CA, a
// VPN's key) is too, so an agent replacing it gets NEEDS_PERSON.
func TestLoginAskRouteSettingsAndSecrets(t *testing.T) {
	invHome(t)
	t.Setenv("CAPEM", "x")
	mustRun(t, "secret", "set", "corpca", "--from-env", "CAPEM")
	mustRun(t, "secret", "set", "evilca", "--from-env", "CAPEM")
	mustRun(t, "host", "add", "win1", "winrm://Administrator@10.0.0.9", "--login", "ask")
	mustRun(t, "host", "add", "win2", "winrm://Administrator@10.0.0.8?ca=secret:corpca", "--login", "ask")
	mustRun(t, "secret", "set", "connca", "--from-env", "CAPEM")
	mustRun(t, "conn", "add", "pg1", "postgres://app@db.internal:5432/app?ca=secret:connca", "--login", "ask")
	mustRun(t, "secret", "set", "tskey", "--from-env", "CAPEM")
	mustRun(t, "vpn", "add", "ts", "tailscale", "--password-ref", "secret:tskey")
	mustRun(t, "host", "add", "web1", "u@100.64.0.5", "--login", "ask", "--via", "ts")
	setCallerEnv(t, "CLAUDECODE", "1")
	for _, a := range []string{"winrm://Administrator@10.0.0.9?ca=secret:evilca", "winrm://Administrator@10.0.0.9?auth=basic"} {
		wantCode(t, "NEEDS_PERSON", "host", "edit", "win1", "--address", a)
	}
	t.Setenv("EVIL", "y")
	for _, name := range []string{"corpca", "connca", "tskey"} {
		if e := wantCode(t, "NEEDS_PERSON", "secret", "set", name, "--from-env", "EVIL"); !strings.Contains(e.Message, name) {
			t.Errorf("%s: %+v", name, e)
		}
	}
}

// default_user is the account a login-ask server with no user logs in
// as: an agent's change of it gets NEEDS_PERSON.
func TestLoginAskDefaultUserNeedsPerson(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "10.0.0.5", "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")
	wantCode(t, "NEEDS_PERSON", "host", "edit", "web1", "--user", "root")
	wantCode(t, "NEEDS_PERSON", "config", "set", "default_user", "root")
}

// A VPN on the way to a login-ask server that an agent adds again with
// --overwrite stops even with the same flags: the profile or key in its
// secret may be new. An edit that changes only its groups goes on.
func TestLoginAskVpnOverwriteWay(t *testing.T) {
	invHome(t)
	t.Setenv("K", "x")
	mustRun(t, "secret", "set", "tskey", "--from-env", "K")
	mustRun(t, "vpn", "add", "ts", "tailscale", "--password-ref", "secret:tskey")
	mustRun(t, "host", "add", "web1", "u@100.64.0.5", "--login", "ask", "--via", "ts")
	setCallerEnv(t, "CLAUDECODE", "1")
	wantCode(t, "NEEDS_PERSON", "vpn", "add", "ts", "tailscale", "--password-ref", "secret:tskey", "--overwrite")
	mustRun(t, "vpn", "edit", "ts", "-g", "lab")
}

// The user in a login-ask conn's URL is the account the typed password is
// for, as a server's user is: an agent's conn edit to another user stops.
func TestLoginAskConnURLUser(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "pg1", "postgres://app@db.internal:5432/app", "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")
	base := mustRun(t, "conn", "show", "pg1")["url"].(string)
	if e := wantCode(t, "NEEDS_PERSON", "conn", "edit", "pg1", "--url", strings.Replace(base, "app@", "postgres@", 1)); !strings.Contains(e.Message, "postgres") {
		t.Errorf("%+v", e)
	}
}
