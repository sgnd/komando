package cli

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// runCache runs komando in this process and returns what it printed.
func runCache(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRoot()
	root.SetArgs(args)
	var b strings.Builder
	saved := out.P.W
	out.P.W = &b
	defer func() { out.P.W = saved; out.P.Reset() }()
	err := root.Execute()
	return b.String(), err
}

// TestCacheRunScriptsNeedApproval: a read-only script (EVAL_RO, EVALSHA_RO,
// FCALL_RO) cannot write, but it can loop and leave Redis answering BUSY to
// every client; module code (TFCALL, RG.PYEXECUTE) can do anything; FUNCTION
// LOAD REPLACE swaps code the application calls. All of them need --write
// and --allow-dangerous, and --dry-run sends nothing.
// The conn has no server: a command that got as far as connecting fails
// with CACHE_CONNECT.
func TestCacheRunScriptsNeedApproval(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	defer func() { g.dryRun, store.DryRun = false, false }()
	if _, err := runCache(t, "-o", "json", "conn", "add", "c", "redis://127.0.0.1:1/0"); err != nil {
		t.Fatal(err)
	}
	code := func(err error) string {
		var e *out.Error
		if errors.As(err, &e) {
			return e.Code
		}
		return ""
	}
	for _, command := range [][]string{
		{"EVAL_RO", "while true do end", "0"},
		{"evalsha_ro", "e0e1f9fabfc9d4800c877a703b823ac0578ff8db", "0"},
		{"FCALL_RO", "app_get", "1", "k"},
		{"FUNCTION", "LOAD", "REPLACE", "#!lua name=app\nredis.register_function('app_get', function() return 1 end)"},
		{"TFCALL", "app.get", "0"},
		{"RG.PYEXECUTE", "GB().run()"},
		{"TFUNCTION", "LOAD", "REPLACE", "#!js api_version=1.0 name=app"},
	} {
		run := func(flags ...string) (string, error) {
			return runCache(t, append(append([]string{"-o", "json", "cache", "run", "c"}, flags...), append([]string{"--"}, command...)...)...)
		}
		if _, err := run(); code(err) != "WRITE_REQUIRES_FLAG" || !strings.Contains(err.Error(), "--allow-dangerous") {
			t.Errorf("%s: %v", command[0], err)
		}
		if _, err := run("--dry-run"); code(err) != "WRITE_REQUIRES_FLAG" {
			t.Errorf("%s --dry-run sent it: %v", command[0], err)
		}
		if _, err := run("--write"); code(err) != "POLICY_BLOCKED" {
			t.Errorf("%s --write: %v", command[0], err)
		}
		s, err := run("--write", "--dry-run")
		if err != nil || !strings.Contains(s, "nothing sent") || !strings.Contains(s, "POLICY_BLOCKED") {
			t.Errorf("%s --write --dry-run: %v\n%s", command[0], err, s)
		}
		g.dryRun, store.DryRun = false, false
	}
}

// TestCacheRunHidesPasswordsLive: an AI agent reads CONFIG GET without
// --write, so requirepass and masterauth must come out [hidden] (set
// KOMANDO_E2E_REDIS=host:port and KOMANDO_E2E_REDIS_PASSWORD to a server
// started with --requirepass and --masterauth).
func TestCacheRunHidesPasswordsLive(t *testing.T) {
	addr, pw := os.Getenv("KOMANDO_E2E_REDIS"), os.Getenv("KOMANDO_E2E_REDIS_PASSWORD")
	if addr == "" || pw == "" {
		t.Skip("set KOMANDO_E2E_REDIS=host:port and KOMANDO_E2E_REDIS_PASSWORD")
	}
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	t.Setenv("KOMANDO_TEST_REDIS_PW", pw) // an env: reference, which the vault redaction does not know
	if _, err := runCache(t, "-o", "json", "conn", "add", "c", "redis://"+addr+"/0", "--password-ref", "env:KOMANDO_TEST_REDIS_PW"); err != nil {
		t.Fatal(err)
	}
	asAgent(t, false, true)
	defer func() { out.P.Mask = false }()
	for _, format := range []string{"json", "text"} {
		for _, param := range []string{"requirepass", "masterauth", "*"} {
			s, err := runCache(t, "-o", format, "cache", "run", "c", "--", "CONFIG", "GET", param)
			if err != nil || strings.Contains(s, pw) || !strings.Contains(s, out.Hidden) {
				t.Errorf("%s CONFIG GET %s: %v\n%s", format, param, err, s)
			}
			if format == "text" && param != "*" && s != "1# "+param+": [hidden]\n" {
				t.Errorf("text: %q", s)
			}
		}
	}
}

// A command in one quoted argument is read as words, so "get foo" is the
// read GET, and MONITOR, which never returns, is refused before connecting.
func TestCacheRunQuotedCommand(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	defer func() { g.dryRun, store.DryRun = false, false }()
	if _, err := runCache(t, "-o", "json", "conn", "add", "c", "redis://127.0.0.1:1/0"); err != nil {
		t.Fatal(err)
	}
	code := func(err error) string {
		var e *out.Error
		if errors.As(err, &e) {
			return e.Code
		}
		return ""
	}
	if _, err := runCache(t, "-o", "json", "cache", "run", "c", "--", "get foo"); code(err) != "CACHE_CONNECT" {
		t.Errorf("get foo: %v", err)
	}
	// without -- the words could hold komando's own flags: refused
	if _, err := runCache(t, "-o", "json", "cache", "run", "c", "get foo"); code(err) != "USAGE" {
		t.Errorf("get foo without --: %v", err)
	}
	if _, err := runCache(t, "-o", "json", "cache", "run", "c", "--write", "--dry-run", "--", "MONITOR"); code(err) != "NOT_SUPPORTED" {
		t.Errorf("MONITOR: %v", err)
	}
}

// fakeMemcached answers just enough of memcached's text protocol for a
// connect and a get, and records every line it receives.
func fakeMemcached(t *testing.T) (addr string, lines func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					l = strings.TrimRight(l, "\r\n")
					mu.Lock()
					got = append(got, l)
					mu.Unlock()
					reply := "ERROR"
					switch f := strings.Fields(l); {
					case len(f) == 0:
						continue
					case f[0] == "version":
						reply = "VERSION 1.6.39"
					case f[0] == "mn":
						reply = "MN"
					case f[0] == "get" || f[0] == "stats":
						reply = "END"
					case f[0] == "flush_all":
						reply = "OK"
					case f[0] == "mg":
						reply = "EN"
					}
					fmt.Fprintf(c, "%s\r\n", reply)
				}
			}()
		}
	}()
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// TestCacheRunMemcachedLineInjection: memcached ends a command at a
// newline and splits it at spaces, so `cache run` rates the words memcached
// will read, not the arguments as given: "get" with "\r\nflush_all" in an
// argument must not send flush_all as a read, a leading space must not hide
// flush_all from the --allow-dangerous rule, and "mg" with "key T30" in one
// argument is a touch (a write).
func TestCacheRunMemcachedLineInjection(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	defer func() { g.dryRun, store.DryRun = false, false }()
	addr, lines := fakeMemcached(t)
	if _, err := runCache(t, "-o", "json", "conn", "add", "m", "memcached://"+addr); err != nil {
		t.Fatal(err)
	}
	code := func(err error) string {
		var e *out.Error
		if errors.As(err, &e) {
			return e.Code
		}
		return ""
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--", "get", "a\r\nflush_all"}, "USAGE"},
		{[]string{"--", "get", "a\nflush_all"}, "USAGE"},
		{[]string{`get "a\r\nflush_all"`}, "USAGE"}, // one quoted line, escapes as redis-cli reads them
		{[]string{"--write", "--", " flush_all"}, "POLICY_BLOCKED"},
		{[]string{"--", "mg", "a T30"}, "WRITE_REQUIRES_FLAG"},
		{[]string{"--", "watch"}, "NOT_SUPPORTED"},
	} {
		_, err := runCache(t, append([]string{"-o", "json", "cache", "run", "m"}, c.args...)...)
		if code(err) != c.want {
			t.Errorf("%q: %v, want %s", c.args, err, c.want)
		}
	}
	if _, err := runCache(t, "-o", "json", "cache", "run", "m", "--", "GET", "a"); err != nil {
		t.Errorf("a plain get: %v", err)
	}
	for _, l := range lines() {
		if strings.Contains(l, "flush_all") || strings.Contains(l, "T30") {
			t.Errorf("sent to memcached: %q", l)
		}
	}
	if !slices.Contains(lines(), "get a") {
		t.Errorf("the plain get was not sent as `get a`: %q", lines())
	}
}

// --limit 0 used to list nothing yet say more keys match (cache keys) or
// quietly show 100 items (cache get); it is a usage error before connecting.
func TestCacheLimitMustBePositive(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	if _, err := runCache(t, "-o", "json", "conn", "add", "c", "redis://127.0.0.1:1/0"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"cache", "keys", "c", "--limit", "0"},
		{"cache", "keys", "c", "*", "-n", "-5"},
		{"cache", "get", "c", "k", "--limit", "0"},
	} {
		_, err := runCache(t, append([]string{"-o", "json"}, args...)...)
		var e *out.Error
		if !errors.As(err, &e) || e.Code != "USAGE" {
			t.Errorf("%q: %v", args, err)
		}
	}
}

// In a Redis Cluster, FLUSHALL, SCAN and the other whole-key-space commands
// reach one master only; cache run refuses them before any approval or
// connection (the conn has no server).
func TestCacheRunClusterWide(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	defer func() { g.dryRun, store.DryRun = false, false }()
	if _, err := runCache(t, "-o", "json", "conn", "add", "cl", "redis://127.0.0.1:1?cluster=1"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--write", "--", "FLUSHALL"}, {"--", "scan", "0"}, {"--", "RANDOMKEY"}} {
		_, err := runCache(t, append([]string{"-o", "json", "cache", "run", "cl"}, args...)...)
		var e *out.Error
		if !errors.As(err, &e) || e.Code != "NOT_SUPPORTED" {
			t.Errorf("%q: %v", args, err)
		}
	}
	var e *out.Error
	if _, err := runCache(t, "-o", "json", "cache", "run", "cl", "--", "DBSIZE"); !errors.As(err, &e) || e.Code != "CACHE_CONNECT" {
		t.Errorf("DBSIZE is summed over the masters, so it is sent: %v", err)
	}
}
