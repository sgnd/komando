package cli

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// passwordRedis is a Redis server that lets in this password only and
// answers PING, INFO and the client's setup. tries counts the passwords
// it got.
func passwordRedis(t *testing.T, password string) (port string, tries *atomic.Int32) {
	t.Helper()
	tries = &atomic.Int32{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				authed := false
				for {
					args, err := readRESP(r)
					if err != nil {
						return
					}
					reply := "+OK\r\n"
					switch strings.ToUpper(args[0]) {
					case "HELLO":
						reply = "-ERR unknown command 'HELLO'\r\n"
					case "AUTH":
						tries.Add(1)
						authed = args[len(args)-1] == password
						if !authed {
							reply = "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
						}
					case "PING":
						reply = "+PONG\r\n"
					case "INFO":
						body := "# Server\r\nredis_version:7.2.0\r\n"
						reply = "$" + strconv.Itoa(len(body)) + "\r\n" + body + "\r\n"
					case "CLIENT", "SELECT":
					default:
						if !authed {
							reply = "-NOAUTH Authentication required.\r\n"
						}
					}
					if args[0] != "CLIENT" && !authed && strings.ToUpper(args[0]) != "AUTH" && strings.ToUpper(args[0]) != "HELLO" {
						reply = "-NOAUTH Authentication required.\r\n"
					}
					if _, err := io.WriteString(c, reply); err != nil {
						return
					}
				}
			}()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, tries
}

// readRESP reads one command (an array of bulk strings).
func readRESP(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil || n < 1 {
		return []string{strings.TrimSpace(line)}, nil // an inline command
	}
	args := make([]string, 0, n)
	for range n {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(hdr, "$")))
		b := make([]byte, size+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		args = append(args, string(b[:size]))
	}
	return args, nil
}

// conn add/edit --login takes ask, password and none, each reading back
// as written; what contradicts it, and login ask for a file or a cluster,
// is refused with its own hint.
func TestConnLoginAskFlag(t *testing.T) {
	invHome(t)
	t.Setenv("PW", "s3cret-pass")
	d := mustRun(t, "conn", "add", "db1", "postgres://app@10.0.0.5/app", "--login", "ask")
	if d["login"] != "ask" || d["password_ref"] != nil {
		t.Fatalf("conn add: %v", d)
	}
	if d := mustRun(t, "conn", "show", "db1"); d["login"] != "ask" {
		t.Errorf("conn show: %v", d)
	}
	if s, err := runCache(t, "-o", "text", "conn", "show", "db1"); err != nil || !strings.Contains(s, "ask") {
		t.Errorf("conn show -o text: %v\n%s", err, s)
	}
	mustRun(t, "conn", "add", "db2", "postgres://app@10.0.0.6/app", "--login", "password", "--password-ref", "env:PW")
	mustRun(t, "conn", "add", "db3", "postgres://app@10.0.0.7/app", "--login", "none")
	if l := loginOf(t); l["db1"] != "ask" || l["db2"] != "password" || l["db3"] != "none" {
		t.Errorf("list logins: %v", l)
	}
	for _, bad := range [][]string{
		{"postgres://app@10.0.0.8/app", "--login", "key"},
		{"postgres://app@10.0.0.8/app", "--login", "ask", "--password-ref", "env:PW"},
		{"postgres://app@10.0.0.8/app", "--login", "password"},
		{"postgres://app@10.0.0.8/app", "--login", "none", "--password-ref", "env:PW"},
		{"sqlite:///tmp/app.db", "--login", "ask"},
	} {
		if e := wantCode(t, "USAGE", append([]string{"conn", "add", "bad"}, bad...)...); e.Hint == out.UsageHint || e.Hint == "" {
			t.Errorf("%v: no hint of its own: %+v", bad, e)
		}
	}
	// edit: a stored password ends login ask; ask lets go of the stored one
	mustRun(t, "secret", "set", "db2-pass", "--from-env", "PW")
	mustRun(t, "conn", "edit", "db2", "--password-ref", "secret:db2-pass")
	d = mustRun(t, "conn", "edit", "db2", "--login", "ask")
	if d["login"] != "ask" || d["password_ref"] != nil || asJSON(d["secrets_unused"]) != `["db2-pass"]` {
		t.Errorf("edit --login ask: %v", d)
	}
	if _, err := vault.Get("db2-pass"); err != nil {
		t.Error("the secret was deleted")
	}
	if d := mustRun(t, "conn", "edit", "db2", "--password-ref", "env:PW"); d["login"] != "password" {
		t.Errorf("edit --password-ref: %v", d)
	}
	if d := mustRun(t, "conn", "edit", "db2", "--login", "none"); d["login"] != "none" || d["password_ref"] != nil {
		t.Errorf("edit --login none: %v", d)
	}
}

// An AI agent's command asks the person in komando's window for a
// login-ask conn: the window names the conn, its user, address and the
// way there; the typed password logs in and never shows in the output.
func TestConnLoginAskAgentWindow(t *testing.T) {
	invHome(t)
	const pw = "conn-Typed-pw"
	port, tries := passwordRedis(t, pw)
	mustRun(t, "conn", "add", "cache1", "redis://default@127.0.0.1:"+port+"/0", "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")
	texts := loginWindow(t, pw, true, true)
	s, err := runCache(t, "-o", "json", "test", "cache1")
	if err != nil || strings.Contains(s, pw) {
		t.Fatalf("%v\n%s", err, s)
	}
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "Claude Code wants komando to log in to conn cache1 as default@127.0.0.1:"+port) ||
		!strings.Contains((*texts)[0], "the agent never sees it") {
		t.Errorf("window: %q", *texts)
	}
	if tries.Load() == 0 {
		t.Error("the server got no password")
	}
	// a cancel stops it, and the window stays shut for a minute
	texts = loginWindow(t, "", false, true)
	e := wantCode(t, "DECLINED", "cache", "run", "cache1", "--", "PING")
	if !strings.Contains(e.Hint, "do not retry") || !strings.Contains(e.Hint, "in their own terminal") {
		t.Errorf("cancel: %+v", e)
	}
	wantCode(t, "DECLINED", "cache", "run", "cache1", "--", "PING")
	if len(*texts) != 1 {
		t.Errorf("the cool-down opened %d windows", len(*texts))
	}
}

// A script, and an agent with no screen, cannot type the password:
// NEEDS_PERSON, and nothing reaches the server.
func TestConnLoginAskNeedsPerson(t *testing.T) {
	invHome(t)
	port, tries := passwordRedis(t, "pw")
	mustRun(t, "conn", "add", "cache1", "redis://default@127.0.0.1:"+port+"/0", "--login", "ask")
	noAgent(t)
	if e := wantCode(t, "NEEDS_PERSON", "cache", "run", "cache1", "--", "PING"); !strings.Contains(e.Hint, "a person run the command") {
		t.Errorf("script: %+v", e)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	loginWindow(t, "", false, false)
	if e := wantCode(t, "NEEDS_PERSON", "cache", "run", "cache1", "--", "PING"); !strings.Contains(e.Hint, "never ask for the password in the chat") {
		t.Errorf("no screen: %+v", e)
	}
	if tries.Load() != 0 {
		t.Errorf("the server got %d passwords", tries.Load())
	}
}

// Only a person sets where a conn's typed password goes: an AI agent's
// add, --url or --via edit, or turn to login ask gets NEEDS_PERSON.
func TestConnLoginAskDestinationNeedsPerson(t *testing.T) {
	invHome(t)
	t.Setenv("PW", "x")
	mustRun(t, "host", "add", "bastion", "u@10.0.0.5")
	mustRun(t, "conn", "add", "db1", "postgres://app@10.0.0.5/app", "--login", "ask")
	mustRun(t, "conn", "add", "db2", "postgres://app@10.0.0.6/app", "--password-ref", "env:PW")
	mustRun(t, "conn", "add", "db3", "postgres://app@10.0.0.7/app", "--login", "ask", "--via", "bastion")
	setCallerEnv(t, "CLAUDECODE", "1")
	for _, args := range [][]string{
		{"conn", "add", "evil", "postgres://app@203.0.113.66/app", "--login", "ask"},
		{"conn", "edit", "db1", "--url", "postgres://app@203.0.113.66/app"},
		{"conn", "edit", "db1", "--via", "bastion"},
		{"conn", "edit", "db2", "--login", "ask"},
		{"host", "edit", "bastion", "--address", "203.0.113.66"},
	} {
		if e := wantCode(t, "NEEDS_PERSON", args...); !strings.Contains(e.Hint, "in their own terminal") || strings.Contains(e.Hint, "--yes") {
			t.Errorf("%v: %+v", args, e)
		}
	}
	mustRun(t, "conn", "edit", "db1", "--add-tag", "x")
	mustRun(t, "conn", "edit", "db1", "--login", "none")
}

// The dump tools get the password in their environment, where an AI
// agent's programs could read it: for a login-ask conn an agent's dump
// stops before anyone is asked.
func TestConnLoginAskDumpToolNeedsPerson(t *testing.T) {
	invHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	texts := loginWindow(t, "pw", true, true)
	cl := testCall()
	c := &store.Conn{Name: "db1", Kind: "postgres", URL: "postgres://app@10.0.0.5/app", Login: store.LoginAsk}
	err := runTool(cl, context.Background(), &store.State{}, c, nil, dumpTool{passwordEnv: "PGPASSWORD"}, []string{"pg_dump"}, nil, io.Discard, false)
	if err == nil || toErr(err).Code != "NEEDS_PERSON" || len(*texts) != 0 {
		t.Errorf("%v, %d windows", err, len(*texts))
	}
}
