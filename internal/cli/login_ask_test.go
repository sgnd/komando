package cli

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// passwordSSHD is a server that logs in with this password only (the
// password method) and answers every command with the password it was
// given, as a careless server might print it. It also carries
// connections on (direct-tcpip), as a jump host does. tries counts the
// passwords it got; key is its host key (trustSSHD pins it).
func passwordSSHD(t *testing.T, password string) (port string, tries *atomic.Int32, key ssh.PublicKey) {
	t.Helper()
	tries = &atomic.Int32{}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		tries.Add(1)
		if string(pw) != password {
			return nil, errors.New("wrong password")
		}
		return &ssh.Permissions{Extensions: map[string]string{"pw": string(pw)}}, nil
	}}
	cfg.AddHostKey(signer)
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
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					if nch.ChannelType() == "direct-tcpip" {
						go forwardTCPIP(nch)
						continue
					}
					ch, creqs, err := nch.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							_ = r.Reply(true, nil)
							if r.Type != "exec" {
								continue
							}
							_, _ = ch.Write([]byte("logged in with " + sc.Permissions.Extensions["pw"] + "\n"))
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
							_ = ch.Close()
						}
					}()
				}
			}()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, tries, signer.PublicKey()
}

// forwardTCPIP carries a direct-tcpip channel to the address it names.
func forwardTCPIP(nch ssh.NewChannel) {
	var to struct {
		Host     string
		Port     uint32
		FromHost string
		FromPort uint32
	}
	if err := ssh.Unmarshal(nch.ExtraData(), &to); err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	c, err := net.Dial("tcp", net.JoinHostPort(to.Host, strconv.Itoa(int(to.Port))))
	if err != nil {
		_ = nch.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nch.Accept()
	if err != nil {
		c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { _, _ = io.Copy(ch, c); _ = ch.CloseWrite() }()
	_, _ = io.Copy(c, ch)
	c.Close()
	ch.Close()
}

// trustSSHD pins a test server's host key and notes that a person logged
// in to login-ask server name with it, as a person's first connection
// does: an AI agent's command never trusts a login-ask server's new key.
func trustSSHD(t *testing.T, name, port string, key ssh.PublicKey) {
	t.Helper()
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := sshx.MarkLoginMet(st.Hosts[name], net.JoinHostPort("127.0.0.1", port), key); err != nil {
		t.Fatal(err)
	}
}

// loginWindow stands in for komando's password window: the person types
// pw (or cancels, or there is no screen). It returns the texts shown.
func loginWindow(t *testing.T, pw string, given, shown bool) *[]string {
	t.Helper()
	var mu sync.Mutex
	texts := &[]string{}
	saved := askLoginOnScreen
	askLoginOnScreen = func(_ *call, text string) (string, bool, bool) {
		mu.Lock()
		defer mu.Unlock()
		*texts = append(*texts, text)
		if !shown {
			return "", false, false
		}
		return pw, given, true
	}
	t.Cleanup(func() { askLoginOnScreen = saved })
	return texts
}

// loginOf is the login field of every row of a list (servers and conns).
func loginOf(t *testing.T) map[string]any {
	t.Helper()
	logins := map[string]any{}
	for _, r := range mustRun(t, "list")["targets"].([]any) {
		row := r.(map[string]any)
		logins[row["name"].(string)] = row["login"]
	}
	return logins
}

// --login takes the words host show and host list print, and each one
// reads back as written; flags that contradict it are refused.
func TestLoginAskFlag(t *testing.T) {
	invHome(t)
	t.Setenv("WEB3_PASS", "x")
	d := mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--login", "ask")
	if d["login"] != "ask" || d["password_ref"] != nil {
		t.Fatalf("host add: %v", d)
	}
	if d := mustRun(t, "host", "show", "web1"); d["login"] != "ask" {
		t.Fatalf("host show: %v", d)
	}
	if s, err := runCache(t, "-o", "text", "host", "show", "web1"); err != nil || !strings.Contains(s, "ask") {
		t.Errorf("host show -o text: %v\n%s", err, s)
	}
	keyFile := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(keyFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		login string
		more  []string
	}{
		{"agent", nil},
		{"password", []string{"--password-ref", "env:WEB3_PASS"}},
		{"key", []string{"--identity", keyFile}},
	} {
		name := "h-" + c.login
		d := mustRun(t, append([]string{"host", "add", name, "u@10.0.0.9", "--login", c.login}, c.more...)...)
		if d["login"] != c.login {
			t.Errorf("--login %s reads back as %v", c.login, d["login"])
		}
	}
	// what each word needs, and what it cannot go with
	for _, bad := range [][]string{
		{"--login", "always"},
		{"--login", "ask", "--password-ref", "secret:web2-pass"},
		{"--login", "ask", "--ask-password"},
		{"--login", "password"},
		{"--login", "password", "--password-ref", "env:X", "--identity", keyFile},
		{"--login", "key"},
		{"--login", "agent", "--identity", keyFile},
		{"--login", "agent", "--password-ref", "env:X"},
	} {
		// each names its own way out, not the generic one
		if e := wantCode(t, "USAGE", append([]string{"host", "add", "web2", "u@10.0.0.2"}, bad...)...); e.Hint == out.UsageHint || e.Hint == "" {
			t.Errorf("%v: no hint of its own: %+v", bad, e)
		}
	}
	wantCode(t, "USAGE", "host", "edit", "web1", "--unset", "login") // --login says it: no second way
	e := wantCode(t, "USAGE", "host", "add", "win1", "winrm://Administrator@10.0.0.9", "--login", "agent")
	if !strings.Contains(e.Message, "WinRM") {
		t.Errorf("winrm agent: %+v", e)
	}

	// the settings alone say it too
	mustRun(t, "host", "add", "web2", "u@10.0.0.2")
	mustRun(t, "host", "add", "web3", "u@10.0.0.3", "--password-ref", "env:WEB3_PASS")
	if l := loginOf(t); l["web1"] != "ask" || l["web2"] != "agent" || l["web3"] != "password" || l["h-key"] != "key" {
		t.Errorf("host list logins: %v", l)
	}

	// edit: a stored password ends login ask; each word switches to itself
	if d := mustRun(t, "host", "edit", "web1", "--password-ref", "env:WEB1_PASS"); d["login"] != "password" {
		t.Errorf("edit --password-ref: %v", d)
	}
	mustRun(t, "host", "edit", "web1", "--login", "ask")
	if d := mustRun(t, "host", "edit", "web1", "--login", "agent"); d["login"] != "agent" {
		t.Errorf("edit --login agent: %v", d)
	}
	wantCode(t, "USAGE", "host", "edit", "web1", "--login", "key")      // it has no key
	wantCode(t, "USAGE", "host", "edit", "web1", "--login", "password") // nor a password
	if d := mustRun(t, "host", "edit", "web1", "--login", "key", "--identity", keyFile, "--password-ref", "env:WEB1_PASS"); d["login"] != "key" {
		t.Errorf("edit --login key: %v", d)
	}
	if d := mustRun(t, "host", "edit", "web1", "--login", "password"); d["login"] != "password" || d["identity"] != nil {
		t.Errorf("edit --login password keeps the key: %v", d)
	}
	st, _ := store.Load()
	if h := st.Hosts["web1"]; h.Login != "" || h.PasswordRef != "env:WEB1_PASS" {
		t.Errorf("stored: %+v", h)
	}
}

// komando schema of the commands that take --login reads as written: no
// example or usage text that the output hides, the one --login usage
// text, and nothing typed or stored in it.
func TestLoginAskSchemaNotHidden(t *testing.T) {
	invHome(t)
	t.Setenv("PW", "s3cret-in-env")
	mustRun(t, "secret", "set", "web1-pass", "--from-env", "PW")
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--password-ref", "secret:web1-pass")
	for _, cmd := range [][]string{{"host", "add"}, {"host", "edit"}, {"conn", "add"}, {"conn", "edit"}} {
		s, err := runCache(t, append([]string{"-o", "json", "schema"}, cmd...)...)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(s, "[hidden") || strings.Contains(s, "s3cret-in-env") || !strings.Contains(s, loginFlagUsage[:40]) {
			t.Errorf("schema %v:\n%s", cmd, s)
		}
	}
	// a table leaf's add has the table's --login text; nothing in it is hidden
	if s, err := runCache(t, "-o", "json", "schema", "database", "postgres", "add"); err != nil || strings.Contains(s, "[hidden") || strings.Contains(s, "s3cret-in-env") || !strings.Contains(s, `"login"`) {
		t.Errorf("schema database postgres add (%v):\n%s", err, s)
	}
	for _, c := range []struct{ cmd, example string }{
		{"host", "never store its password; type it at every connect"},
		{"conn", "never store its password; type it at every connect"},
	} {
		if s, _ := runCache(t, "-o", "json", "schema", c.cmd, "edit"); !strings.Contains(s, c.example) {
			t.Errorf("schema %s edit lacks its --login example", c.cmd)
		}
	}
}

// Switching to login ask (or agent) unlinks the stored password; the
// secret stays in the vault, and is named unused only when nothing else
// uses it.
func TestLoginAskUnlinksTheStoredPassword(t *testing.T) {
	invHome(t)
	t.Setenv("PW", "s3cret-pass")
	mustRun(t, "secret", "set", "web1-pass", "--from-env", "PW")
	mustRun(t, "secret", "set", "shared-pass", "--from-env", "PW")
	mustRun(t, "secret", "set", "web4-pass", "--from-env", "PW")
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--password-ref", "secret:web1-pass")
	mustRun(t, "host", "add", "web2", "u@10.0.0.2", "--password-ref", "secret:shared-pass")
	mustRun(t, "host", "add", "web3", "u@10.0.0.3", "--password-ref", "secret:shared-pass")
	mustRun(t, "host", "add", "web4", "u@10.0.0.4", "--password-ref", "secret:web4-pass")

	d := mustRun(t, "host", "edit", "web1", "--login", "ask")
	if d["login"] != "ask" || d["password_ref"] != nil || asJSON(d["secrets_unused"]) != `["web1-pass"]` ||
		!strings.Contains(asJSON(d["warnings"]), "komando secret rm web1-pass") {
		t.Fatalf("edit web1: %v", d)
	}
	if _, err := vault.Get("web1-pass"); err != nil {
		t.Error("the secret was deleted; komando never deletes it on its own")
	}
	d = mustRun(t, "host", "edit", "web2", "--login", "ask")
	if d["secrets_unused"] != nil {
		t.Errorf("web3 still uses shared-pass: %v", d)
	}
	if _, err := vault.Get("shared-pass"); err != nil {
		t.Error("a secret another server uses was deleted")
	}
	if d := mustRun(t, "host", "edit", "web4", "--login", "agent"); asJSON(d["secrets_unused"]) != `["web4-pass"]` {
		t.Errorf("edit web4 --login agent: %v", d)
	}
}

// A login-ask server's address is where a person's password goes, so only
// a person sets it: an AI agent that adds one, turns a server to login
// ask, points one somewhere else, or changes a server on the way to one,
// gets NEEDS_PERSON, which no flag lifts. Other edits go on.
func TestLoginAskDestinationNeedsPerson(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "bastion0", "u@10.0.0.4")
	mustRun(t, "host", "add", "bastion", "u@10.0.0.5", "--via", "bastion0")
	mustRun(t, "host", "add", "other", "u@10.0.0.6")
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--login", "ask", "--via", "bastion")
	t.Setenv("PW", "x")
	mustRun(t, "host", "add", "web2", "u@10.0.0.2", "--password-ref", "env:PW")
	setCallerEnv(t, "CLAUDECODE", "1")

	needsPerson := func(want string, args ...string) {
		t.Helper()
		e := wantCode(t, "NEEDS_PERSON", args...)
		if !strings.Contains(e.Message, want) || !strings.Contains(e.Hint, "in their own terminal") || strings.Contains(e.Hint, "--yes") {
			t.Errorf("%v: %+v", args, e)
		}
	}
	needsPerson("evil", "host", "add", "evil", "u@203.0.113.66", "--login", "ask")
	for _, edit := range [][]string{
		{"--port", "2222"},
		{"--address", "203.0.113.66"},
		{"--user", "root"},
		{"--via", "other"},
		{"--unset", "via"},
		{"--address", "winrm://u@10.0.0.1"},
	} {
		needsPerson("web1", append([]string{"host", "edit", "web1"}, edit...)...)
	}
	needsPerson("web2", "host", "edit", "web2", "--login", "ask")
	// (--proxy-command stops first with SAFETY_SETTING; hostPlaceChanges
	// counts it too, TestLoginPlaceChanges)
	// the servers on the way: the password goes through them
	needsPerson("web1", "host", "edit", "bastion", "--address", "203.0.113.66")
	needsPerson("web1", "host", "edit", "bastion0", "--port", "2200")
	// the dry run is never blocked, and says what the real run needs
	d := mustRun(t, "host", "edit", "web1", "--port", "2222", "--dry-run")
	if m := asJSON(d["_meta"]); !strings.Contains(m, "NEEDS_PERSON") || strings.Contains(m, "SECRET_DESTINATION") {
		t.Errorf("dry run: %v", d)
	}
	// nothing about where it goes: no stop
	mustRun(t, "host", "edit", "web1", "--add-tag", "canary")
	mustRun(t, "host", "edit", "bastion", "--add-tag", "canary")
	mustRun(t, "host", "edit", "other", "--port", "2200")
	mustRun(t, "host", "edit", "web1", "--login", "agent") // nothing typed goes anywhere now
	st, _ := store.Load()
	if h := st.Hosts["bastion"]; h.Address != "10.0.0.5" {
		t.Errorf("a hop edit went through: %+v", h)
	}
	if h := st.Hosts["web2"]; h.AskLogin() {
		t.Errorf("web2 became login ask: %+v", h)
	}

	// a person at the terminal (or a script of theirs) sets it as before
	noAgent(t)
	mustRun(t, "host", "edit", "web2", "--login", "ask")
	mustRun(t, "host", "edit", "web2", "--port", "2222")
}

// The VPN on the way to a login-ask server is part of where its password
// goes: an AI agent that changes how the VPN connects, or replaces it,
// gets NEEDS_PERSON; its notes and tags are only words.
func TestLoginAskVpnOnTheWayNeedsPerson(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "office", "socks", "--proxy-address", "10.0.0.1:1080")
	mustRun(t, "vpn", "add", "lab", "socks", "--proxy-address", "10.0.0.2:1080")
	mustRun(t, "host", "add", "bastion", "u@10.1.0.5", "--via", "office")
	mustRun(t, "host", "add", "web1", "u@10.1.0.1", "--login", "ask", "--via", "bastion")
	setCallerEnv(t, "CLAUDECODE", "1")
	e := wantCode(t, "NEEDS_PERSON", "vpn", "edit", "office", "--proxy-address", "203.0.113.66:1080")
	if !strings.Contains(e.Message, "VPN office is on the way to server web1") {
		t.Errorf("%+v", e)
	}
	wantCode(t, "NEEDS_PERSON", "vpn", "add", "office", "socks", "--proxy-address", "203.0.113.66:1080", "--overwrite")
	mustRun(t, "vpn", "edit", "office", "--notes", "the office", "--add-tag", "x")
	mustRun(t, "vpn", "edit", "lab", "--proxy-address", "10.0.0.3:1080") // on nobody's way
	st, _ := store.Load()
	if v := st.Vpns["office"]; v.Address != "10.0.0.1:1080" {
		t.Errorf("the VPN changed: %+v", v)
	}
}

// LoginAskFor names the way to a server: the VPN, each jump host with
// its address, and a proxy command.
func TestLoginAskForWay(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "office", "socks", "--proxy-address", "10.0.0.1:1080")
	mustRun(t, "host", "add", "bastion", "jump@10.1.0.5:2200", "--via", "office")
	mustRun(t, "host", "add", "web1", "u@10.1.0.1", "--login", "ask", "--via", "bastion")
	mustRun(t, "host", "add", "web2", "u@10.1.0.2", "--login", "ask")
	st, _ := store.Load()
	if q := sshx.LoginAskFor(st, st.Hosts["web1"]); q.Path != "VPN office, then bastion (jump@10.1.0.5:2200)" || q.Addr != "10.1.0.1:22" {
		t.Errorf("web1: %+v", q)
	}
	if q := sshx.LoginAskFor(st, st.Hosts["web2"]); q.Path != "" {
		t.Errorf("web2: %+v", q)
	}
	h := *st.Hosts["web2"]
	h.ProxyCommand = "cloudflared access ssh --hostname %h"
	if q := sshx.LoginAskFor(st, &h); q.Path != "the proxy command `cloudflared access ssh --hostname %h`" {
		t.Errorf("proxy: %+v", q)
	}
}

// An OpenVPN VPN's profile is a vault secret: replacing it moves the VPN
// as an edit would, so for an AI agent it is NEEDS_PERSON while the VPN is
// on the way to a login-ask server.
func TestLoginAskVpnProfileSecretNeedsPerson(t *testing.T) {
	secretHome(t)
	profile := filepath.Join(t.TempDir(), "office.ovpn")
	if err := os.WriteFile(profile, []byte(testProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "vpn", "add", "office", "openvpn", "--config", profile, "--check", "10.8.0.1:22", "--user", "alice", "--password-ref", "secret:db-pass")
	mustRun(t, "host", "add", "web1", "u@10.8.0.5", "--login", "ask", "--via", "office")
	setCallerEnv(t, "CLAUDECODE", "1")
	t.Setenv("EVIL", "remote 203.0.113.66 1194")
	e := wantCode(t, "NEEDS_PERSON", "secret", "set", "office-config", "--from-env", "EVIL")
	if !strings.Contains(e.Message, "profile of VPN office") || !strings.Contains(e.Message, "server web1") {
		t.Errorf("%+v", e)
	}
	t.Setenv("OTHER", "x")
	mustRun(t, "secret", "set", "other-thing", "--from-env", "OTHER")
	wantCode(t, "NEEDS_PERSON", "secret", "cp", "other-thing", "office-config", "--overwrite")
	if v, _ := vault.Get("office-config"); strings.Contains(v, "203.0.113.66") || v == "x" {
		t.Error("the profile was replaced")
	}
}

// hostPlaceChanges counts each setting that moves a typed password, and
// connPlaceChanges a conn's URL and way.
func TestLoginPlaceChanges(t *testing.T) {
	s := &store.State{Hosts: map[string]*store.Host{}, Conns: map[string]*store.Conn{}, Vpns: map[string]*store.Vpn{}}
	ask := &store.Host{Name: "web1", Address: "10.0.0.1", User: "u", Login: store.LoginAsk}
	s.Hosts["web1"] = ask
	for _, change := range []func(h *store.Host){
		func(h *store.Host) { h.ProxyCommand = "nc %h %p" },
		func(h *store.Host) { h.Transport = store.TransportWinRM },
		func(h *store.Host) { h.Address = "10.0.0.9" },
	} {
		now := *ask
		change(&now)
		if got := hostPlaceChanges(s, []*store.Host{&now}, map[string]*store.Host{"web1": ask}); len(got) != 1 {
			t.Errorf("%+v: %q", now, got)
		}
	}
	same := *ask
	same.Notes, same.Tags = "x", []string{"y"}
	if got := hostPlaceChanges(s, []*store.Host{&same}, map[string]*store.Host{"web1": ask}); len(got) != 0 {
		t.Errorf("notes: %q", got)
	}
	db := &store.Conn{Name: "db1", URL: "postgres://app@10.0.0.5/app", Login: store.LoginAsk}
	moved := *db
	moved.URL = "postgres://app@203.0.113.66/app"
	if len(connPlaceChanges(db, &moved)) != 1 || len(connPlaceChanges(nil, db)) != 1 || len(connPlaceChanges(db, db)) != 0 {
		t.Error("connPlaceChanges")
	}
	moved.Via = "bastion"
	moved.URL = db.URL
	if len(connPlaceChanges(db, &moved)) != 1 {
		t.Error("a new way is a new place")
	}
}

// A script (no terminal, not an agent) cannot type a password: NEEDS_PERSON,
// nothing sent to the server.
func TestLoginAskScriptNeedsPerson(t *testing.T) {
	invHome(t)
	noAgent(t)
	port, tries, key := passwordSSHD(t, "pw-123456")
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	trustSSHD(t, "web1", port, key)
	e := wantCode(t, "NEEDS_PERSON", "exec", "web1", "--read-only", "--", "uptime")
	if e.Exit != out.ExitPolicy || !strings.Contains(e.Hint, "`komando test web1`") {
		t.Errorf("%+v", e)
	}
	if n := tries.Load(); n != 0 {
		t.Errorf("the server got %d passwords", n)
	}
}

// The first connection to a login-ask server, whose host key nobody has
// seen, is not an AI agent's to make: NEEDS_PERSON, no window, no
// password, and the key stays unpinned, so the next try asks the same.
func TestLoginAskFirstConnectionNeedsPerson(t *testing.T) {
	invHome(t)
	port, tries, key := passwordSSHD(t, "pw")
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")
	texts := loginWindow(t, "pw", true, true)
	wantCode(t, "NEEDS_PERSON", "test", "web1") // a look command logs in too
	for range 2 {
		e := wantCode(t, "NEEDS_PERSON", "exec", "web1", "--read-only", "--", "uptime")
		if !strings.Contains(e.Message, "has not met web1") || !strings.Contains(e.Hint, "`komando test web1`") || !strings.Contains(e.Message, "nothing was sent") {
			t.Fatalf("%+v", e)
		}
	}
	if len(*texts) != 0 || tries.Load() != 0 {
		t.Errorf("windows %d, passwords %d", len(*texts), tries.Load())
	}
	if pins, _ := sshx.PinnedKeys(net.JoinHostPort("127.0.0.1", port)); len(pins) != 0 {
		t.Errorf("the new key was pinned: %v", pins)
	}
	// once a person has met it, the agent's command asks in the window
	trustSSHD(t, "web1", port, key)
	if _, err := runCache(t, "-o", "json", "exec", "web1", "--read-only", "--", "uptime"); err != nil || len(*texts) != 1 {
		t.Errorf("after the pin: %v, %d windows", err, len(*texts))
	}
}

// A pinned key is not enough: an AI agent can pin whatever answers at an
// address through any server it adds there (host trust, or a connection),
// so a typed password goes to a login-ask server's key only after a
// person logged in to that server with it. The agent gets NEEDS_PERSON;
// a person's login (here: an app's window, which warns) notes it, and the
// agent's next command asks in the window.
func TestLoginAskPinAloneNeedsPerson(t *testing.T) {
	invHome(t)
	const pw = "pin-Pa55"
	port, tries, _ := passwordSSHD(t, pw)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")
	mustRun(t, "host", "add", "other", "u@127.0.0.1:"+port)
	mustRun(t, "host", "trust", "other")
	if pins, _ := sshx.PinnedKeys(net.JoinHostPort("127.0.0.1", port)); len(pins) != 1 {
		t.Fatalf("pins: %v", pins)
	}
	texts := loginWindow(t, pw, true, true)
	e := wantCode(t, "NEEDS_PERSON", "exec", "web1", "--read-only", "--", "uptime")
	if !strings.Contains(e.Message, "nobody has logged in to web1") || len(*texts) != 0 || tries.Load() != 0 {
		t.Fatalf("%+v; %d windows, %d passwords", e, len(*texts), tries.Load())
	}

	noAgent(t)
	var asked []string
	tcl.io.AskPassword = func(text string) (string, bool, bool) { asked = append(asked, text); return pw, true, true }
	if _, err := runCache(t, "-o", "json", "exec", "web1", "--read-only", "--", "uptime"); err != nil {
		t.Fatal(err)
	}
	tcl.io.AskPassword = nil
	if len(asked) != 1 || !strings.Contains(asked[0], "WARNING: first login to web1") {
		t.Fatalf("app window: %q", asked)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	if _, err := runCache(t, "-o", "json", "exec", "web1", "--read-only", "--", "uptime"); err != nil || len(*texts) != 1 || strings.Contains((*texts)[0], "WARNING") {
		t.Errorf("after a person's login: %v, %q", err, *texts)
	}
	// a rename keeps it: the login is noted by the server's record
	mustRun(t, "host", "rename", "web1", "web9")
	if _, err := runCache(t, "-o", "json", "exec", "web9", "--read-only", "--", "uptime"); err != nil {
		t.Errorf("after a rename: %v", err)
	}
}

// `komando login` is a person's: an AI agent's gets NEEDS_PERSON, and
// one that starts the login's background process itself (whose questions
// it would answer as if it were the person) gets NEEDS_PERSON before it
// connects, so it cannot accept a login-ask server's new key.
func TestLoginAskHolderIsAPersons(t *testing.T) {
	invHome(t)
	port, tries, _ := passwordSSHD(t, "pw")
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")
	wantCode(t, "NEEDS_PERSON", "login", "web1")
	tcl.stdin = strings.NewReader("TOKEN x\nUNTIL 4070908800\nPASS \nyes\npw\n")
	t.Cleanup(func() { tcl.stdin = nil })
	s, err := runCache(t, "login-holder", "web1")
	if err == nil || !strings.Contains(s, "NEEDS_PERSON") {
		t.Errorf("holder: %v\n%s", err, s)
	}
	if tries.Load() != 0 {
		t.Errorf("the server got %d passwords", tries.Load())
	}
	if pins, _ := sshx.PinnedKeys(net.JoinHostPort("127.0.0.1", port)); len(pins) != 0 {
		t.Errorf("the holder pinned the key for an agent: %v", pins)
	}
}

// An AI agent's command asks the person in komando's window: the typed
// password logs in, never reaches the agent's output, and a fleet run asks
// once per server.
func TestLoginAskAgentWindow(t *testing.T) {
	invHome(t)
	const pw = "typed-Pa55word"
	port1, tries1, key1 := passwordSSHD(t, pw)
	port2, tries2, key2 := passwordSSHD(t, pw)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port1, "--login", "ask", "--group", "web")
	mustRun(t, "host", "add", "web2", "u@127.0.0.1:"+port2, "--login", "ask", "--group", "web")
	trustSSHD(t, "web1", port1, key1)
	trustSSHD(t, "web2", port2, key2)
	setCallerEnv(t, "CLAUDECODE", "1")
	texts := loginWindow(t, pw, true, true)

	s, err := runCache(t, "-o", "json", "exec", "web1", "--read-only", "--", "uptime")
	if err != nil {
		t.Fatalf("%v\n%s", err, s)
	}
	if strings.Contains(s, pw) || !strings.Contains(s, "logged in with [hidden]") {
		t.Errorf("the typed password shows in the output:\n%s", s)
	}
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "Claude Code wants komando to log in to web1 as u@127.0.0.1:"+port1) ||
		strings.Contains((*texts)[0], pw) {
		t.Errorf("window: %q", *texts)
	}

	*texts = nil
	s, err = runCache(t, "-o", "json", "exec", "@web", "-P", "4", "--read-only", "--", "uptime")
	if err != nil || strings.Contains(s, pw) {
		t.Fatalf("%v\n%s", err, s)
	}
	if len(*texts) != 2 {
		t.Errorf("a fleet of two asked %d times", len(*texts))
	}
	if tries1.Load() != 2 || tries2.Load() != 1 {
		t.Errorf("passwords sent: %d, %d", tries1.Load(), tries2.Load())
	}
	// nothing typed is kept: the store holds no password
	b, _ := os.ReadFile(store.Path("store.db"))
	if strings.Contains(string(b), pw) {
		t.Error("the typed password is on disk")
	}
}

// A fleet run through Dial asks once per server: three login-ask servers,
// two of them behind a login-ask jump host, run in parallel, ask four
// windows (the jump host once, though two connections go through it),
// and each server gets the password once.
func TestLoginAskFleetAsksOncePerHost(t *testing.T) {
	invHome(t)
	const pw = "fleet-Pa55"
	bport, _, bkey := passwordSSHD(t, pw)
	mustRun(t, "host", "add", "bastion", "u@127.0.0.1:"+bport, "--login", "ask")
	trustSSHD(t, "bastion", bport, bkey)
	tries := map[string]*atomic.Int32{}
	for _, n := range []string{"web1", "web2", "web3"} {
		port, tr, key := passwordSSHD(t, pw)
		args := []string{"host", "add", n, "u@127.0.0.1:" + port, "--login", "ask", "--group", "web"}
		if n != "web3" {
			args = append(args, "--via", "bastion")
		}
		mustRun(t, args...)
		trustSSHD(t, n, port, key)
		tries[n] = tr
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	texts := loginWindow(t, pw, true, true)
	s, err := runCache(t, "-o", "json", "exec", "@web", "-P", "3", "--read-only", "--", "uptime")
	if err != nil || strings.Contains(s, pw) {
		t.Fatalf("%v\n%s", err, s)
	}
	asked := map[string]int{}
	for _, text := range *texts {
		for _, n := range []string{"bastion", "web1", "web2", "web3"} {
			if strings.Contains(text, "log in to "+n+" as") {
				asked[n]++
			}
		}
	}
	if len(*texts) != 4 || asked["bastion"] != 1 || asked["web1"] != 1 || asked["web2"] != 1 || asked["web3"] != 1 {
		t.Errorf("windows: %v (%d)", asked, len(*texts))
	}
	for n, tr := range tries {
		if tr.Load() != 1 {
			t.Errorf("%s got the password %d times", n, tr.Load())
		}
	}
}

// No screen, a cancel, a wrong password: each stops with its own code, and
// a refused password is not sent again. After a cancel the window stays
// shut for that server for a minute.
func TestLoginAskAgentStops(t *testing.T) {
	invHome(t)
	port, tries, key := passwordSSHD(t, "right-password")
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	trustSSHD(t, "web1", port, key)
	setCallerEnv(t, "CLAUDECODE", "1")

	loginWindow(t, "", false, false)
	e := wantCode(t, "NEEDS_PERSON", "exec", "web1", "--read-only", "--", "uptime")
	if !strings.Contains(e.Hint, "`komando test web1`") || !strings.Contains(e.Hint, "never ask for the password in the chat") {
		t.Errorf("no screen: %+v", e)
	}
	texts := loginWindow(t, "", false, true)
	e = wantCode(t, "DECLINED", "exec", "web1", "--read-only", "--", "uptime")
	if e.Hint != "do not retry: ask the user to run `komando test web1` in their own terminal" {
		t.Errorf("cancel: %+v", e)
	}
	// the cool-down: no second window, even for a look command
	wantCode(t, "DECLINED", "test", "web1")
	e = wantCode(t, "DECLINED", "exec", "web1", "--read-only", "--", "uptime")
	if len(*texts) != 1 || !strings.Contains(e.Message, "less than a minute ago") || !strings.Contains(e.Hint, "`komando test web1`") {
		t.Errorf("cool-down: %d windows, %+v", len(*texts), e)
	}
	// a rename does not end it
	mustRun(t, "host", "rename", "web1", "web9")
	if e := wantCode(t, "DECLINED", "exec", "web9", "--read-only", "--", "uptime"); len(*texts) != 1 || !strings.Contains(e.Message, "less than a minute ago") {
		t.Errorf("after a rename: %d windows, %+v", len(*texts), e)
	}
	mustRun(t, "host", "rename", "web9", "web1")
	if n := tries.Load(); n != 0 {
		t.Fatalf("the server got %d passwords", n)
	}
	// a minute later the window may open again
	if err := store.UpdateRuntime(store.Save(), func(s *store.State) error {
		for id := range s.LoginDeclined {
			s.LoginDeclined[id] = time.Now().Add(-loginCoolDown)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loginWindow(t, "wrong-password", true, true)
	e = wantCode(t, "AUTH_FAILED", "exec", "web1", "--read-only", "--", "uptime")
	if strings.Contains(e.Message+e.Hint, "wrong-password") || !strings.Contains(e.Message, "refused the password typed") {
		t.Errorf("wrong password: %+v", e)
	}
	if n := tries.Load(); n != 1 {
		t.Errorf("a refused password went out %d times", n)
	}
}

// ssh-gate runs commands as an agent with no window: NEEDS_PERSON.
func TestLoginAskGateNeedsPerson(t *testing.T) {
	invHome(t)
	port, _, key := passwordSSHD(t, "pw")
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	trustSSHD(t, "web1", port, key)
	setCallerEnv(t, engine.GateEnv, "phone")
	texts := loginWindow(t, "pw", true, true)
	wantCode(t, "NEEDS_PERSON", "exec", "web1", "--read-only", "--", "uptime")
	if len(*texts) != 0 {
		t.Errorf("ssh-gate opened a window: %q", *texts)
	}
}

// An app's call asks in the app's own window (engine.Call.AskPassword); on
// a first connection the window says so.
func TestLoginAskAppWindow(t *testing.T) {
	invHome(t)
	noAgent(t)
	const pw = "app-typed-pw"
	port, _, _ := passwordSSHD(t, pw)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	var asked []string
	tcl.io.AskPassword = func(text string) (string, bool, bool) { asked = append(asked, text); return pw, true, true }
	t.Cleanup(func() { tcl.io.AskPassword = nil })
	for range 2 {
		s, err := runCache(t, "-o", "json", "exec", "web1", "--read-only", "--", "uptime")
		if err != nil || strings.Contains(s, pw) {
			t.Fatalf("%v %q\n%s", err, asked, s)
		}
	}
	if len(asked) != 2 || !strings.Contains(asked[0], "WARNING: first connection to 127.0.0.1:"+port) || strings.Contains(asked[1], "WARNING") {
		t.Fatalf("windows: %q", asked)
	}
}

// Connections of one command to one server share the typed password, even
// when they ask at the same time; a refused one is asked again.
func TestLoginAskOncePerServer(t *testing.T) {
	invHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	texts := loginWindow(t, "pw", true, true)
	q := sshx.LoginAsk{Host: &store.Host{Name: "web1", Address: "10.0.0.1", Login: store.LoginAsk}, User: "u", Addr: "10.0.0.1:22"}
	var wg sync.WaitGroup
	var forget func()
	var mu sync.Mutex
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, f, err := tcl.loginPassword(q)
			if err != nil || got != "pw" {
				t.Errorf("%q %v", got, err)
			}
			mu.Lock()
			forget = f
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(*texts) != 1 {
		t.Fatalf("asked %d times", len(*texts))
	}
	forget()
	if _, _, err := tcl.loginPassword(q); err != nil || len(*texts) != 2 {
		t.Errorf("after a refusal: %v, asked %d times", err, len(*texts))
	}
	// a new host key on a later connection: never for an agent
	k := sshx.NewHostKey{Host: "web1", Address: "10.0.0.1:22", Type: "ssh-ed25519", Fingerprint: "SHA256:x"}
	q.NewKey = &k
	if _, _, err := tcl.loginPassword(q); err == nil || toErr(err).Code != "NEEDS_PERSON" {
		t.Errorf("new key: %v", err)
	}
	resetApproval() // the command ended: nothing typed is kept
	if len(tcl.logins.pw) != 0 {
		t.Error("typed passwords outlive the command")
	}
}

// A tunnel's background process gets the typed passwords from tunnel
// start on its input, and asks nobody itself.
func TestLoginAskTunnelHandoff(t *testing.T) {
	invHome(t)
	cl := testCall()
	in := loginsInput(map[string]string{"web1": "p w\n1", "bastion": "b"})
	cl.logins.background = true
	if err := readLogins(cl, bufio.NewReader(in)); err != nil {
		t.Fatal(err)
	}
	ask := func(name string) sshx.LoginAsk {
		return sshx.LoginAsk{Host: &store.Host{Name: name, Login: store.LoginAsk}, User: "u", Addr: "10.0.0.1:22"}
	}
	if pw, _, err := cl.loginPassword(ask("web1")); err != nil || pw != "p w\n1" {
		t.Errorf("web1: %q %v", pw, err)
	}
	if _, _, err := cl.loginPassword(ask("db1")); err == nil || toErr(err).Code != "NEEDS_PERSON" {
		t.Errorf("a server tunnel start typed nothing for: %v", err)
	}
	// nor does it trust a new host key: nobody would see it
	if err := cl.loginNewKey(ask("web1").Host, sshx.NewHostKey{Host: "web1", Address: "10.0.0.1:22"}); err == nil || toErr(err).Code != "NEEDS_PERSON" {
		t.Errorf("new key in the background: %v", err)
	}
}

// The window names the agent, the server, its user, address and port and
// the command (or says the command is hidden), warns on a first
// connection, says look commands log in too, and that the password stays
// with komando.
func TestLoginAskWindowText(t *testing.T) {
	setCallerEnv(t, "CLAUDECODE", "1")
	cl := testCall()
	cl.args = []string{"komando", "exec", "web1", "--read-only", "--", "uptime"}
	q := sshx.LoginAsk{Host: &store.Host{Name: "web1", Address: "10.0.0.1", User: "deploy", Login: store.LoginAsk}, User: "deploy", Addr: "10.0.0.1:2222"}
	text := loginWindowText(cl, hostTarget(q))
	for _, want := range []string{"Claude Code wants komando to log in to web1 as deploy@10.0.0.1:2222 for:", "komando exec web1 --read-only -- uptime",
		"the agent never sees it", "even one that only looks (komando test"} {
		if !strings.Contains(text, want) {
			t.Errorf("window text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "WARNING") {
		t.Errorf("a known server warned:\n%s", text)
	}
	cl.args = []string{"komando", "exec", "web1", "--", "echo", "a\u202eb"}
	k := sshx.NewHostKey{Host: "web1", Address: "10.0.0.1:2222", Type: "ssh-ed25519", Fingerprint: "SHA256:abc"}
	q.NewKey = &k
	text = loginWindowText(cl, hostTarget(q))
	for _, want := range []string{"The command is hidden here", "WARNING: first connection to 10.0.0.1:2222", "SHA256:abc"} {
		if !strings.Contains(text, want) {
			t.Errorf("window text lacks %q:\n%s", want, text)
		}
	}
	// the way there is part of where the password goes: the window names
	// every step komando dials through
	q.NewKey, q.Path = nil, "VPN office, then bastion (u@10.1.0.5:22)"
	if text = loginWindowText(cl, hostTarget(q)); !strings.Contains(text, "deploy@10.0.0.1:2222, reached through VPN office, then bastion (u@10.1.0.5:22)") {
		t.Errorf("path:\n%s", text)
	}
	q.Path = ""
	q.NewKey = &k
	k.Unchecked, k.Fingerprint = true, ""
	if text = loginWindowText(cl, hostTarget(q)); !strings.Contains(text, "WARNING: komando does not check who answers at 10.0.0.1:2222") {
		t.Errorf("unchecked:\n%s", text)
	}
}
