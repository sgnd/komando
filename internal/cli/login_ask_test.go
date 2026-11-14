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

// trustSSHD pins a test server's host key, as a person's first connection
// would: an AI agent's command never trusts a login-ask server's new key.
func trustSSHD(t *testing.T, port string, key ssh.PublicKey) {
	t.Helper()
	if _, err := sshx.PinHostKey(net.JoinHostPort("127.0.0.1", port), key, false); err != nil {
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

// loginOf is the login field of every row of a host list.
func loginOf(t *testing.T) map[string]any {
	t.Helper()
	logins := map[string]any{}
	for _, r := range mustRun(t, "host", "list")["targets"].([]any) {
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
		wantCode(t, "USAGE", append([]string{"host", "add", "web2", "u@10.0.0.2"}, bad...)...)
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

// The example of host edit reads in komando schema as written: no word
// after "password:" that the output hides.
func TestLoginAskExampleNotHidden(t *testing.T) {
	invHome(t)
	s, err := runCache(t, "-o", "json", "schema", "host", "edit")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "never store its password; type it at every connect") || strings.Contains(s, "password: [hidden]") {
		t.Errorf("schema host edit:\n%s", s)
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

// A login-ask server's address is where a person's password goes: an AI
// agent that adds one, or points one somewhere else, needs a person's yes
// (SECRET_DESTINATION), as for a stored password. Other edits do not ask.
func TestLoginAskDestinationNeedsYes(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "bastion", "u@10.0.0.5")
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--login", "ask")
	t.Setenv("PW", "x")
	mustRun(t, "host", "add", "web2", "u@10.0.0.2", "--password-ref", "env:PW")
	setCallerEnv(t, "CLAUDECODE", "1")

	e := wantCode(t, "SECRET_DESTINATION", "host", "add", "evil", "u@203.0.113.66", "--login", "ask")
	if !strings.Contains(e.Message, "login ask") || !strings.Contains(e.Message, "203.0.113.66") {
		t.Errorf("add: %+v", e)
	}
	for _, edit := range [][]string{
		{"--port", "2222"},
		{"--address", "203.0.113.66"},
		{"--user", "root"},
		{"--via", "bastion"},
		{"--address", "winrm://u@10.0.0.1"},
	} {
		if e := wantCode(t, "SECRET_DESTINATION", append([]string{"host", "edit", "web1"}, edit...)...); !strings.Contains(e.Message, "login ask") {
			t.Errorf("%v: %+v", edit, e)
		}
	}
	// the dry run is never blocked, and says what the real run needs
	d := mustRun(t, "host", "edit", "web1", "--port", "2222", "--dry-run")
	if !strings.Contains(asJSON(d["_meta"]), "SECRET_DESTINATION") {
		t.Errorf("dry run: %v", d)
	}
	// nothing new goes anywhere: no question
	mustRun(t, "host", "edit", "web1", "--add-tag", "canary")
	mustRun(t, "host", "edit", "web2", "--login", "ask") // its stored password went there already
	st, _ := store.Load()
	if h := st.Hosts["web1"]; h.Port != 0 || h.User != "u" || h.Via != "" {
		t.Errorf("an edit went through: %+v", h)
	}
}

// A script (no terminal, not an agent) cannot type a password: NEEDS_PERSON,
// nothing sent to the server.
func TestLoginAskScriptNeedsPerson(t *testing.T) {
	invHome(t)
	noAgent(t)
	port, tries, key := passwordSSHD(t, "pw-123456")
	trustSSHD(t, port, key)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	e := wantCode(t, "NEEDS_PERSON", "exec", "web1", "--read-only", "--", "uptime")
	if e.Exit != out.ExitPolicy || !strings.Contains(e.Hint, "`komando login web1`") {
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
		if !strings.Contains(e.Message, "has not met web1") || !strings.Contains(e.Hint, "`komando login web1`") || !strings.Contains(e.Message, "nothing was sent") {
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
	trustSSHD(t, port, key)
	if _, err := runCache(t, "-o", "json", "exec", "web1", "--read-only", "--", "uptime"); err != nil || len(*texts) != 1 {
		t.Errorf("after the pin: %v, %d windows", err, len(*texts))
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
	trustSSHD(t, port1, key1)
	trustSSHD(t, port2, key2)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port1, "--login", "ask", "--group", "web")
	mustRun(t, "host", "add", "web2", "u@127.0.0.1:"+port2, "--login", "ask", "--group", "web")
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
	trustSSHD(t, bport, bkey)
	mustRun(t, "host", "add", "bastion", "u@127.0.0.1:"+bport, "--login", "ask")
	tries := map[string]*atomic.Int32{}
	for _, n := range []string{"web1", "web2", "web3"} {
		port, tr, key := passwordSSHD(t, pw)
		trustSSHD(t, port, key)
		args := []string{"host", "add", n, "u@127.0.0.1:" + port, "--login", "ask", "--group", "web"}
		if n != "web3" {
			args = append(args, "--via", "bastion")
		}
		mustRun(t, args...)
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
	trustSSHD(t, port, key)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")

	loginWindow(t, "", false, false)
	e := wantCode(t, "NEEDS_PERSON", "exec", "web1", "--read-only", "--", "uptime")
	if !strings.Contains(e.Hint, "`komando login web1`") || !strings.Contains(e.Hint, "never ask for the password in the chat") {
		t.Errorf("no screen: %+v", e)
	}
	texts := loginWindow(t, "", false, true)
	e = wantCode(t, "DECLINED", "exec", "web1", "--read-only", "--", "uptime")
	if e.Hint != "do not retry: ask the user to run `komando login web1` in their own terminal" {
		t.Errorf("cancel: %+v", e)
	}
	// the cool-down: no second window, even for a look command
	wantCode(t, "DECLINED", "test", "web1")
	e = wantCode(t, "DECLINED", "exec", "web1", "--read-only", "--", "uptime")
	if len(*texts) != 1 || !strings.Contains(e.Message, "less than a minute ago") || !strings.Contains(e.Hint, "`komando login web1`") {
		t.Errorf("cool-down: %d windows, %+v", len(*texts), e)
	}
	if n := tries.Load(); n != 0 {
		t.Fatalf("the server got %d passwords", n)
	}
	// a minute later the window may open again
	if err := store.UpdateRuntime(store.Save(), func(s *store.State) error {
		s.LoginDeclined["web1"] = time.Now().Add(-loginCoolDown)
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
	trustSSHD(t, port, key)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
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
	text := loginWindowText(cl, q)
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
	text = loginWindowText(cl, q)
	for _, want := range []string{"The command is hidden here", "WARNING: first connection to 10.0.0.1:2222", "SHA256:abc"} {
		if !strings.Contains(text, want) {
			t.Errorf("window text lacks %q:\n%s", want, text)
		}
	}
	k.Unchecked, k.Fingerprint = true, ""
	if text = loginWindowText(cl, q); !strings.Contains(text, "WARNING: komando does not check who answers at 10.0.0.1:2222") {
		t.Errorf("unchecked:\n%s", text)
	}
}
