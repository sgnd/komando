package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// loginSSHD is a loopback SSH server with cfg's login rules (and a fresh
// host key unless cfg has one). It opens no channels.
func loginSSHD(t *testing.T, cfg *ssh.ServerConfig, hostKey ssh.Signer) (string, int) {
	t.Helper()
	if hostKey == nil {
		hostKey = newSigner(t)
	}
	cfg.AddHostKey(hostKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					nc.Close()
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					nch.Reject(ssh.Prohibited, "no channels here")
				}
			}()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// keyOnlySSHD lets in only the client key pub.
func keyOnlySSHD(t *testing.T, pub ssh.PublicKey) (string, int) {
	t.Helper()
	return loginSSHD(t, &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if SameKey(k, pub) {
			return nil, nil
		}
		return nil, errors.New("not this key")
	}}, nil)
}

// scratchAgent serves an in-process ssh-agent holding keys on a short
// socket path under /tmp, and points SSH_AUTH_SOCK at it. The user's own
// agent is never touched.
func scratchAgent(t *testing.T, keys ...any) {
	t.Helper()
	base := "/tmp" // short: a Unix socket path has a small limit
	if runtime.GOOS == "windows" {
		base = "" // no /tmp there; the user's TEMP is short enough
	}
	dir, err := os.MkdirTemp(base, "kag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(kr, c); c.Close() }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
}

// encryptedKey writes an ed25519 key with a passphrase to dir/name and
// returns the path and the private key (for the agent).
func encryptedKey(t *testing.T, dir, name string) (string, ed25519.PrivateKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, priv
}

func pubOf(t *testing.T, priv any) ssh.PublicKey {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s.PublicKey()
}

func dialHost(st *store.State, h *store.Host) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := Dial(ctx, st, h, Options{ConnectTimeout: 5 * time.Second, HostKeyPolicy: "off"})
	if c != nil {
		c.Close()
	}
	return err
}

// An encrypted IdentityFile (what `import ssh-config` makes of one) or
// --key key with no passphrase ref logs in with the same key from
// ssh-agent, as OpenSSH does. Only when the agent does not hold it is it
// KEY_PASSPHRASE_REQUIRED (exit 2), with commands that work.
func TestEncryptedKeyFromAgent(t *testing.T) {
	type setup struct {
		agentKeys []any // nil: no SSH_AUTH_SOCK
		viaKey    bool  // a keychain key (--key work) instead of --identity
	}
	cases := []struct {
		name     string
		setup    setup
		inAgent  bool // the agent holds the encrypted key
		code     string
		inHint   []string
		notHints []string
	}{
		{name: "identity in the agent", inAgent: true},
		{name: "keychain key in the agent", setup: setup{viaKey: true}, inAgent: true},
		{name: "agent holds other keys", setup: setup{agentKeys: []any{otherKey()}}, code: "KEY_PASSPHRASE_REQUIRED",
			inHint:   []string{"load it with `ssh-add ~/.ssh/id_ed25519`", "`komando secret set id_ed25519-pass`", "`komando key add id_ed25519 ~/.ssh/id_ed25519 --passphrase-ref secret:id_ed25519-pass`", "`komando host edit web1 --key id_ed25519 --unset identity`"},
			notHints: []string{"start ssh-agent", "<name>"}},
		{name: "no agent", code: "KEY_PASSPHRASE_REQUIRED", inHint: []string{"start ssh-agent and load it with `ssh-add ~/.ssh/id_ed25519`"}},
		{name: "keychain key, agent holds other keys", setup: setup{agentKeys: []any{otherKey()}, viaKey: true}, code: "KEY_PASSPHRASE_REQUIRED",
			inHint:   []string{"`komando secret set work-pass`, then `komando key edit work --passphrase-ref secret:work-pass`"},
			notHints: []string{"<name>", "key add"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialHome(t)
			home, _ := os.UserHomeDir()
			path, priv := encryptedKey(t, filepath.Join(home, ".ssh"), "id_ed25519")
			keys := tc.setup.agentKeys
			if tc.inAgent {
				keys = append([]any{otherKey(), priv}, keys...)
			}
			if keys != nil {
				scratchAgent(t, keys...)
			}
			host, port := keyOnlySSHD(t, pubOf(t, priv))
			h := &store.Host{Name: "web1", Address: host, Port: port, User: "u", Identity: path}
			st := newState(h)
			if tc.setup.viaKey {
				h.Identity, h.Key = "", "work"
				st.Keys["work"] = &store.Key{Name: "work", Path: path}
			}
			err := dialHost(st, h)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("login with the agent's copy of the key: %v", err)
				}
				return
			}
			oe := asOutErr(t, err)
			if oe.Code != tc.code || oe.Exit != out.ExitUsage {
				t.Fatalf("got %s exit %d (%s), want %s exit 2", oe.Code, oe.Exit, oe.Message, tc.code)
			}
			for _, s := range tc.inHint {
				if !strings.Contains(oe.Hint, s) {
					t.Errorf("hint lacks %q: %s", s, oe.Hint)
				}
			}
			for _, s := range tc.notHints {
				if strings.Contains(oe.Hint, s) {
					t.Errorf("hint has %q: %s", s, oe.Hint)
				}
			}
		})
	}
}

func otherKey() ed25519.PrivateKey {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return priv
}

// An old PEM key with a passphrase keeps no public key in the clear: the
// .pub file next to it finds its copy in ssh-agent.
func TestEncryptedPEMKeyFromAgentByPubFile(t *testing.T) {
	dialHome(t)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1019 the legacy format is the point of the test
	blk, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk), []byte("pw"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy")
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	pub := pubOf(t, rk)
	scratchAgent(t, otherKey(), rk)
	host, port := keyOnlySSHD(t, pub)
	h := &store.Host{Name: "web1", Address: host, Port: port, User: "u", Identity: path}
	if err := dialHost(newState(h), h); asOutErr(t, err).Code != "KEY_PASSPHRASE_REQUIRED" {
		t.Fatalf("without a .pub file: %v", err)
	}
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := dialHost(newState(h), h); err != nil {
		t.Fatalf("with a .pub file: %v", err)
	}
}

// The agent's copy of an encrypted explicit key is offered first, before
// the agent's other keys (a server may allow only a few tries).
func TestAgentCopyOfExplicitKeyGoesFirst(t *testing.T) {
	a, b, c := newSigner(t), newSigner(t), newSigner(t)
	lk := &loginKeys{locked: []lockedKey{{path: "/k", pub: c.PublicKey()}}, agent: agentHasKeys}
	got, err := lk.fromAgent(newState(), &store.Host{Name: "web1"}, []ssh.Signer{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != c || got[1] != a || got[2] != b {
		t.Errorf("order: %v", got)
	}
}

// otpServer asks the questions in rounds; it counts every answer that
// carries the password, and records which questions got an answer.
type otpServer struct {
	pw       string
	rounds   [][]string // the questions, round by round
	echo     bool
	password bool // also offer the password method

	mu       sync.Mutex
	answered []string // the questions answered
	sentPW   int      // times the password came
}

func (s *otpServer) start(t *testing.T) (string, int) {
	t.Helper()
	cfg := &ssh.ServerConfig{KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		for _, qs := range s.rounds {
			echos := make([]bool, len(qs))
			for i := range echos {
				echos[i] = s.echo
			}
			ans, err := ask("", "", qs, echos)
			if err != nil {
				return nil, err
			}
			s.mu.Lock()
			for i, a := range ans {
				s.answered = append(s.answered, qs[i])
				if a == s.pw {
					s.sentPW++
				}
			}
			s.mu.Unlock()
			if len(ans) != len(qs) || (len(ans) > 0 && ans[0] != s.pw) {
				return nil, errors.New("wrong")
			}
		}
		return nil, nil
	}}
	if s.password {
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if string(pw) == s.pw {
				s.sentPW++
			}
			return nil, errors.New("wrong")
		}
	}
	return loginSSHD(t, cfg, nil)
}

// The stored password goes out at most once per login, and only to a
// hidden question that asks for it: never as a one-time code, which would
// count as a failed login (and can lock the account).
func TestPasswordIsNeverSentAsACode(t *testing.T) {
	const pw = "s3cret-Pass"
	cases := []struct {
		name      string
		srv       *otpServer
		stored    string
		ok        bool
		sentPW    int
		answered  []string
		inMessage string
		inHint    string
	}{
		{name: "password only", srv: &otpServer{rounds: [][]string{{"Password: "}}}, stored: pw, ok: true, sentPW: 1, answered: []string{"Password: "}},
		{name: "password, then a code", srv: &otpServer{rounds: [][]string{{"Password: "}, {"Verification code: "}}}, stored: pw, sentPW: 1, answered: []string{"Password: "},
			inMessage: `web1 asks "Verification code:" (two-factor login)`, inHint: "komando asks you for the code once and keeps the login"},
		{name: "a code first", srv: &otpServer{rounds: [][]string{{"Enter your OTP\x1b[2J: "}, {"Password: "}}}, stored: pw,
			inMessage: `web1 asks "Enter your OTP [2J:" (two-factor login)`},
		{name: "password and code in one round", srv: &otpServer{rounds: [][]string{{"Password: ", "One-time token: "}}}, stored: pw,
			inMessage: `"One-time token:" (two-factor login)`},
		{name: "a shown question", srv: &otpServer{rounds: [][]string{{"Password: "}}, echo: true}, stored: pw,
			inMessage: `web1 asks "Password:"; komando answers only a hidden password question by itself`},
		{name: "a wrong password is sent once", srv: &otpServer{rounds: [][]string{{"Password: "}}, password: true}, stored: "old-pass",
			inMessage: `web1 asks "Password:" again`, inHint: "the password that env:KOMANDO_TEST_PW holds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialHome(t)
			tc.srv.pw = pw
			if tc.name == "a wrong password is sent once" {
				tc.srv.pw = tc.stored // count the stored one
				tc.sentPW = 1
			}
			t.Setenv("KOMANDO_TEST_PW", tc.stored)
			host, port := tc.srv.start(t)
			h := &store.Host{Name: "web1", Address: host, Port: port, User: "u", PasswordRef: "env:KOMANDO_TEST_PW"}
			err := dialHost(newState(h), h)
			tc.srv.mu.Lock()
			sent, answered := tc.srv.sentPW, tc.srv.answered
			tc.srv.mu.Unlock()
			if sent != tc.sentPW || strings.Join(answered, "|") != strings.Join(tc.answered, "|") {
				t.Errorf("the password went out %d times (want %d); answered %q, want %q", sent, tc.sentPW, answered, tc.answered)
			}
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			oe := asOutErr(t, err)
			if oe.Code != "AUTH_FAILED" || oe.Exit != out.ExitConnect {
				t.Fatalf("got %s exit %d (%s)", oe.Code, oe.Exit, oe.Message)
			}
			if !strings.Contains(oe.Message, tc.inMessage) || !strings.Contains(oe.Hint, tc.inHint) {
				t.Errorf("message %q\nhint %q\nwant %q and %q", oe.Message, oe.Hint, tc.inMessage, tc.inHint)
			}
			if strings.Contains(oe.Hint, "key deploy") {
				t.Errorf("hint suggests key deploy, which logs in the same way: %s", oe.Hint)
			}
		})
	}
}

func TestQuestionKind(t *testing.T) {
	cases := map[string]int{
		"Password: ":                      askPassword,
		"(root@web1) Password:":           askPassword,
		"(deploy@code-01) Password:":      askPassword, // the host's name does not count
		"Verification code: ":             askCode,
		"Enter PASSCODE:":                 askCode,
		"One-time password (OATH) for u:": askCode,
		"Duo two-factor TOKEN:":           askCode,
		"TOTP:":                           askCode,
		"Username:":                       askOther,
		"Passwort:":                       askPassword,
	}
	for q, want := range cases {
		if got := questionKind(q, false); got != want {
			t.Errorf("%q: kind %d, want %d", q, got, want)
		}
	}
	if questionKind("Password:", true) != askOther {
		t.Error("a shown answer must not get the password")
	}
	if got := cleanQuestion("Code\x1b]52;c;ZXZpbA==\a\r\n  \u202eplease:" + strings.Repeat("x", 100)); strings.ContainsAny(got, "\x1b\a\r\n\u202e") || len([]rune(got)) > 80 {
		t.Errorf("not cleaned: %q", got)
	}
}

// NO_AUTH says what to do for the reason it found, and mentions starting
// ssh-agent only when SSH_AUTH_SOCK is unset.
func TestNoAuthHints(t *testing.T) {
	cases := []struct {
		name      string
		encrypted bool   // ~/.ssh/id_ed25519 is encrypted
		agent     string // "unset", "empty" or "down"
		hint      []string
		notHint   []string
	}{
		{"encrypted default key, empty agent", true, "empty", []string{"run `ssh-add ~/.ssh/id_ed25519`"}, []string{"start ssh-agent"}},
		{"encrypted default key, no agent", true, "unset", []string{"start ssh-agent, then run `ssh-add ~/.ssh/id_ed25519`"}, nil},
		{"encrypted default key, agent down", true, "down", []string{"`ssh-add ~/.ssh/id_ed25519`"}, []string{"start ssh-agent"}},
		{"empty agent", false, "empty", []string{"run `ssh-add`"}, []string{"start ssh-agent"}},
		{"no agent", false, "unset", []string{"save its password: `komando secret set web1-pass`, then `komando host edit web1 --password-ref secret:web1-pass` (or --key KEY)", "start ssh-agent"}, nil},
		{"agent down", false, "down", []string{"`komando host edit web1 --password-ref secret:web1-pass`"}, []string{"start ssh-agent"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialHome(t)
			if tc.encrypted {
				home, _ := os.UserHomeDir()
				encryptedKey(t, filepath.Join(home, ".ssh"), "id_ed25519")
			}
			switch tc.agent {
			case "empty":
				scratchAgent(t)
			case "down":
				t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "gone.sock"))
			}
			h := &store.Host{Name: "web1", Address: "10.0.0.1"}
			_, _, err := authMethods(newState(h), h, time.Second)
			oe := asOutErr(t, err)
			if oe.Code != "NO_AUTH" || oe.Exit != out.ExitConnect {
				t.Fatalf("got %s exit %d", oe.Code, oe.Exit)
			}
			for _, s := range tc.hint {
				if !strings.Contains(oe.Hint, s) {
					t.Errorf("hint lacks %q: %s", s, oe.Hint)
				}
			}
			for _, s := range tc.notHint {
				if strings.Contains(oe.Hint, s) {
					t.Errorf("hint has %q: %s", s, oe.Hint)
				}
			}
		})
	}
}

// AUTH_FAILED never sends a host to `key deploy` (it logs in the same way);
// a password-only host is told how to store the new password.
func TestAuthFailedHint(t *testing.T) {
	for _, tc := range []struct {
		h    *store.Host
		want string
	}{
		{&store.Host{Name: "web1", PasswordRef: "secret:web1-pass"}, "`komando secret set web1-pass`"},
		{&store.Host{Name: "web1", PasswordRef: "env:WEB1_PASS"}, "the password that env:WEB1_PASS holds"},
		{&store.Host{Name: "web1", Key: "work"}, "check the user and key with `komando host show web1`"},
		{&store.Host{Name: "u@10.0.0.1:22"}, "`komando host add NAME u@10.0.0.1:22 --key KEY`"},
		{&store.Host{Name: "10.0.0.1"}, "`komando host add NAME 10.0.0.1 --key KEY`"},
	} {
		st := newState(tc.h)
		if tc.h.Name == "10.0.0.1" {
			st = newState() // a target typed as an address, not in the inventory
		}
		hint := authFailedHint(st, tc.h)
		if !strings.Contains(hint, tc.want) || strings.Contains(hint, "key deploy") {
			t.Errorf("%+v: %s", tc.h, hint)
		}
	}
	// `host ssh-command` needs a server from the inventory
	q := &unanswered{question: "Verification code:", kind: askCode}
	if e := q.authFailed(newState(), &store.Host{Name: "10.0.0.1"}); strings.Contains(e.Hint, "ssh-command") {
		t.Errorf("ad-hoc target: %s", e.Hint)
	}
}

// HOSTKEY_MISMATCH names the full fingerprint the server shows now. An
// agent is told to report it; a person at a terminal how to check it.
func TestHostKeyMismatchShowsTheFingerprint(t *testing.T) {
	dialHome(t)
	shown, pinned := newSigner(t), newSigner(t)
	host, port := testSSHD(t, shown)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if _, err := PinHostKey(addr, pinned.PublicKey(), false); err != nil {
		t.Fatal(err)
	}
	h := &store.Host{Name: "web1", Address: host, Port: port, User: "u", Identity: clientKey(t)}
	dial := func() *out.Error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := Dial(ctx, newState(h), h, Options{ConnectTimeout: 5 * time.Second, HostKeyPolicy: "accept-new"})
		if c != nil {
			c.Close()
		}
		return asOutErr(t, err)
	}
	e := dial()
	want := "pinned " + ssh.FingerprintSHA256(pinned.PublicKey()) + ", the server now shows " + ssh.FingerprintSHA256(shown.PublicKey())
	if e.Code != "HOSTKEY_MISMATCH" || e.Exit != out.ExitConnect || !strings.Contains(e.Message, want) {
		t.Fatalf("got %s exit %d: %s", e.Code, e.Exit, e.Message)
	}
	if !strings.Contains(e.Hint, "report this to the user") || strings.Contains(e.Hint, "console") {
		t.Errorf("agent hint: %s", e.Hint)
	}
	saved := PersonAtTerminal
	PersonAtTerminal = func() bool { return true }
	defer func() { PersonAtTerminal = saved }()
	e = dial()
	if e.Hint != "if you rebuilt web1, compare this fingerprint with the one on its console, then run `komando host trust web1 --reset`" {
		t.Errorf("person hint: %s", e.Hint)
	}
}

func TestSudoHintNamesTheHost(t *testing.T) {
	got := sudoHint(&store.Host{Name: "web1"})
	if strings.Contains(got, "<") || !strings.Contains(got, "`komando secret set web1-sudo`, then run `komando host edit web1 --sudo-ref secret:web1-sudo`") {
		t.Errorf("hint: %s", got)
	}
	if got := sudoHint(&store.Host{Name: "u@10.0.0.1"}); strings.Contains(got, "host edit") || strings.Contains(got, "<") {
		t.Errorf("ad-hoc hint: %s", got)
	}
}
