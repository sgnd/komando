package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// keyOnlyServer is a loopback SSH server that lets in only the key pub
// and answers every command like a server where sudo needs a password.
func keyOnlyServer(t *testing.T, pub ssh.PublicKey) string {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if sshx.SameKey(k, pub) {
			return nil, nil
		}
		return nil, errors.New("not this key")
	}}
	cfg.AddHostKey(trustSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &fakeServer{}
	s.reply("u\nweb1\nsudo-no\n")
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
}

// scratchAgentWith serves an in-process ssh-agent on a short socket path
// under /tmp and points SSH_AUTH_SOCK at it (never the user's own agent).
func scratchAgentWith(t *testing.T, keys ...any) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "kag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "a.sock"))
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
	t.Setenv("SSH_AUTH_SOCK", ln.Addr().String())
}

// The macOS case: `import ssh-config` makes an encrypted ~/.ssh/id_ed25519
// the host's --identity, and ssh-agent holds it. `komando test` logs in
// with the agent's copy, as ssh does. Without it, the error names commands
// that work, and following them logs in with the passphrase from the vault.
func TestTestWithEncryptedIdentityInAgent(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	const pass = "correct horse battery"
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	addr := keyOnlyServer(t, signer.PublicKey())
	mustRun(t, "host", "add", "web1", "u@"+addr, "--identity", keyPath)

	scratchAgentWith(t, priv)
	mustRun(t, "test", "web1")

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	scratchAgentWith(t, other)
	d, top := invRun(t, "test", "web1")
	if top == nil || top.Code != "KEY_PASSPHRASE_REQUIRED" || top.Exit != out.ExitUsage {
		t.Fatalf("want KEY_PASSPHRASE_REQUIRED exit 2, got %+v", top)
	}
	res, _ := d["results"].([]any)
	if len(res) != 1 {
		t.Fatalf("results: %v", d)
	}
	hint, _ := res[0].(map[string]any)["error"].(map[string]any)["hint"].(string)
	for _, cmd := range []string{
		"`ssh-add ~/.ssh/id_ed25519`",
		"`komando secret set id_ed25519-pass`",
		"`komando key add id_ed25519 ~/.ssh/id_ed25519 --passphrase-ref secret:id_ed25519-pass`",
		"`komando host edit web1 --key id_ed25519 --unset identity`",
	} {
		if !strings.Contains(hint, cmd) {
			t.Errorf("hint lacks %s: %s", cmd, hint)
		}
	}

	// follow the hint (a value from --from-env instead of the hidden prompt)
	t.Setenv("KOMANDO_TEST_KEY_PASS", pass)
	mustRun(t, "secret", "set", "id_ed25519-pass", "--from-env", "KOMANDO_TEST_KEY_PASS")
	mustRun(t, "key", "add", "id_ed25519", keyPath, "--passphrase-ref", "secret:id_ed25519-pass")
	mustRun(t, "host", "edit", "web1", "--key", "id_ed25519", "--unset", "identity")
	t.Setenv("SSH_AUTH_SOCK", "")
	mustRun(t, "test", "web1")
}

// sshx words the HOSTKEY_MISMATCH hint for a person only when interactive()
// says one is at the terminal.
func TestHostKeyHintFollowsInteractive(t *testing.T) {
	saved := interactive
	defer func() { interactive = saved }()
	interactive = func() bool { return true }
	if !strings.Contains(sshx.HostKeyMismatch("web1", "SHA256:x", nil).Hint, "compare this fingerprint") {
		t.Error("a person gets the agent's hint")
	}
	interactive = func() bool { return false }
	if !strings.Contains(sshx.HostKeyMismatch("web1", "SHA256:x", nil).Hint, "report this to the user") {
		t.Error("an agent or a script gets the person's hint")
	}
}
