package vault

import (
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func TestShortPassphraseIsReported(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Cleanup(store.Close) // before the folder goes: Windows cannot remove an open file
	t.Setenv("KOMANDO_VAULT_PASS", "short")
	pass = ""
	Passphrase()
	defer func(n int) { PassphraseN = n }(PassphraseN)
	PassphraseN = 1 << 10
	if err := Set(store.Save, "x", "value-1"); err != nil {
		t.Fatal(err)
	}
	if s, _ := Check(); !s.ShortPass {
		t.Errorf("%+v", s)
	}
}

// A background komando process (tunnel serve, vpn serve) gets the passphrase on
// stdin, never in its environment, which stays in view while it runs.
func TestPassOnStdin(t *testing.T) {
	freshHome(t)
	setPass := func(p string) { passMu.Lock(); pass = p; passMu.Unlock() }
	t.Cleanup(func() { setPass("") })
	const want = "a long passphrase\nwith a line break"
	t.Setenv("KOMANDO_VAULT_PASS", want)
	Passphrase() // komando takes it out of its environment when it starts
	c := exec.Command("komando", "tunnel", "serve", "t-1")
	PassOnStdin(c)
	for _, e := range c.Env {
		if strings.HasPrefix(e, "KOMANDO_VAULT_PASS=") {
			t.Fatal("the passphrase is in the environment")
		}
	}
	if c.Args[len(c.Args)-1] != PassStdinFlag || c.Stdin == nil {
		t.Fatalf("args %q, stdin %v", c.Args, c.Stdin)
	}
	setPass("") // the child starts without it
	if err := ReadPassStdin(c.Stdin); err != nil || Passphrase() != want {
		t.Fatalf("read back %q: %v", Passphrase(), err)
	}
	// vpn serve reads its own lines first: the passphrase comes after them
	setPass(want)
	c = exec.Command("komando", "vpn", "serve", "office", "--password-stdin")
	c.Stdin = strings.NewReader("SOCKS u p\n\n")
	PassOnStdin(c)
	if b, _ := io.ReadAll(c.Stdin); string(b) != "SOCKS u p\n\n"+want {
		t.Errorf("stdin %q", b)
	}
	setPass("") // a vault without a passphrase: no flag, nothing on stdin
	c = exec.Command("komando", "tunnel", "serve", "t-1")
	PassOnStdin(c)
	if c.Stdin != nil || len(c.Args) != 4 {
		t.Errorf("args %q, stdin %v", c.Args, c.Stdin)
	}
}
