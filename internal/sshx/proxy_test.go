package sshx

import (
	"io"
	"os"
	"runtime"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func TestExpandProxy(t *testing.T) {
	h := &store.Host{Name: "web1", Address: "i-0abc", Port: 2222, User: "ec2-user"}
	got := ExpandProxy("aws ssm start-session --target %h --parameters portNumber=%p # %r %n 100%%", h)
	want := "aws ssm start-session --target 'i-0abc' --parameters portNumber=2222 # 'ec2-user' 'web1' 100%"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	evil := &store.Host{Address: "x; rm -rf /"}
	if got := ExpandProxy("nc %h 22", evil); got != `nc 'x; rm -rf /' 22` {
		t.Errorf("address must be quoted: %s", got)
	}
}

// On Windows cmd.exe runs the line: a value goes in bare or in double
// quotes, and one that could still start a command is refused.
func TestExpandProxyForCmd(t *testing.T) {
	h := &store.Host{Name: "web1", Address: "10.0.0.9", Port: 22, User: "ec2-user"}
	if got, err := expandProxy(`ncat.exe --proxy bastion:3128 %h %p # %r %n 100%%`, h, quoteCmd); err != nil || got != `ncat.exe --proxy bastion:3128 10.0.0.9 22 # ec2-user web1 100%` {
		t.Errorf("got %q %v", got, err)
	}
	for v, want := range map[string]string{
		"fe80::1%eth0": "", // %NAME% expands even inside quotes
		"%COMSPEC%":    "",
		`x" & calc`:    "", // a " ends the quotes
		"line\nnext":   "",
		"line\rnext":   "",
		"x & calc":     `"x & calc"`,
		"a|b<c>d^e!":   `"a|b<c>d^e!"`,
		"web 1":        `"web 1"`,
		"[::1]":        "[::1]",
		"i-0abc":       "i-0abc",
	} {
		got, err := quoteCmd(v)
		if want == "" {
			if err == nil {
				t.Errorf("quoteCmd(%q) = %q, want it refused", v, got)
			}
		} else if err != nil || got != want {
			t.Errorf("quoteCmd(%q) = %q %v, want %q", v, got, err, want)
		}
	}
}

// TestProxyCatChild is the program the proxy test starts as its
// ProxyCommand: it copies its input to its output, like cat, on every
// system (Windows has no cat).
func TestProxyCatChild(t *testing.T) {
	if os.Getenv("KOMANDO_TEST_PROXY_CAT") != "1" {
		t.Skip("the child of TestProxyConnCarriesBytes")
	}
	_, _ = io.Copy(os.Stdout, os.Stdin)
	os.Exit(0)
}

func TestProxyConnCarriesBytes(t *testing.T) {
	t.Setenv("KOMANDO_TEST_PROXY_CAT", "1")
	self := Q(os.Args[0])
	if runtime.GOOS == "windows" {
		self = `"` + os.Args[0] + `"`
	}
	c, err := dialProxy(&store.Host{Name: "echo", ProxyCommand: self + " -test.run=^TestProxyCatChild$"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("SSH-2.0-test\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 13)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "SSH-2.0-test\n" {
		t.Errorf("read %q %v", buf, err)
	}
	c.Close()
	if err := c.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}
