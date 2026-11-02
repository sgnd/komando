package sshx

import (
	"io"
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

func TestProxyConnCarriesBytes(t *testing.T) {
	c, err := dialProxy(&store.Host{Name: "echo", ProxyCommand: "cat"})
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
