package sshx

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/store"
)

// komando logs in to a server that offers only the post-quantum hybrid
// key exchange (mlkem768x25519-sha256, OpenSSH 10's default): it is the
// first one komando asks for, so a recording of the traffic today cannot
// be read later with a quantum computer.
func TestPostQuantumKeyExchange(t *testing.T) {
	dialHome(t)
	var got string
	cfg := &ssh.ServerConfig{Config: ssh.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519}},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(newSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
		if err != nil {
			nc.Close()
			return
		}
		got = "ok"
		go ssh.DiscardRequests(reqs)
		go func() {
			for c := range chans {
				c.Reject(ssh.Prohibited, "no")
			}
		}()
		time.Sleep(100 * time.Millisecond)
		sc.Close()
	}()
	a := ln.Addr().(*net.TCPAddr)
	h := &store.Host{Name: "pq", Address: a.IP.String(), Port: a.Port, User: "u", Identity: clientKey(t)}
	c, err := Dial(context.Background(), newState(h), h, Options{ConnectTimeout: 5 * time.Second, HostKeyPolicy: "accept-new"})
	if err != nil {
		t.Fatalf("a server with only mlkem768x25519-sha256: %v", err)
	}
	c.Close()
	<-done
	if got != "ok" {
		t.Fatal("the server saw no login")
	}
}
