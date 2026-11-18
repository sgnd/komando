package storex

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/storex/ftptest"
)

// hopDial is a --via hop in this process: an SSH server that forwards
// each direct-tcpip channel to its address and closes the channel as soon
// as that server closes its socket, as sshd does. It returns the dial
// komando uses through a hop (conn_access.go: Dial, then WithDeadlines).
func hopDial(t *testing.T) DialFunc {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		a, err := ln.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := ssh.NewServerConn(a, cfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			var to struct {
				Host     string
				Port     uint32
				OrigHost string
				OrigPort uint32
			}
			if ssh.Unmarshal(nc.ExtraData(), &to) != nil {
				nc.Reject(ssh.ConnectionFailed, "bad address")
				continue
			}
			back, err := net.Dial("tcp", net.JoinHostPort(to.Host, strconv.Itoa(int(to.Port))))
			if err != nil {
				nc.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			ch, creqs, err := nc.Accept()
			if err != nil {
				back.Close()
				continue
			}
			go ssh.DiscardRequests(creqs)
			go func() { io.Copy(back, ch); back.(*net.TCPConn).CloseWrite() }()
			go func() { io.Copy(ch, back); ch.Close(); back.Close() }() // the server closed: close the channel
		}
	}()
	b, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(b, "hop", &ssh.ClientConfig{
		User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { client.Close() })
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := client.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return sshx.WithDeadlines(c), nil
	}
}

// C132: an FTP transfer through a --via hop that the server completed
// comes back with no error, also when the far end closes the data
// connection before komando does. Each step runs many times: the far
// end's close and komando's race.
func TestFTPThroughAHopEndsWithoutEOF(t *testing.T) {
	s := ftptest.New(t)
	b, err := OpenFTP(context.Background(), s.Target(), "p", hopDial(t), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx := context.Background()
	for i := range 25 {
		if err := b.Put(ctx, "obj.txt", strings.NewReader("old\n"), 4, ""); err != nil {
			t.Fatalf("STOR %d: %v", i, err)
		}
		var got bytes.Buffer
		if _, err := b.Get(ctx, "obj.txt", &got); err != nil || got.String() != "old\n" {
			t.Fatalf("RETR %d: %q %v", i, got.String(), err)
		}
		if _, _, err := b.List(ctx, "", false, 0); err != nil {
			t.Fatalf("LIST %d: %v", i, err)
		}
		if _, err := Append(ctx, b, "obj.txt", 4, strings.NewReader("new\n")); err != nil {
			t.Fatalf("APPE %d: %v", i, err)
		}
	}
}

// The same through a hop over FTPS: TLS sends its close_notify before it
// closes the channel, and that send meets a channel the far end closed.
func TestFTPSThroughAHopEndsWithoutEOF(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	certs := srv.TLS.Certificates
	srv.Close()
	s := ftptest.New(t)
	s.TLS = &tls.Config{Certificates: certs}
	tg := s.Target()
	tg.Secure, tg.TLS = true, "skip-verify"
	b, err := OpenFTP(context.Background(), tg, "p", hopDial(t), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx := context.Background()
	for i := range 25 {
		if err := b.Put(ctx, "obj.txt", strings.NewReader("old\n"), 4, ""); err != nil {
			t.Fatalf("STOR %d: %v", i, err)
		}
		var got bytes.Buffer
		if _, err := b.Get(ctx, "obj.txt", &got); err != nil || got.String() != "old\n" {
			t.Fatalf("RETR %d: %q %v", i, got.String(), err)
		}
		if _, _, err := b.List(ctx, "", false, 0); err != nil {
			t.Fatalf("LIST %d: %v", i, err)
		}
		if _, err := Append(ctx, b, "obj.txt", 4, strings.NewReader("new\n")); err != nil {
			t.Fatalf("APPE %d: %v", i, err)
		}
	}
}
