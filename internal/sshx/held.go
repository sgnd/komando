package sshx

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/store"
)

// Held logins: `komando login HOST` lets a person log in to a server once
// (password, two-factor code) and keeps that connection open in a
// background komando process for the login_for setting. Later commands,
// an AI agent's too, reach the server through it without a person: the
// process serves it on a Unix socket only this user can open, as a small
// SSH server that takes one random password (the login's Token) and passes
// every channel (commands, file transfers, port forwards) on to the
// server. komando's checks and audit still run in the command that uses
// it; the held login only answers the server's login questions.

// HeldUser is the user name a command logs in to a held login's socket with.
const HeldUser = "komando"

// TargetOf is where h logs in: a held login is used only while the host
// still points there (a changed address or user logs in anew).
func TargetOf(h *store.Host) string {
	return h.User + "@" + net.JoinHostPort(h.Address, strconv.Itoa(h.EffectivePort())) + "|" + h.Identity + "|" + h.ProxyCommand + "|" + h.Via
}

// HeldFor is the held login for h that is still in time, or nil.
func HeldFor(st *store.State, h *store.Host) *store.SSHLogin {
	if st == nil || h == nil {
		return nil
	}
	l := st.Logins[h.Name]
	if l == nil || l.Socket == "" || l.Token == "" || time.Now().After(l.Until) || l.Target != TargetOf(h) {
		return nil
	}
	return l
}

// dialHeld connects to a held login's socket. An error means it is gone
// (the process ended, the server dropped it): the caller logs in as usual.
func dialHeld(ctx context.Context, l *store.SSHLogin, timeout time.Duration) (*ssh.Client, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l.HostKey))
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "unix", l.Socket)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            HeldUser,
		Auth:            []ssh.AuthMethod{ssh.Password(l.Token)},
		HostKeyCallback: ssh.FixedHostKey(key),
		Timeout:         timeout,
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sc, chans, reqs, err := ssh.NewClientConn(conn, "held:"+l.Host, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), nil
}

// ServeHeld serves up (the person's login) on ln until ln closes: each
// client that knows token gets its channels passed on to up.
func ServeHeld(ln net.Listener, up *ssh.Client, token string, key ssh.Signer, used func()) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == HeldUser && subtle.ConstantTimeCompare(pw, []byte(token)) == 1 {
				return nil, nil
			}
			time.Sleep(time.Second) // a wrong password costs time
			return nil, errors.New("wrong password")
		},
		MaxAuthTries: 1,
	}
	cfg.AddHostKey(key)
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go serveHeldConn(c, cfg, up, used)
	}
}

func serveHeldConn(c net.Conn, cfg *ssh.ServerConfig, up *ssh.Client, used func()) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	defer sc.Close()
	if used != nil {
		used()
	}
	go func() {
		// the client's keepalives are answered here; nothing else (no
		// remote port forwarding: a held login carries no listener)
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(r.Type == "keepalive@komando" || r.Type == "keepalive@openssh.com", nil)
			}
		}
	}()
	for nc := range chans {
		go passChannel(nc, up)
	}
}

// passChannel opens the same channel on up and copies everything between
// the two: data, error output, requests (a command, a window size, a
// signal) and the server's answers (the exit status).
func passChannel(nc ssh.NewChannel, up *ssh.Client) {
	uch, ureqs, err := up.OpenChannel(nc.ChannelType(), nc.ExtraData())
	if err != nil {
		var oe *ssh.OpenChannelError
		if errors.As(err, &oe) {
			_ = nc.Reject(oe.Reason, oe.Message)
		} else {
			_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		}
		return
	}
	dch, dreqs, err := nc.Accept()
	if err != nil {
		uch.Close()
		return
	}
	var out sync.WaitGroup
	out.Add(2)
	go func() { defer out.Done(); _, _ = io.Copy(dch, uch) }()
	go func() { defer out.Done(); _, _ = io.Copy(dch.Stderr(), uch.Stderr()) }()
	go func() {
		_, _ = io.Copy(uch, dch)
		_ = uch.CloseWrite()
	}()
	go func() {
		_, _ = io.Copy(uch.Stderr(), dch.Stderr())
	}()
	go func() {
		for r := range dreqs {
			ok, err := uch.SendRequest(r.Type, r.WantReply, r.Payload)
			if r.WantReply {
				_ = r.Reply(ok && err == nil, nil)
			}
		}
		uch.Close() // the client closed its side
	}()
	upDone := make(chan struct{})
	go func() {
		for r := range ureqs {
			ok, err := dch.SendRequest(r.Type, r.WantReply, r.Payload)
			if r.WantReply {
				_ = r.Reply(ok && err == nil, nil)
			}
		}
		close(upDone)
	}()
	out.Wait() // the server's output ended
	_ = dch.CloseWrite()
	<-upDone // and it closed the channel (its exit status went first)
	dch.Close()
}
