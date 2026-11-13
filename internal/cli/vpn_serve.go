package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// vpnServeCmd is the background process of a WireGuard session: it holds
// the VPN and offers a local SOCKS5 port into it.
func vpnServeCmd() *cobra.Command {
	var passwordStdin, passStdin bool
	c := &cobra.Command{
		Use:    "serve NAME",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			fail := func(err error) error { fmt.Printf("ERROR %v\n", err); return exitCode(1) }
			socksUser, socksPass, err := serveStdin(cl.stdin, passwordStdin, passStdin)
			if err != nil {
				return fail(err)
			}
			st, err := loadState()
			if err != nil {
				return fail(err)
			}
			v, ok := st.Vpns[args[0]]
			if !ok {
				return fail(errors.New("no such VPN"))
			}
			ctx := cmd.Context()
			started := time.Now()
			d, closer, err := netx.OpenDirect(ctx, v, sshOpts(cl, st).ConnectTimeout)
			if err != nil {
				return fail(err)
			}
			defer closer.Close()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return fail(err)
			}
			fmt.Printf("READY %s\n", ln.Addr())
			idle, _ := time.ParseDuration(st.Settings.VpnIdle)
			var use sessionUse
			use.touch()
			if idle > 0 {
				go func() {
					for range time.Tick(time.Minute) {
						if use.idleFor(time.Now()) > idle {
							ln.Close()
							return
						}
					}
				}()
			}
			go func() { <-ctx.Done(); ln.Close() }() // SIGTERM from `vpn down`
			if ended, ok := closer.(interface{ Done() <-chan struct{} }); ok {
				// the VPN dropped: stop, so the session is seen as down and
				// the next command connects again
				go func() {
					<-ended.Done()
					if e, ok := closer.(interface{ Err() error }); ok && e.Err() != nil {
						// a timestamp like the log's other lines, and how long it ran
						fmt.Printf("%s ENDED %v (after %s)\n", time.Now().Format("2006/01/02 15:04:05"), e.Err(), time.Since(started).Round(time.Second))
					}
					ln.Close()
				}()
			}
			cm := &connMgr{cl: cl, ctx: ctx, st: st, vpnDial: d}
			logger := log.New(cl.out.W, "", log.LstdFlags)
			// only a client that logged in keeps the session from going
			// idle, for as long as its connection stays open
			acceptLoop(ln, logger, func(c net.Conn) {
				defer c.Close()
				loggedIn, done := use.conn()
				defer done()
				socks5Auth(c, cm, logger, socksUser, socksPass, loggedIn)
			})
			_ = store.UpdateRuntime(func(s *store.State) error {
				if x := s.Sessions[v.Name]; x != nil && x.PID == os.Getpid() { // not a newer session's entry
					delete(s.Sessions, v.Name)
				}
				return nil
			})
			return nil
		}),
	}
	c.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the SOCKS login and a typed VPN password from stdin")
	c.Flags().BoolVar(&passStdin, strings.TrimPrefix(vault.PassStdinFlag, "--"), false, "then read the vault passphrase from stdin (vpn up passes it)")
	return c
}

// serveStdin reads what spawnServeWith sends `vpn serve` on stdin: the
// SOCKS login for this session and a typed VPN password, one line each
// (with password), then the vault passphrase up to the end (with pass;
// vault.PassOnStdin).
func serveStdin(r io.Reader, password, pass bool) (socksUser, socksPass string, err error) {
	in := bufio.NewReader(r)
	if password {
		line, _ := in.ReadString('\n')
		if f := strings.Fields(line); len(f) == 3 && f[0] == "SOCKS" {
			socksUser, socksPass = f[1], f[2]
		}
		line, _ = in.ReadString('\n')
		netx.SessionSecret = strings.TrimRight(line, "\r\n")
	}
	if pass {
		err = vault.ReadPassStdin(in)
	}
	return socksUser, socksPass, err
}

// acceptLoop hands each connection on ln to serve until ln is closed. Any
// other accept error, such as running out of file descriptors, is logged
// and retried: a flood of local connections must not end the session.
func acceptLoop(ln net.Listener, logger *log.Logger, serve func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Printf("accept: %v", err)
			time.Sleep(50 * time.Millisecond) // do not spin
			continue
		}
		go serve(c)
	}
}

// sessionUse is how a session's server tells it is idle: no client that
// logged in has a connection open, and none has for the vpn_idle setting.
// A long connection (a shell, logs --follow, a tunnel) is use for as long
// as it stays open; counting only new logins cut it at vpn_idle.
type sessionUse struct {
	last   atomic.Int64 // unix seconds of the last login or close
	active atomic.Int64 // logged-in connections open now
}

func (u *sessionUse) touch() { u.last.Store(time.Now().Unix()) }

// idleFor is how long the session has been unused at now: 0 while a
// logged-in connection is open.
func (u *sessionUse) idleFor(now time.Time) time.Duration {
	if u.active.Load() > 0 {
		return 0
	}
	return now.Sub(time.Unix(u.last.Load(), 0))
}

// conn is one client connection's part: loggedIn when it has logged in,
// done when it closes (always called; it counts only a logged-in one).
func (u *sessionUse) conn() (loggedIn, done func()) {
	var in atomic.Bool
	loggedIn = func() {
		if in.CompareAndSwap(false, true) {
			u.active.Add(1)
			u.touch()
		}
	}
	done = func() {
		if in.Load() {
			u.active.Add(-1)
			u.touch()
		}
	}
	return loggedIn, done
}
