package cli

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Tunnels run as detached background komando processes so that an agent's
// tool call returns immediately while the forward stays up.

func tunnelCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "tunnel",
		Aliases: []string{"forward", "pf"},
		Short:   "Background port forwarding: local (-L), remote (-R), SOCKS5 (-D)",
		Long: `Specs:
  -L [bind:]LPORT:RHOST:RPORT   local port -> RHOST:RPORT as seen from the server
  -R [rbind:]RPORT:LHOST:LPORT  server port -> LHOST:LPORT on this machine
  -D [bind:]PORT                SOCKS5 proxy through the server
LPORT/PORT 0 picks a free port; the chosen address is returned.`,
		Example: `  komando tunnel start db1 -L 15432:localhost:5432
  komando tunnel start bastion -D 1080
  komando tunnel list
  komando tunnel stop t1102-...`,
	}
	c.AddCommand(tunnelStartCmd(), tunnelListCmd(), tunnelStopCmd(), tunnelServeCmd())
	return c
}

type tunnelSpec struct {
	Kind       string
	BindAddr   string
	TargetAddr string
}

// guardBind asks for --yes before a tunnel listens on anything but this
// computer's loopback (or, for -R, the server's): other machines on the
// network could then use it, without a login (docs/design/network.md).
func guardBind(t tunnelSpec) error {
	host, _, err := net.SplitHostPort(t.BindAddr)
	if err != nil || host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if yesOK() {
		return nil
	}
	where := "this computer"
	if t.Kind == "remote" {
		where = "the server"
	}
	return policyStop(out.Errf(out.ExitPolicy, "OPEN_BIND", "keep the default 127.0.0.1, or re-run with --yes if other machines should reach it",
		"the tunnel would listen on %s of %s, open to its network", host, where))
}

func portInUse(addr, where string, err error) error {
	return out.Errf(out.ExitConflict, "PORT_IN_USE", "pick another port, or 0 for a free one",
		"%s on %s is already in use (%v)", addr, where, err)
}

// tunnelInfo is a started (or, under --dry-run, planned) tunnel.
type tunnelInfo struct {
	ID           string `json:"id,omitempty"`
	Host         string `json:"host"`
	Via          string `json:"via,omitempty"`
	Conn         string `json:"conn,omitempty"`
	Kind         string `json:"kind"`
	Spec         string `json:"spec"`
	Listen       string `json:"listen,omitempty"`
	RemoteListen string `json:"remote_listen,omitempty"` // -R: the address is on the server
	ListenOn     string `json:"listen_on,omitempty"`     // -R: which server
	Target       string `json:"target,omitempty"`
	PID          int    `json:"pid,omitempty"`
	Log          string `json:"log,omitempty"`
	would        bool
}

func (t tunnelInfo) Text() string {
	listen := t.Listen
	if listen == "" {
		listen = t.Spec
	}
	var line string
	switch t.Kind {
	case "remote":
		line = fmt.Sprintf("%s on %s -> %s on this computer", listen, t.Host, t.Target)
	case "dynamic":
		line = fmt.Sprintf("SOCKS5 proxy on %s (this computer), through %s", listen, t.Host)
	default:
		dest := t.Target
		if t.Conn != "" {
			dest = t.Conn + " (" + t.Target + ")"
		}
		line = fmt.Sprintf("%s (this computer) -> %s, through %s", listen, dest, t.Host)
	}
	if t.would {
		return "would start a tunnel: " + line + "\n"
	}
	return "tunnel " + t.ID + " is up: " + line + "\nstop it with: komando tunnel stop " + t.ID + "\n"
}

func parseTunnel(kind, spec string) (tunnelSpec, error) {
	parts := strings.Split(spec, ":")
	t := tunnelSpec{Kind: kind}
	switch kind {
	case "local", "remote":
		switch len(parts) {
		case 3:
			t.BindAddr = "127.0.0.1:" + parts[0]
			t.TargetAddr = net.JoinHostPort(parts[1], parts[2])
		case 4:
			t.BindAddr = net.JoinHostPort(parts[0], parts[1])
			t.TargetAddr = net.JoinHostPort(parts[2], parts[3])
		default:
			return t, out.Usage("invalid forward spec %q", spec)
		}
	case "dynamic":
		switch len(parts) {
		case 1:
			t.BindAddr = "127.0.0.1:" + parts[0]
		case 2:
			t.BindAddr = net.JoinHostPort(parts[0], parts[1])
		default:
			return t, out.Usage("invalid SOCKS spec %q", spec)
		}
	}
	return t, nil
}

func tunnelStartCmd() *cobra.Command {
	var l, r, d string
	var port int
	c := &cobra.Command{
		Use:   "start TARGET (-L spec | -R spec | -D spec)",
		Short: "Start a background tunnel; returns its ID and bound address",
		Long: `With a conn name and no -L/-R/-D, the tunnel leads to that conn through its
--via path: point your database app or psql at the local address it prints.`,
		Example: `  komando tunnel start app-db               # localhost:<free port> -> app-db
  komando tunnel start app-db --port 15432
  komando tunnel start web1 -L 8080:localhost:80
  komando tunnel start bastion -D 1080       # SOCKS proxy`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, via := "", ""
			if l == "" && r == "" && d == "" {
				st, err := loadState()
				if err != nil {
					return err
				}
				c, err := tunnelConn(st, args[0])
				if err != nil {
					return err
				}
				t, err := driver.Parse(c.URL)
				if err != nil {
					return err
				}
				conn, via = c.Name, c.Via
				l = fmt.Sprintf("127.0.0.1:%d:%s", port, t.Address)
			}
			n := 0
			kind, spec := "", ""
			for k, v := range map[string]string{"local": l, "remote": r, "dynamic": d} {
				if v != "" {
					n++
					kind, spec = k, v
				}
			}
			if n != 1 {
				return out.Usage("exactly one of -L, -R, -D is required")
			}
			ts, err := parseTunnel(kind, spec)
			if err != nil {
				return err
			}
			if err := guardBind(ts); err != nil {
				return err
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			if v, ok := st.Vpns[args[0]]; ok && via == "" {
				via = v.Name // a tunnel into a VPN: -L or -D through it
			}
			var h *store.Host
			var vpn *store.Vpn
			if via != "" {
				h, vpn, err = resolveVia(st, via)
			} else {
				h, err = singleHost(st, args[0])
			}
			if err != nil {
				return err
			}
			if vpn != nil && kind == "remote" {
				return out.Usage("-R needs a server at the end of the path; a VPN cannot listen for you")
			}
			hostName := via
			if h != nil {
				hostName = h.Name
			}
			if g.dryRun {
				out.P.Print("tunnel.start", tunnelInfo{Host: hostName, Via: via, Conn: conn, Kind: kind, Spec: spec, Target: ts.TargetAddr, would: true}, nil)
				return nil
			}
			if kind != "remote" {
				// a port already taken here: say so before starting anything
				ln, err := net.Listen("tcp", ts.BindAddr)
				if err != nil {
					return portInUse(ts.BindAddr, "this computer", err)
				}
				ln.Close()
			}
			id := newID("t")
			logPath := store.Path("tunnels", id+".log")
			if err := os.MkdirAll(store.Path("tunnels"), 0o700); err != nil {
				return err
			}
			t := &store.Tunnel{ID: id, Host: hostName, Via: via, Conn: conn, Kind: kind, Spec: spec, LogFile: logPath, StartedAt: time.Now().UTC()}
			if err := store.Update(func(s *store.State) error { s.Tunnels[id] = t; return nil }); err != nil {
				return err
			}
			self, err := os.Executable()
			if err != nil {
				return err
			}
			lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			pargs := []string{"tunnel", "serve", id}
			if g.hostKeyPolicy != "" {
				pargs = append(pargs, "--host-key-policy", g.hostKeyPolicy)
				if g.hostKeyPolicy == "off" {
					pargs = append(pargs, "--yes") // checked by this command already
				}
			}
			p := exec.Command(self, pargs...)
			p.Stdout, p.Stderr, p.Stdin = lf, lf, nil
			p.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			p.Env = vault.SelfEnv()
			if err := p.Start(); err != nil {
				return err
			}
			lf.Close()
			pid := p.Process.Pid
			_ = p.Process.Release()
			_ = store.Update(func(s *store.State) error {
				if x, ok := s.Tunnels[id]; ok {
					x.PID = pid
				}
				return nil
			})
			// wait for READY / ERROR from the child
			deadline := time.Now().Add(sshOpts(st).ConnectTimeout + 5*time.Second)
			for time.Now().Before(deadline) {
				b, _ := os.ReadFile(logPath)
				s := string(b)
				if i := strings.Index(s, "READY "); i >= 0 {
					addr := strings.TrimSpace(strings.SplitN(s[i+6:], "\n", 2)[0])
					audit(st, "tunnel.start", []string{hostName}, "", true, map[string]any{"kind": kind, "spec": spec, "id": id})
					info := tunnelInfo{ID: id, Host: hostName, Via: via, Conn: conn, Kind: kind, Spec: spec, Listen: addr, Target: ts.TargetAddr, PID: pid, Log: logPath}
					if kind == "remote" {
						info.RemoteListen, info.ListenOn = addr, hostName
					}
					out.P.Print("tunnel.start", info, nil)
					return nil
				}
				if i := strings.Index(s, "ERROR "); i >= 0 {
					_ = store.Update(func(s *store.State) error { delete(s.Tunnels, id); return nil })
					msg := strings.TrimSpace(s[i+6:])
					if strings.Contains(msg, "address already in use") {
						return portInUse(ts.BindAddr, "this computer", errors.New(msg))
					}
					if kind == "remote" && strings.Contains(msg, "request denied") {
						return out.Errf(out.ExitConflict, "PORT_IN_USE", "the port may be taken on "+hostName+" (pick another, or 0 for a free one), or sshd there has AllowTcpForwarding off",
							"%s refused to listen on %s: %s", hostName, ts.BindAddr, msg)
					}
					return out.Errf(out.ExitConnect, "TUNNEL_FAILED", "", "%s", msg)
				}
				time.Sleep(150 * time.Millisecond)
			}
			_ = netx.Terminate(pid)
			_ = store.Update(func(s *store.State) error { delete(s.Tunnels, id); return nil })
			return out.Errf(out.ExitTimeout, "TUNNEL_TIMEOUT", "see log "+logPath, "tunnel did not become ready")
		},
	}
	c.Flags().StringVarP(&l, "local", "L", "", "local forward [bind:]LPORT:RHOST:RPORT")
	c.Flags().StringVarP(&r, "remote", "R", "", "remote forward [rbind:]RPORT:LHOST:LPORT")
	c.Flags().StringVarP(&d, "dynamic", "D", "", "SOCKS5 proxy [bind:]PORT")
	c.Flags().IntVar(&port, "port", 0, "with a conn: the local port (default: a free one)")
	return c
}

// tunnelConn finds the conn a tunnel leads to. Only conns reached through
// --via need one; the others are already reachable from this computer.
func tunnelConn(st *store.State, expr string) (*store.Conn, error) {
	sel, err := resolveSelection(st, expr)
	if err != nil {
		return nil, err
	}
	if len(sel.Hosts) > 0 || len(sel.Conns) != 1 {
		return nil, out.Usage("give -L, -R or -D for a server, or the name of one conn")
	}
	c := sel.Conns[0]
	t, err := driver.Parse(c.URL)
	if err != nil {
		return nil, err
	}
	if t.Kind.File {
		return nil, out.Usage("%s is a local file; it needs no tunnel", c.Name)
	}
	if c.Via == "" {
		return nil, out.Errf(out.ExitUsage, "NO_TUNNEL_NEEDED", "connect to "+t.Address+" directly",
			"%s has no --via, so it is reachable without a tunnel", c.Name)
	}
	return c, nil
}

func alive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

type tunnelRow struct {
	*store.Tunnel
	Alive  bool   `json:"alive"`
	Listen string `json:"listen,omitempty"`
}

type tunnelList struct {
	Count   int         `json:"count"`
	Tunnels []tunnelRow `json:"tunnels"`
}

func (l tunnelList) Text() string {
	if len(l.Tunnels) == 0 {
		return "no tunnels\n"
	}
	rows := [][]string{}
	for _, t := range l.Tunnels {
		state := "up"
		if !t.Alive {
			state = "dead (removed)"
		}
		listen, to := tunnelEnds(t)
		rows = append(rows, []string{t.ID, t.Host, t.Kind, listen, to, state, humanAge(time.Since(t.StartedAt))})
	}
	return textTable([]string{"id", "host", "kind", "listen", "to", "state", "age"}, rows)
}

// tunnelEnds is where a tunnel listens and where it leads, for text output.
func tunnelEnds(t tunnelRow) (listen, to string) {
	listen = t.Listen
	if t.Kind == "remote" && listen != "" {
		listen += " on " + t.Host
	}
	to = t.Spec
	if ts, err := parseTunnel(t.Kind, t.Spec); err == nil && ts.TargetAddr != "" {
		to = ts.TargetAddr
		if t.Conn != "" {
			to = t.Conn
		}
	}
	return listen, to
}

// tunnelListen is the address the tunnel's process said it listens on.
func tunnelListen(t *store.Tunnel) string {
	b, err := os.ReadFile(t.LogFile)
	if err != nil {
		return ""
	}
	i := strings.Index(string(b), "READY ")
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(b)[i+6:], "\n", 2)[0])
}

func tunnelListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List tunnels with liveness; dead entries are pruned",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rows := []tunnelRow{}
			var dead []string
			st, err := loadState()
			if err != nil {
				return err
			}
			for _, t := range st.Tunnels {
				r := tunnelRow{Tunnel: t, Alive: alive(t.PID), Listen: tunnelListen(t)}
				if !r.Alive {
					dead = append(dead, t.ID)
				}
				rows = append(rows, r)
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].StartedAt.Before(rows[j].StartedAt) })
			if len(dead) > 0 {
				_ = store.Update(func(s *store.State) error {
					for _, id := range dead {
						delete(s.Tunnels, id)
					}
					return nil
				})
			}
			out.P.Print("tunnel.list", tunnelList{Count: len(rows), Tunnels: rows}, nil)
			return nil
		},
	}
}

func tunnelStopCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:   "stop [ID...]",
		Short: "Stop tunnel(s) (--all for every tunnel)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !all && len(args) == 0 {
				return out.Usage("give tunnel IDs or --all")
			}
			stopped := []string{}
			err := store.Update(func(s *store.State) error {
				ids := args
				if all {
					ids = nil
					for id := range s.Tunnels {
						ids = append(ids, id)
					}
				}
				for _, id := range ids {
					t, ok := s.Tunnels[id]
					if !ok {
						return out.NotFound("tunnel", id)
					}
					if alive(t.PID) && !g.dryRun {
						_ = netx.Terminate(t.PID)
					}
					delete(s.Tunnels, id)
					stopped = append(stopped, id)
				}
				return nil
			})
			if err != nil {
				return err
			}
			if g.dryRun {
				out.P.Print("tunnel.stop", map[string]any{"would_stop": stopped}, nil)
				return nil
			}
			out.P.Print("tunnel.stop", map[string]any{"stopped": stopped}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&all, "all", false, "stop all tunnels")
	return c
}

// tunnelServeCmd is the hidden daemon entry point.
func tunnelServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "serve ID",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := log.New(os.Stdout, "", log.LstdFlags)
			fail := func(err error) error {
				fmt.Printf("ERROR %v\n", err)
				return exitCode(1)
			}
			st, err := loadState()
			if err != nil {
				return fail(err)
			}
			t, ok := st.Tunnels[args[0]]
			if !ok {
				return fail(fmt.Errorf("tunnel %s not found", args[0]))
			}
			var h *store.Host
			var vpn *store.Vpn
			if t.Via != "" {
				h, vpn, err = resolveVia(st, t.Via)
			} else {
				h, err = singleHost(st, t.Host)
			}
			if err != nil {
				return fail(err)
			}
			spec, err := parseTunnel(t.Kind, t.Spec)
			if err != nil {
				return fail(err)
			}
			ctx := cmd.Context()
			cm := &connMgr{ctx: ctx, st: st, h: h}
			if vpn != nil {
				d, closer, err := netx.Open(ctx, vpn, sshOpts(st).ConnectTimeout)
				if err != nil {
					return fail(err)
				}
				defer closer.Close()
				cm.vpnDial = d
			} else if _, err := cm.get(); err != nil {
				return fail(err)
			}
			var ln net.Listener
			if spec.Kind == "remote" {
				c, _ := cm.get()
				ln, err = c.Listen("tcp", spec.BindAddr)
			} else {
				ln, err = net.Listen("tcp", spec.BindAddr)
			}
			if err != nil {
				return fail(err)
			}
			fmt.Printf("READY %s\n", ln.Addr().String())
			go func() { <-ctx.Done(); ln.Close() }()
			for {
				conn, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return nil
					}
					if spec.Kind == "remote" {
						return fail(fmt.Errorf("remote listener closed: %v", err))
					}
					logger.Printf("accept: %v", err)
					continue
				}
				go func(conn net.Conn) {
					defer conn.Close()
					switch spec.Kind {
					case "local":
						rc, err := cm.dial(spec.TargetAddr)
						if err != nil {
							logger.Printf("dial %s: %v", spec.TargetAddr, err)
							return
						}
						pipe(conn, rc)
					case "remote":
						lc, err := net.DialTimeout("tcp", spec.TargetAddr, 10*time.Second)
						if err != nil {
							logger.Printf("dial local %s: %v", spec.TargetAddr, err)
							return
						}
						pipe(conn, lc)
					case "dynamic":
						socks5(conn, cm, logger)
					}
				}(conn)
			}
		},
	}
}

// connMgr reconnects the SSH client when it drops (local/dynamic forwards).
type connMgr struct {
	mu      sync.Mutex
	ctx     context.Context
	st      *store.State
	h       *store.Host
	c       *sshx.Client
	vpnDial netx.Dialer // set when the path is only a VPN
}

func (m *connMgr) get() (*sshx.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.c != nil {
		return m.c, nil
	}
	c, err := sshx.Dial(m.ctx, m.st, m.h, sshOpts(m.st))
	if err != nil {
		return nil, err
	}
	m.c = c
	return c, nil
}

func (m *connMgr) dial(addr string) (net.Conn, error) {
	if m.vpnDial != nil {
		ctx, cancel := context.WithTimeout(m.ctx, sshOpts(m.st).ConnectTimeout)
		defer cancel()
		return m.vpnDial(ctx, "tcp", addr)
	}
	for attempt := 0; attempt < 2; attempt++ {
		c, err := m.get()
		if err != nil {
			return nil, err
		}
		conn, err := c.Dial("tcp", addr)
		if err == nil {
			return conn, nil
		}
		var oe *net.OpError
		if errors.As(err, &oe) || strings.Contains(err.Error(), "open failed") {
			return nil, err // remote refused: connection itself is fine
		}
		m.mu.Lock()
		if m.c == c {
			m.c.Close()
			m.c = nil
		}
		m.mu.Unlock()
	}
	return nil, errors.New("ssh reconnect failed")
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	b.Close()
}

// socks5 implements the no-auth CONNECT subset of RFC 1928.
func socks5(conn net.Conn, cm *connMgr, logger *log.Logger) {
	r := bufio.NewReader(conn)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}
	conn.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(r, req); err != nil || req[1] != 1 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(r, b)
		host = net.IP(b).String()
	case 3:
		l, _ := r.ReadByte()
		b := make([]byte, l)
		io.ReadFull(r, b)
		host = string(b)
	case 4:
		b := make([]byte, 16)
		io.ReadFull(r, b)
		host = net.IP(b).String()
	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		return
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
	rc, err := cm.dial(addr)
	if err != nil {
		logger.Printf("socks dial %s: %v", addr, err)
		conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if n := r.Buffered(); n > 0 {
		b, _ := r.Peek(n)
		rc.Write(b)
	}
	pipe(conn, rc)
}
