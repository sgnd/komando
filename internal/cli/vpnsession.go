package cli

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// VPN sessions: a VPN kept up in the background between commands, so a
// login (and its MFA) happens once. `vpn up` starts one; commands whose
// --via path needs a VPN without MFA start one by themselves. A session
// unused for the vpn_idle setting (30m) is disconnected.

func init() {
	netx.StartSession = func(ctx context.Context, name string) error {
		st, err := loadState()
		if err != nil {
			return err
		}
		v, ok := st.Vpns[name]
		if !ok {
			return out.NotFound("vpn", name)
		}
		if _, err = startSession(ctx, st, v, false); err != nil {
			return err
		}
		// started by a command, not by `vpn up`: say it now stays up
		if idle, _ := time.ParseDuration(st.Settings.VpnIdle); idle > 0 {
			noticef("vpn %s connected; it stays up until unused for %s (`komando vpn down %s` stops it)", name, humanAge(idle), name)
		} else {
			noticef("vpn %s connected; it stays up until `komando vpn down %s`", name, name)
		}
		return nil
	}
}

func vpnDir() (string, error) {
	d := store.Path("vpn")
	return d, os.MkdirAll(d, 0o700)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// waitFor polls until ok returns true or the timeout passes.
func waitFor(timeout time.Duration, ok func() bool) bool {
	for end := time.Now().Add(timeout); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if ok() {
			return true
		}
	}
	return false
}

func listening(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		c.Close()
	}
	return err == nil
}

// vpnClients are the programs a VPN needs on this computer.
func vpnClients(v *store.Vpn) []string {
	if v.Kind == "openvpn" && v.OSMode {
		return []string{"openvpn", "sudo"}
	}
	return netx.Kinds[v.Kind].Client
}

func clientMissing(v *store.Vpn) error {
	for _, bin := range vpnClients(v) {
		if _, err := exec.LookPath(bin); err != nil {
			return out.Errf(out.ExitNotFound, "VPN_CLIENT_MISSING", installHint(bin),
				"%s VPNs need the %s program, which is not installed", v.Kind, bin)
		}
	}
	return nil
}

func installHint(bin string) string {
	pkg := map[string]string{"ocproxy": "ocproxy", "openconnect": "openconnect", "openvpn": "openvpn",
		"tailscaled": "tailscale", "tailscale": "tailscale"}[bin]
	if bin == "docker" {
		return "install Docker (Docker Desktop or Colima); or add the VPN with --os-mode to run OpenVPN on this computer (changes its network)"
	}
	if runtime.GOOS == "darwin" {
		return "install it with `brew install " + pkg + "`"
	}
	return "install the " + pkg + " package (apt, dnf, ...)"
}

// startSession connects v in the background and records the session.
// interactive means a person is at the terminal for the login (and MFA).
func startSession(ctx context.Context, st *store.State, v *store.Vpn, interactive bool) (*store.VpnSession, error) {
	if v.MFA && !interactive {
		return nil, netx.LoginRequired(v)
	}
	if err := clientMissing(v); err != nil {
		return nil, err
	}
	dir, err := vpnDir()
	if err != nil {
		return nil, err
	}
	// one start at a time per VPN: two commands that both need it would
	// otherwise each start one and leak the first
	unlock, err := netx.Lock(v.Name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if cur, err := store.Load(); err == nil {
		if s := cur.Sessions[v.Name]; s != nil && netx.SessionAlive(s) {
			return s, nil // another command started it meanwhile
		}
	}
	logFile := filepath.Join(dir, v.Name+".log")
	password := ""
	if v.KeyRef != "" && v.Kind != "wireguard" {
		if password, err = vault.Resolve(v.KeyRef); err != nil {
			return nil, out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", netx.SecretHint(v.KeyRef), "VPN %s password %s: %v", v.Name, v.KeyRef, err)
		}
	}
	s := &store.VpnSession{Vpn: v.Name, LogFile: logFile, StartedAt: time.Now().UTC(), LastUsed: time.Now().UTC()}
	k := netx.Kinds[v.Kind]
	timeout := 60 * time.Second
	switch {
	case v.Kind == "wireguard":
		pid, addr, err := spawnServe(v.Name, logFile)
		if err != nil {
			return nil, err
		}
		s.PID, s.Socks = pid, addr
		if self, err := os.Executable(); err == nil {
			s.Exe = filepath.Base(self)
		}
	case v.Kind == "tailscale":
		port, err := freePort()
		if err != nil {
			return nil, err
		}
		state := filepath.Join(dir, v.Name+"-tailscale")
		sock := filepath.Join(state, "tailscaled.sock")
		if err := os.MkdirAll(state, 0o700); err != nil {
			return nil, err
		}
		d := exec.Command("tailscaled", "--tun=userspace-networking", "--statedir="+state, "--socket="+sock,
			fmt.Sprintf("--socks5-server=127.0.0.1:%d", port), "--port=0")
		pid, err := background(d, logFile)
		if err != nil {
			return nil, err
		}
		s.PID, s.Socks, s.Exe = pid, fmt.Sprintf("127.0.0.1:%d", port), "tailscaled"
		if !waitFor(10*time.Second, func() bool { _, err := os.Stat(sock); return err == nil }) {
			netx.StopSession(s)
			return nil, netx.Down(v, fmt.Errorf("tailscaled did not start; see %s", logFile))
		}
		args := []string{"--socket=" + sock, "up", "--hostname=komando-" + v.Name, "--timeout=" + timeout.String()}
		if password != "" { // through a file, so the key never shows in ps
			keyFile := filepath.Join(state, "authkey")
			if err := os.WriteFile(keyFile, []byte(password), 0o600); err != nil {
				return nil, err
			}
			defer os.Remove(keyFile)
			args = append(args, "--auth-key=file:"+keyFile)
		}
		if v.Server != "" {
			args = append(args, "--login-server="+v.Server)
		}
		up := exec.CommandContext(ctx, "tailscale", args...)
		if interactive {
			up.Stdin, up.Stdout, up.Stderr = os.Stdin, os.Stderr, os.Stderr // shows the login link
		}
		if err := up.Run(); err != nil {
			netx.StopSession(s)
			return nil, netx.Down(v, fmt.Errorf("tailscale up: %v", err))
		}
	case k.Protocol != "": // openconnect family, with ocproxy giving a SOCKS port
		port, err := freePort()
		if err != nil {
			return nil, err
		}
		pidFile := filepath.Join(dir, v.Name+".pid")
		_ = os.Remove(pidFile)
		args := []string{"--protocol=" + k.Protocol, "--background", "--pid-file=" + pidFile,
			"--script-tun", "--script", fmt.Sprintf("ocproxy -D %d", port)}
		if v.User != "" {
			args = append(args, "--user="+v.User)
		}
		if !interactive {
			args = append(args, "--non-inter", "--passwd-on-stdin")
		}
		oc := exec.CommandContext(ctx, "openconnect", append(args, "--", v.Portal)...)
		if interactive {
			oc.Stdin, oc.Stdout, oc.Stderr = os.Stdin, os.Stderr, os.Stderr // the login and MFA prompts
		} else {
			oc.Stdin = strings.NewReader(password + "\n")
			lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return nil, err
			}
			defer lf.Close()
			oc.Stdout, oc.Stderr = lf, lf
		}
		if err := oc.Run(); err != nil {
			return nil, netx.Down(v, fmt.Errorf("openconnect: %v (see %s)", err, logFile))
		}
		b, _ := os.ReadFile(pidFile)
		if s.PID, err = strconv.Atoi(strings.TrimSpace(string(b))); err != nil || s.PID <= 1 {
			return nil, netx.Down(v, fmt.Errorf("openconnect wrote no pid; it may still run, see %s", logFile))
		}
		s.Socks, s.Exe = fmt.Sprintf("127.0.0.1:%d", port), "openconnect"
		if !waitFor(10*time.Second, func() bool { return listening(s.Socks) }) {
			netx.StopSession(s)
			return nil, netx.Down(v, fmt.Errorf("ocproxy did not open its SOCKS port"))
		}
	case v.Kind == "openvpn" && !v.OSMode:
		if err := openvpnContainer(ctx, v, dir, password, s, timeout); err != nil {
			return nil, err
		}
	case v.Kind == "openvpn":
		cfg, err := vault.Resolve(v.ConfigRef)
		if err != nil {
			return nil, out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", "add the VPN again with --config", "VPN %s: %v", v.Name, err)
		}
		if err := checkOVPN(cfg); err != nil {
			return nil, out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "add the VPN again without that line", "VPN %s: %v", v.Name, err)
		}
		// root writes its pid and log only where the user cannot plant a
		// symlink: /var/run and syslog
		cfgFile, pidFile := filepath.Join(dir, v.Name+".ovpn"), "/var/run/komando-openvpn-"+v.Name+".pid"
		authFile := filepath.Join(dir, v.Name+".auth")
		defer os.Remove(cfgFile) // openvpn reads both at start; never leave them, also on failure
		defer os.Remove(authFile)
		if err := os.WriteFile(cfgFile, []byte(cfg), 0o600); err != nil {
			return nil, err
		}
		args := []string{"openvpn", "--config", cfgFile, "--daemon", "komando-" + v.Name, "--writepid", pidFile, "--syslog", "komando-" + v.Name}
		logFile = "the system log (komando-" + v.Name + ")"
		if v.User != "" {
			if err := os.WriteFile(authFile, []byte(v.User+"\n"+password+"\n"), 0o600); err != nil {
				return nil, err
			}
			args = append(args, "--auth-user-pass", authFile)
		}
		if !interactive {
			args = append([]string{"-n"}, args...) // works only while sudo remembers the person's password
		}
		sd := exec.CommandContext(ctx, "sudo", args...)
		sd.Stdin, sd.Stdout, sd.Stderr = os.Stdin, os.Stderr, os.Stderr
		if err := sd.Run(); err != nil {
			if !interactive {
				return nil, out.Errf(out.ExitConnect, "VPN_LOGIN_REQUIRED", "ask a human to run `komando vpn up "+v.Name+"` (it needs sudo)",
					"VPN %s runs as root and needs a person to approve sudo", v.Name)
			}
			return nil, netx.Down(v, fmt.Errorf("openvpn: %v", err))
		}
		s.Sudo, s.Exe = true, "openvpn"
		waitFor(10*time.Second, func() bool { _, err := os.Stat(pidFile); return err == nil })
		b, _ := os.ReadFile(pidFile)
		if s.PID, err = strconv.Atoi(strings.TrimSpace(string(b))); err != nil || s.PID <= 1 {
			return nil, netx.Down(v, fmt.Errorf("openvpn wrote no pid; check `sudo ps ax | grep openvpn` and %s", logFile))
		}
		if !waitFor(timeout, func() bool { return listening(v.Check) }) {
			netx.StopSession(s)
			return nil, netx.Down(v, fmt.Errorf("%s did not answer after connecting (see %s)", v.Check, logFile))
		}
	default:
		return nil, out.Usage("%s VPNs need no session", v.Kind)
	}
	if err := store.Update(func(st *store.State) error { st.Sessions[v.Name] = s; return nil }); err != nil {
		netx.StopSession(s)
		return nil, err
	}
	audit(st, "vpn.up", []string{v.Name}, "", true, map[string]any{"kind": v.Kind, "interactive": interactive})
	return s, nil
}

// background starts a process detached from this one, logging to logFile,
// and returns its pid. The pid is read before Release, which resets it.
func background(c *exec.Cmd, logFile string) (int, error) {
	lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer lf.Close()
	c.Stdout, c.Stderr, c.Stdin = lf, lf, nil
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		return 0, err
	}
	pid := c.Process.Pid
	_ = c.Process.Release()
	return pid, nil
}

// spawnServe starts `komando vpn serve NAME` and waits for its SOCKS port.
func spawnServe(name, logFile string) (int, string, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, "", err
	}
	c := exec.Command(self, "vpn", "serve", name)
	c.Env = vault.SelfEnv()
	pid, err := background(c, logFile)
	if err != nil {
		return 0, "", err
	}
	var addr string
	waitFor(15*time.Second, func() bool {
		b, _ := os.ReadFile(logFile)
		if i := strings.Index(string(b), "READY "); i >= 0 {
			addr = strings.TrimSpace(strings.SplitN(string(b)[i+6:], "\n", 2)[0])
			return true
		}
		return strings.Contains(string(b), "ERROR ")
	})
	if addr == "" {
		_ = netx.Terminate(pid)
		b, _ := os.ReadFile(logFile)
		return 0, "", out.Errf(out.ExitConnect, "VPN_DOWN", "see "+logFile, "VPN %s did not start: %s", name, strings.TrimSpace(string(b)))
	}
	return pid, addr, nil
}

// systemVPN connects or disconnects a VPN configured in the OS settings.
func systemVPN(v *store.Vpn, up bool) error {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("scutil", "--nc", map[bool]string{true: "start", false: "stop"}[up], v.Service)
	case "linux":
		c = exec.Command("nmcli", "connection", map[bool]string{true: "up", false: "down"}[up], "id", v.Service)
	default:
		return out.Usage("connect %s from your computer's settings; komando checks it with --check", v.Name)
	}
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := c.Run(); err != nil {
		return netx.Down(v, err)
	}
	return nil
}

func vpnUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up NAME",
		Short: "Connect a VPN now and keep it up for later commands (a person logs in here, MFA included)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			v, ok := st.Vpns[args[0]]
			if !ok {
				return out.NotFound("vpn", args[0])
			}
			if s := netx.LiveSession(v); s != nil {
				out.P.Print("vpn.up", map[string]any{"vpn": v.Name, "already_up": true, "session": s}, nil)
				return nil
			}
			if g.dryRun {
				out.P.Print("vpn.up", map[string]any{"vpn": v.Name, "kind": v.Kind, "would_connect": true}, nil)
				return nil
			}
			// VPNs that change this computer's routes get a before/after
			// comparison, so two networks that claim the same addresses are
			// reported instead of silently breaking one of them
			osLevel := (v.Kind == "openvpn" && v.OSMode) || (v.Kind == "system" && v.Service != "")
			var before []netx.Route
			if osLevel {
				before, _ = netx.Routes()
			}
			clashes := func() []string {
				if !osLevel || before == nil {
					return nil
				}
				after, err := netx.Routes()
				if err != nil {
					return nil
				}
				return netx.Clashes(before, after)
			}
			if !netx.Kinds[v.Kind].Session && v.Kind != "wireguard" { // wireguard may keep a session to skip handshakes
				if v.Kind == "system" && v.Service != "" {
					if err := systemVPN(v, true); err != nil {
						return err
					}
				}
				r := testVpn(cmd.Context(), st, v)
				if !r.OK {
					return r.Error
				}
				res := map[string]any{"vpn": v.Name, "note": v.Kind + " VPNs connect for each command; nothing stays running"}
				if w := clashes(); len(w) > 0 {
					res["warnings"] = w
				}
				out.P.Print("vpn.up", res, nil)
				return nil
			}
			s, err := startSession(cmd.Context(), st, v, interactive())
			if err != nil {
				return err
			}
			res := map[string]any{"vpn": v.Name, "session": s}
			if v.Kind == "wireguard" {
				// WireGuard "connects" without a handshake: only an answer
				// from --check shows the tunnel works
				if v.Check == "" {
					res["notes"] = []string{"no --check address, so the connection was not verified; add one with `komando vpn edit " + v.Name + " --check HOST:PORT`"}
				} else if r := testVpn(cmd.Context(), st, v); !r.OK {
					_ = netx.StopSession(s)
					_ = store.Update(func(st *store.State) error {
						if x := st.Sessions[v.Name]; x != nil && x.PID == s.PID {
							delete(st.Sessions, v.Name)
						}
						return nil
					})
					return out.Errf(out.ExitConnect, "VPN_DOWN", netx.DownHint(v), "VPN %s: no answer from %s through the tunnel (no WireGuard handshake from %s?)",
						v.Name, v.Check, vpnWhere(v))
				} else {
					res["checked"] = v.Check
				}
			}
			if w := clashes(); len(w) > 0 {
				res["warnings"] = w
			}
			out.P.Print("vpn.up", res, nil)
			return nil
		},
	}
}

func vpnDownCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:   "down [NAME...]",
		Short: "Disconnect VPN sessions (--all for every one)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			names := args
			if all {
				names = nil
				for n := range st.Sessions {
					names = append(names, n)
				}
			}
			if len(names) == 0 && !all {
				return out.Usage("give VPN names or --all")
			}
			for _, n := range names {
				if _, ok := st.Vpns[n]; !ok && st.Sessions[n] == nil {
					return out.NotFound("vpn", n)
				}
			}
			if g.dryRun {
				out.P.Print("vpn.down", map[string]any{"would_disconnect": names}, nil)
				return nil
			}
			down, idle, notes := []string{}, []string{}, []string{}
			for _, n := range names {
				v, ok := st.Vpns[n]
				if !ok {
					v = &store.Vpn{Name: n} // a session left from a removed VPN
				}
				if s := st.Sessions[n]; s != nil {
					err := netx.StopSession(s)
					if errors.Is(err, netx.ErrNeedsSudo) && interactive() {
						k := exec.Command("sudo", "kill", strconv.Itoa(s.PID)) // the person types the sudo password
						k.Stdin, k.Stdout, k.Stderr = os.Stdin, os.Stderr, os.Stderr
						err = k.Run()
					}
					if err != nil {
						return out.Errf(out.ExitError, "VPN_STOP_FAILED", "run `komando vpn down "+n+"` in a terminal (it needs sudo)",
							"could not disconnect %s: %v", n, err)
					}
					down = append(down, n)
				} else if v.Kind == "system" && v.Service != "" {
					if err := systemVPN(v, false); err != nil {
						return err
					}
					down = append(down, n)
				} else {
					idle = append(idle, n)
					switch v.Kind {
					case "socks":
						how := "stop the program that serves " + v.Address
						if id := socksTunnel(st, v.Address); id != "" {
							how = "stop its tunnel with `komando tunnel stop " + id + "`"
						}
						notes = append(notes, n+" is a SOCKS proxy that komando does not run; "+how)
					case "wireguard", "system":
						notes = append(notes, n+" is not connected ("+v.Kind+" VPNs connect for each command)")
					default:
						notes = append(notes, n+" is not connected")
					}
				}
			}
			if len(names) == 0 {
				notes = append(notes, "nothing to disconnect: no VPN session is running")
			}
			if err := store.Update(func(s *store.State) error {
				for _, n := range down {
					delete(s.Sessions, n)
				}
				return nil
			}); err != nil {
				return err
			}
			if len(down) > 0 {
				audit(st, "vpn.down", down, "", true, nil)
			}
			out.P.Print("vpn.down", vpnDownData{Disconnected: down, NotConnected: idle, Notes: notes}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&all, "all", false, "disconnect every VPN session")
	return c
}

type vpnDownData struct {
	Disconnected []string `json:"disconnected"`
	NotConnected []string `json:"not_connected,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

func (d vpnDownData) Text() string {
	var sb strings.Builder
	for _, n := range d.Disconnected {
		sb.WriteString("disconnected " + n + "\n")
	}
	for _, n := range d.Notes {
		sb.WriteString(n + "\n")
	}
	return sb.String()
}

type vpnStatusRow struct {
	Name     string    `json:"name"`
	Kind     string    `json:"kind"`
	Up       bool      `json:"up"`
	MFA      bool      `json:"mfa,omitempty"`
	Since    time.Time `json:"since,omitzero"`
	LastUsed time.Time `json:"last_used,omitzero"`
	Socks    string    `json:"socks,omitempty"`
	UsedBy   []string  `json:"used_by,omitempty"`
	Detail   string    `json:"detail,omitempty"` // how "up" was seen, or why not
}

func vpnStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Which VPNs are connected, since when, and what uses them",
		Long: `Shows each VPN with up yes/no. Session VPNs are up while their session
runs; a SOCKS proxy is up when its address answers, a system VPN when its
--check address answers. WireGuard connects for each command.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			out.P.Print("vpn.status", vpnStatusData{Vpns: vpnStatusRows(st)}, nil)
			return nil
		},
	}
}

// vpnServeCmd is the background process of a WireGuard session: it holds
// the VPN and offers a local SOCKS5 port into it.
func vpnServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "serve NAME",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fail := func(err error) error { fmt.Printf("ERROR %v\n", err); return exitCode(1) }
			st, err := loadState()
			if err != nil {
				return fail(err)
			}
			v, ok := st.Vpns[args[0]]
			if !ok {
				return fail(errors.New("no such VPN"))
			}
			ctx := cmd.Context()
			d, closer, err := netx.OpenDirect(ctx, v, sshOpts(st).ConnectTimeout)
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
			var last atomic.Int64
			last.Store(time.Now().Unix())
			if idle > 0 {
				go func() {
					for range time.Tick(time.Minute) {
						if time.Since(time.Unix(last.Load(), 0)) > idle {
							ln.Close()
							return
						}
					}
				}()
			}
			go func() { <-ctx.Done(); ln.Close() }() // SIGTERM from `vpn down`
			cm := &connMgr{ctx: ctx, st: st, vpnDial: d}
			logger := log.New(os.Stdout, "", log.LstdFlags)
			for {
				c, err := ln.Accept()
				if err != nil {
					_ = store.Update(func(s *store.State) error {
						if x := s.Sessions[v.Name]; x != nil && x.PID == os.Getpid() { // not a newer session's entry
							delete(s.Sessions, v.Name)
						}
						return nil
					})
					return nil
				}
				last.Store(time.Now().Unix())
				go func() { defer c.Close(); socks5(c, cm, logger) }()
			}
		},
	}
}

//go:embed ovpn/Dockerfile ovpn/entrypoint.sh ovpn/up.sh ovpn/sockd.conf
var ovpnFiles embed.FS

// ovpnImage names the container image; bump it when ovpn/ changes.
const ovpnImage = "komando-openvpn:4"

// ensureOVPNImage builds komando's OpenVPN image once, from files inside
// the komando binary (Alpine's openvpn and dante packages).
func ensureOVPNImage(ctx context.Context) error {
	if exec.CommandContext(ctx, "docker", "image", "inspect", ovpnImage).Run() == nil {
		return nil
	}
	dir, err := os.MkdirTemp("", "komando-ovpn-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for _, f := range []string{"Dockerfile", "entrypoint.sh", "up.sh", "sockd.conf"} {
		b, _ := ovpnFiles.ReadFile("ovpn/" + f)
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "building the OpenVPN container image (once)...")
	b, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", ovpnImage, dir).CombinedOutput()
	if err != nil {
		return out.Errf(out.ExitError, "VPN_IMAGE", "check that Docker runs (`docker info`)", "building %s: %v: %s", ovpnImage, err, strings.TrimSpace(string(b)))
	}
	return nil
}

// openvpnContainer runs OpenVPN in a container with a SOCKS port on
// 127.0.0.1, so only komando's connections use the VPN.
func openvpnContainer(ctx context.Context, v *store.Vpn, dir, password string, s *store.VpnSession, timeout time.Duration) error {
	cfg, err := vault.Resolve(v.ConfigRef)
	if err != nil {
		return out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", "add the VPN again with --config", "VPN %s: %v", v.Name, err)
	}
	if err := checkOVPN(cfg); err != nil {
		return out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "add the VPN again without that line", "VPN %s: %v", v.Name, err)
	}
	if err := ensureOVPNImage(ctx); err != nil {
		return err
	}
	mount := filepath.Join(dir, v.Name+"-openvpn")
	if err := os.MkdirAll(mount, 0o700); err != nil {
		return err
	}
	// OpenVPN reads these once at start; they never stay on disk, also not
	// when connecting fails
	cfgFile, authFile, envFile := filepath.Join(mount, "config.ovpn"), filepath.Join(mount, "auth"), filepath.Join(dir, v.Name+".env")
	defer os.Remove(cfgFile)
	defer os.Remove(authFile)
	defer os.Remove(envFile)
	if err := os.WriteFile(cfgFile, []byte(cfg), 0o600); err != nil {
		return err
	}
	auth := ""
	if v.User != "" {
		auth = v.User + "\n" + password + "\n"
	}
	if err := os.WriteFile(authFile, []byte(auth), 0o600); err != nil {
		return err
	}
	// a random login for the container's SOCKS port, passed in a file so it
	// is not on any command line
	s.SocksUser, s.SocksPass = "k"+randHex(6), randHex(24)
	if err := os.WriteFile(envFile, []byte("KOMANDO_SOCKS_USER="+s.SocksUser+"\nKOMANDO_SOCKS_PASS="+s.SocksPass+"\n"), 0o600); err != nil {
		return err
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	// the name is unique per komando home, so two homes never touch each other's container
	name := "komando-vpn-" + v.Name + "-" + randHex(4)
	run := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name,
		"--label", "komando.home="+store.Home(), "--label", "komando.vpn="+v.Name,
		"--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "SETUID", "--cap-add", "SETGID",
		"--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
		"--security-opt", "no-new-privileges", "--device", "/dev/net/tun", "--env-file", envFile,
		"-p", fmt.Sprintf("127.0.0.1:%d:1080", port), "-v", mount+":/vpn:ro", ovpnImage)
	b, err := run.CombinedOutput()
	if err != nil {
		return netx.Down(v, fmt.Errorf("docker run: %v: %s", err, strings.TrimSpace(string(b))))
	}
	s.Container, s.Socks = strings.TrimSpace(string(b)), fmt.Sprintf("127.0.0.1:%d", port)
	fail := func(why string) error {
		logs, _ := exec.Command("docker", "logs", "--tail", "20", s.Container).CombinedOutput()
		_ = exec.Command("docker", "rm", "-f", s.Container).Run()
		return netx.Down(v, fmt.Errorf("%s: %s", why, strings.TrimSpace(string(logs))))
	}
	logs := func() string { b, _ := exec.Command("docker", "logs", s.Container).CombinedOutput(); return string(b) }
	waitFor(timeout, func() bool {
		l := logs()
		return strings.Contains(l, "OPENVPN_READY") || strings.Contains(l, "OPENVPN_FAILED") || !netx.SessionAlive(s)
	})
	if !strings.Contains(logs(), "OPENVPN_READY") {
		return fail("OpenVPN did not connect")
	}
	if !waitFor(10*time.Second, func() bool { return listening(s.Socks) }) {
		return fail("the SOCKS port did not open")
	}
	return nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
