package cli

import (
	"context"
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
		_, err = startSession(ctx, st, v, false)
		return err
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

func clientMissing(v *store.Vpn) error {
	for _, bin := range netx.Kinds[v.Kind].Client {
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
	logFile := filepath.Join(dir, v.Name+".log")
	password := ""
	if v.KeyRef != "" && v.Kind != "wireguard" {
		if password, err = vault.Resolve(v.KeyRef); err != nil {
			return nil, out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", "store it with `komando secret set NAME`", "VPN %s: %v", v.Name, err)
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
		s.PID, s.Socks = pid, fmt.Sprintf("127.0.0.1:%d", port)
		if !waitFor(10*time.Second, func() bool { _, err := os.Stat(sock); return err == nil }) {
			netx.StopSession(s)
			return nil, netx.Down(v, fmt.Errorf("tailscaled did not start; see %s", logFile))
		}
		args := []string{"--socket=" + sock, "up", "--hostname=komando-" + v.Name, "--timeout=" + timeout.String()}
		if password != "" {
			args = append(args, "--authkey="+password)
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
		oc := exec.CommandContext(ctx, "openconnect", append(args, v.Portal)...)
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
		s.PID, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		s.Socks = fmt.Sprintf("127.0.0.1:%d", port)
		if !waitFor(10*time.Second, func() bool { return listening(s.Socks) }) {
			netx.StopSession(s)
			return nil, netx.Down(v, fmt.Errorf("ocproxy did not open its SOCKS port"))
		}
	case v.Kind == "openvpn":
		cfg, err := vault.Resolve(v.ConfigRef)
		if err != nil {
			return nil, out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", "add the VPN again with --config", "VPN %s: %v", v.Name, err)
		}
		if err := checkOVPN(cfg); err != nil {
			return nil, out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "add the VPN again without that line", "VPN %s: %v", v.Name, err)
		}
		cfgFile, pidFile := filepath.Join(dir, v.Name+".ovpn"), filepath.Join(dir, v.Name+".pid")
		if err := os.WriteFile(cfgFile, []byte(cfg), 0o600); err != nil {
			return nil, err
		}
		_ = os.Remove(pidFile)
		args := []string{"openvpn", "--config", cfgFile, "--daemon", "komando-" + v.Name, "--writepid", pidFile, "--log", logFile}
		if v.User != "" {
			auth := filepath.Join(dir, v.Name+".auth")
			if err := os.WriteFile(auth, []byte(v.User+"\n"+password+"\n"), 0o600); err != nil {
				return nil, err
			}
			args = append(args, "--auth-user-pass", auth)
		}
		if !interactive {
			args = append([]string{"-n"}, args...) // only works with a sudo rule for openvpn
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
		s.Sudo = true
		waitFor(10*time.Second, func() bool { _, err := os.Stat(pidFile); return err == nil })
		b, _ := os.ReadFile(pidFile)
		s.PID, _ = strconv.Atoi(strings.TrimSpace(string(b)))
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
	c.Env = os.Environ()
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
				out.P.Print("vpn.up", map[string]any{"vpn": v.Name, "note": v.Kind + " VPNs connect for each command; nothing stays running"}, nil)
				return nil
			}
			if g.dryRun {
				out.P.Print("vpn.up", map[string]any{"vpn": v.Name, "kind": v.Kind}, nil)
				return nil
			}
			var warn []string
			if v.Kind == "openvpn" {
				for _, x := range st.Sessions {
					if xv := st.Vpns[x.Vpn]; xv != nil && xv.Kind == "openvpn" && netx.Alive(x.PID) {
						warn = append(warn, "OpenVPN "+x.Vpn+" is also connected; if both use the same addresses, one will not work")
					}
				}
			}
			s, err := startSession(cmd.Context(), st, v, interactive())
			if err != nil {
				return err
			}
			res := map[string]any{"vpn": v.Name, "session": s}
			if len(warn) > 0 {
				res["warnings"] = warn
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
			if len(names) == 0 {
				return out.Usage("give VPN names or --all")
			}
			var down []string
			for _, n := range names {
				v, ok := st.Vpns[n]
				if !ok {
					return out.NotFound("vpn", n)
				}
				if s := st.Sessions[n]; s != nil {
					netx.StopSession(s)
					down = append(down, n)
				} else if v.Kind == "system" && v.Service != "" {
					if err := systemVPN(v, false); err != nil {
						return err
					}
					down = append(down, n)
				}
			}
			if err := store.Update(func(s *store.State) error {
				for _, n := range down {
					delete(s.Sessions, n)
				}
				return nil
			}); err != nil {
				return err
			}
			audit(st, "vpn.down", down, "", true, nil)
			out.P.Print("vpn.down", map[string]any{"disconnected": down}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&all, "all", false, "disconnect every VPN session")
	return c
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
}

func vpnStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Which VPNs are connected, since when, and what uses them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			rows := []vpnStatusRow{}
			for _, v := range st.SortedVpns() {
				r := vpnStatusRow{Name: v.Name, Kind: v.Kind, MFA: v.MFA, UsedBy: vpnUsers(st, v.Name)}
				if s := st.Sessions[v.Name]; s != nil && netx.Alive(s.PID) {
					r.Up, r.Since, r.LastUsed, r.Socks = true, s.StartedAt, s.LastUsed, s.Socks
				}
				rows = append(rows, r)
			}
			out.P.Print("vpn.status", map[string]any{"vpns": rows}, nil)
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
					_ = store.Update(func(s *store.State) error { delete(s.Sessions, v.Name); return nil })
					return nil
				}
				last.Store(time.Now().Unix())
				go func() { defer c.Close(); socks5(c, cm, logger) }()
			}
		},
	}
}
