package cli

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
	if netx.BuiltinSSL(v.Kind) {
		return nil // komando's own client
	}
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
	pkg := map[string]string{"ocproxy": "ocproxy", "openconnect": "openconnect", "openvpn": "openvpn"}[bin]
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
		pid, addr, err := spawnServe(v.Name, logFile, 15*time.Second, s)
		if err != nil {
			return nil, err
		}
		s.PID, s.Socks = pid, addr
		if self, err := os.Executable(); err == nil {
			s.Exe = filepath.Base(self)
		}
	case v.Kind == "tailscale":
		if v.MFA { // no auth key: a person logs in through the browser first
			err := netx.TailscaleLogin(ctx, v, func(url string) {
				fmt.Fprintf(os.Stderr, "komando: log in to %s at %s\n", v.Name, cleanText(url))
				openBrowser(ctx, url)
			})
			if err != nil {
				return nil, err
			}
		}
		pid, addr, err := spawnServe(v.Name, logFile, 90*time.Second, s)
		if err != nil {
			return nil, err
		}
		s.PID, s.Socks = pid, addr
		if self, err := os.Executable(); err == nil {
			s.Exe = filepath.Base(self)
		}
	case netx.BuiltinSSL(v.Kind):
		// log in here, where a person can answer (MFA); the session's
		// server gets only the cookie
		var prompt func(string, bool) (string, error)
		if interactive {
			prompt = loginPrompt
		}
		cookie, err := netx.SSLVPNLogin(ctx, v, prompt)
		if err != nil {
			return nil, err
		}
		pid, addr, err := spawnServeWith(v.Name, logFile, timeout+15*time.Second, cookie, s)
		if err != nil {
			return nil, err
		}
		s.PID, s.Socks = pid, addr
		if self, err := os.Executable(); err == nil {
			s.Exe = filepath.Base(self)
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
	case v.Kind == "openvpn" && !v.OSMode, oneOf(v.Kind, "l2tp", "ipsec", "ikev2"):
		// komando's own OpenVPN or IPsec client in a `komando vpn serve` process
		typed := ""
		if v.KeyRef == "" && (v.MFA || v.User != "") {
			if !interactive {
				return nil, netx.LoginRequired(v)
			}
			var err error
			typed, err = loginSecret(fmt.Sprintf("Password for %s on VPN %s (with the PIN or one-time code, if it wants one): ", cmp.Or(v.User, "you"), v.Name))
			if err != nil {
				return nil, err
			}
		}
		pid, addr, err := spawnServeWith(v.Name, logFile, timeout+15*time.Second, typed, s)
		if err != nil {
			return nil, err
		}
		s.PID, s.Socks = pid, addr
		if self, err := os.Executable(); err == nil {
			s.Exe = filepath.Base(self)
		}
	case v.Kind == "openvpn":
		cfg, err := vault.Resolve(v.ConfigRef)
		if err != nil {
			return nil, out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", "add the VPN again with --config", "VPN %s: %v", v.Name, err)
		}
		// openvpn runs as root, so it gets the profile as komando read it,
		// written again (canonicalOVPN), and on its input: there is no
		// file another program could change between the check and the start
		clean, err := canonicalOVPN(cfg)
		if err != nil {
			return nil, out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "add the VPN again without that line", "VPN %s: %v", v.Name, err).NoFlag()
		}
		// root writes its pid and log only where the user cannot plant a
		// symlink: /var/run and syslog
		pidFile := "/var/run/komando-openvpn-" + v.Name + ".pid"
		authFile := filepath.Join(dir, v.Name+".auth")
		defer os.Remove(authFile) // openvpn reads it at start; never leave it, also on failure
		args := []string{"openvpn", "--config", "stdin",
			// options after --config win over the profile's: whatever it
			// says, openvpn calls no scripts, only its own ip/route tools
			"--script-security", "1",
			"--daemon", "komando-" + v.Name, "--writepid", pidFile, "--syslog", "komando-" + v.Name}
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
		// sudo asks for the password, and openvpn for a private key's, on
		// the terminal (/dev/tty), not on the input
		sd := exec.CommandContext(ctx, "sudo", args...)
		sd.Stdin, sd.Stdout, sd.Stderr = strings.NewReader(clean), os.Stderr, os.Stderr
		if err := sd.Run(); err != nil {
			if !interactive {
				return nil, out.Errf(out.ExitConnect, "VPN_LOGIN_REQUIRED", "ask a person to run `komando vpn up "+v.Name+"` (it needs sudo)",
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
	if err := store.UpdateRuntime(func(st *store.State) error { st.Sessions[v.Name] = s; return nil }); err != nil {
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
	c.Stdout, c.Stderr = lf, lf
	c.SysProcAttr = detachAttr()
	if err := c.Start(); err != nil {
		return 0, err
	}
	pid := c.Process.Pid
	_ = c.Process.Release()
	return pid, nil
}

// loginPrompt asks a person what a login wants: a built-in VPN client's or
// an SSH server's (askSSH). A password, a code, a choice, a notice to
// accept. The text comes from the server, so each line is cleaned of
// control characters (a banner keeps its lines); the last line is the
// question.
func loginPrompt(label string, secretIn bool) (string, error) {
	if secretIn {
		return loginSecret(loginQuestion(label))
	}
	v, err := readAnswer(loginQuestion(label), false)
	return strings.TrimSpace(v), err
}

// loginQuestion is the text loginPrompt shows for label: each line cleaned,
// and the last one ending in ": " (or " " after a question mark or a
// [y/N]).
func loginQuestion(label string) string {
	lines := strings.Split(strings.TrimSpace(label), "\n")
	for i, l := range lines {
		lines[i] = cleanText(l)
	}
	q := strings.TrimSuffix(strings.TrimSpace(lines[len(lines)-1]), ":")
	if strings.HasSuffix(q, "?") || strings.HasSuffix(q, "]") {
		q += " "
	} else {
		q += ": "
	}
	return strings.Join(append(lines[:len(lines)-1], q), "\n")
}

// loginSecret reads a login's password or code, hidden. A paste of more than one
// line is refused as it is for a secret, in words that fit a login.
func loginSecret(label string) (string, error) {
	v, err := readHidden(label)
	var oe *out.Error
	if errors.As(err, &oe) && oe.Code == "USAGE" { // readHidden's only usage error
		oe.Message = "the answer has more than one line, so it was not sent"
		oe.Hint = "paste only the password or code, on one line"
	}
	return v, err
}

// spawnServe starts `komando vpn serve NAME` and waits for its SOCKS port.
func spawnServe(name, logFile string, wait time.Duration, s *store.VpnSession) (int, string, error) {
	return spawnServeWith(name, logFile, wait, "", s)
}

// spawnServeWith starts the session's server with a random SOCKS login
// (kept in s), a password a person typed and the vault passphrase, all on
// its stdin.
func spawnServeWith(name, logFile string, wait time.Duration, password string, s *store.VpnSession) (int, string, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, "", err
	}
	pid, err := background(serveCommand(self, name, password, s), logFile)
	if err != nil {
		return 0, "", err
	}
	var addr string
	waitFor(wait, func() bool {
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
		return 0, "", out.Errf(out.ExitConnect, "VPN_DOWN", "the message ends with its log; `komando vpn test "+name+"` tries again, and the whole log is "+logFile+" (for a person to read)", "VPN %s did not start: %s", name, strings.TrimSpace(string(b)))
	}
	return pid, addr, nil
}

// serveCommand is the `komando vpn serve NAME` process (self is komando):
// a new SOCKS login, kept in s, and the typed password go to it on stdin,
// then the vault passphrase, never in its environment: it runs for long
// (serveStdin reads them).
func serveCommand(self, name, password string, s *store.VpnSession) *exec.Cmd {
	c := exec.Command(self, "vpn", "serve", name, "--password-stdin")
	s.SocksUser, s.SocksPass = "k"+randToken(6), randToken(24)
	c.Stdin = strings.NewReader("SOCKS " + s.SocksUser + " " + s.SocksPass + "\n" + password + "\n")
	vault.PassOnStdin(c)
	return c
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

// sessionView is a session as `vpn up` shows it: without the SOCKS login,
// which only komando itself uses (an agent with it could use the tunnel
// without komando's checks or audit).
func sessionView(s *store.VpnSession) store.VpnSession {
	v := *s
	v.SocksUser, v.SocksPass = "", ""
	return v
}

func vpnUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up NAME",
		Short: "Connect a VPN now and keep it up (a person logs in here)",
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
				out.P.Print("vpn.up", map[string]any{"vpn": v.Name, "already_up": true, "session": sessionView(s)}, nil)
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
			res := map[string]any{"vpn": v.Name, "session": sessionView(s)}
			if v.Kind == "wireguard" {
				// WireGuard "connects" without a handshake: only an answer
				// from --check shows the tunnel works
				if v.Check == "" {
					res["notes"] = []string{"no --check address, so the connection was not verified; add one with `komando vpn edit " + v.Name + " --check HOST:PORT`"}
				} else if r := testVpn(cmd.Context(), st, v); !r.OK {
					_ = netx.StopSession(s)
					_ = store.UpdateRuntime(func(st *store.State) error {
						if x := st.Sessions[v.Name]; x != nil && x.PID == s.PID {
							delete(st.Sessions, v.Name)
						}
						return nil
					})
					why := ""
					if v.Kind == "wireguard" {
						why = " (no WireGuard handshake from " + vpnWhere(v) + " yet)"
					}
					return out.Errf(out.ExitConnect, "VPN_DOWN", netx.DownHint(v), "VPN %s: no answer from %s through the tunnel%s", v.Name, v.Check, why)
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
					case "proxy":
						notes = append(notes, n+" is an HTTP proxy that komando does not run")
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
			if err := store.UpdateRuntime(func(s *store.State) error {
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
	Detail   string    `json:"detail,omitempty"`   // how "up" was seen, or why not
	LastEnd  string    `json:"last_end,omitempty"` // why its last session ended, from the session log
	LastLog  []string  `json:"last_log,omitempty"` // l2tp, ipsec, ikev2: the last lines of that log (no secrets in it)
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

// randToken is n random bytes as hex.
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
