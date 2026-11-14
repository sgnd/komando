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
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// VPN sessions: a VPN kept up in the background between commands, so a
// login (and its MFA) happens once. `vpn up` starts one; commands whose
// --via path needs a VPN without MFA start one by themselves. A session
// unused for the vpn_idle setting (30m) is disconnected.

// startVpnFor brings up vpn name for a command of cl whose --via path
// needs it (netx.StartSession, call_hooks.go).
func startVpnFor(cl *call, ctx context.Context, name string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	v, ok := st.Vpns[name]
	if !ok {
		return out.NotFound("vpn", name)
	}
	_, err = startSession(cl, ctx, st, v, false)
	auditVpnUp(cl, st, v, false, err)
	if err != nil {
		return err
	}
	// started by a command, not by `vpn up`: say it now stays up
	if idle, _ := time.ParseDuration(st.Settings.VpnIdle); idle > 0 {
		noticef(cl, "vpn %s connected; it stays up until unused for %s (`komando vpn down %s` stops it)", name, humanAge(idle), name)
	} else {
		noticef(cl, "vpn %s connected; it stays up until `komando vpn down %s`", name, name)
	}
	return nil
}

func vpnDir() (string, error) {
	return store.Path("vpn"), store.MkdirPrivate("vpn")
}

// vpnLogDir is vpnDir for a VPN that starts: it also removes the logs of
// VPNs (some since removed) unused for a week.
func vpnLogDir() (string, error) {
	st, err := store.Load()
	if err != nil {
		return vpnDir()
	}
	return store.Path("vpn"), logDir("vpn", st)
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
	if netx.BuiltinSSLFor(v) {
		return nil // komando's own client
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

// vpnUpPlan is what vpn up --dry-run prints. A VPN that needs a person,
// with nobody at the terminal, would not connect: VPN_LOGIN_REQUIRED goes
// to meta.would_be_blocked.
func vpnUpPlan(cl *call, v *store.Vpn) map[string]any {
	res := map[string]any{"vpn": v.Name, "kind": v.Kind, "would_connect": true}
	if (netx.Kinds[v.Kind].Session || v.Kind == "wireguard") && needsPersonLogin(v) && !cl.interactive() {
		res["would_connect"] = false
		cl.out.WouldBlock(toErr(netx.LoginRequired(v)))
	}
	return res
}

// needsPersonLogin: connecting v needs a person to log in, so startSession
// refuses it with VPN_LOGIN_REQUIRED when nobody is at the terminal.
func needsPersonLogin(v *store.Vpn) bool {
	if v.MFA {
		return true
	}
	ownClient := v.Kind == "openvpn" && !v.OSMode || oneOf(v.Kind, "l2tp", "ipsec", "ikev2")
	return ownClient && v.KeyRef == "" && v.User != ""
}

// startSession connects v in the background and records the session.
// interactive means a person is at the terminal for the login (and MFA).
func startSession(cl *call, ctx context.Context, st *store.State, v *store.Vpn, interactive bool) (*store.VpnSession, error) {
	if err := osModeGone(v); err != nil {
		return nil, err
	}
	if v.MFA && !interactive {
		return nil, netx.LoginRequired(v)
	}
	if err := clientMissing(v); err != nil {
		return nil, err
	}
	dir, err := vpnLogDir()
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
		pid, addr, err := spawnServe(ctx, v.Name, logFile, 15*time.Second, s)
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
				fmt.Fprintf(cl.out.Err, "komando: log in to %s at %s\n", v.Name, cleanText(url))
				openBrowser(ctx, url)
			})
			if err != nil {
				return nil, err
			}
		}
		pid, addr, err := spawnServe(ctx, v.Name, logFile, 90*time.Second, s)
		if err != nil {
			return nil, err
		}
		s.PID, s.Socks = pid, addr
		if self, err := os.Executable(); err == nil {
			s.Exe = filepath.Base(self)
		}
	case netx.BuiltinSSLFor(v):
		// log in here, where a person can answer (MFA); the session's
		// server gets only the cookie
		cookie, err := sslLogin(cl, ctx, v, interactive)
		if err != nil {
			return nil, err
		}
		pid, addr, err := spawnServeWith(ctx, v.Name, logFile, timeout+15*time.Second, cookie, s)
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
		oc, err := openconnectCmd(cl, ctx, v, k.Protocol, pidFile, port, interactive)
		if err != nil {
			return nil, err
		}
		if interactive {
			oc.Stdin, oc.Stdout, oc.Stderr = cl.stdin, cl.out.Err, cl.out.Err // the login and MFA prompts
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
	case v.Kind == "openvpn", oneOf(v.Kind, "l2tp", "ipsec", "ikev2"):
		// komando's own OpenVPN or IPsec client in a `komando vpn serve` process
		typed := ""
		if v.KeyRef == "" && (v.MFA || v.User != "") {
			if !interactive {
				return nil, netx.LoginRequired(v)
			}
			var err error
			typed, err = loginSecret(cl, fmt.Sprintf("Password for %s on VPN %s (with the PIN or one-time code, if it wants one): ", cmp.Or(v.User, "you"), v.Name))
			if err != nil {
				return nil, err
			}
		}
		pid, addr, err := spawnServeWith(ctx, v.Name, logFile, timeout+15*time.Second, typed, s)
		if err != nil {
			return nil, err
		}
		s.PID, s.Socks = pid, addr
		if self, err := os.Executable(); err == nil {
			s.Exe = filepath.Base(self)
		}
	default:
		return nil, out.Usage("%s VPNs need no session", v.Kind)
	}
	if err := store.UpdateRuntime(cl.storeWrite(), func(st *store.State) error { st.Sessions[v.Name] = s; return nil }); err != nil {
		netx.StopSession(s)
		return nil, err
	}
	return s, nil
}

// auditVpnUp records a vpn up, or a session a command started, with how
// it ended: a session that started but failed its --check is a failure.
func auditVpnUp(cl *call, st *store.State, v *store.Vpn, interactive bool, err error) {
	rec := map[string]any{"kind": v.Kind, "interactive": interactive}
	if err != nil {
		rec["error"] = toErr(err).Code
	}
	audit(cl, st, "vpn.up", []string{v.Name}, "", err == nil, rec)
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
func loginPrompt(cl *call, label string, secretIn bool) (string, error) {
	if secretIn {
		return loginSecret(cl, loginQuestion(label))
	}
	v, err := readAnswer(cl, loginQuestion(label), false)
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
func loginSecret(cl *call, label string) (string, error) {
	v, err := readHidden(cl, label)
	var oe *out.Error
	if errors.As(err, &oe) && oe.Code == "USAGE" { // readHidden's only usage error
		oe.Message = "the answer has more than one line, so it was not sent"
		oe.Hint = "paste only the password or code, on one line"
	}
	return v, err
}

// spawnServe starts `komando vpn serve NAME` and waits for its SOCKS port.
func spawnServe(ctx context.Context, name, logFile string, wait time.Duration, s *store.VpnSession) (int, string, error) {
	return spawnServeWith(ctx, name, logFile, wait, "", s)
}

// spawnServeWith starts the session's server with a random SOCKS login
// (kept in s), a password a person typed and the vault passphrase, all on
// its stdin. Ctrl-C (ctx) while it waits stops that server: a VPN the
// person cancelled does not come up after all.
func spawnServeWith(ctx context.Context, name, logFile string, wait time.Duration, password string, s *store.VpnSession) (int, string, error) {
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
		if ctx.Err() != nil {
			return true
		}
		b, _ := os.ReadFile(logFile)
		if i := strings.Index(string(b), "READY "); i >= 0 {
			addr = strings.TrimSpace(strings.SplitN(string(b)[i+6:], "\n", 2)[0])
			return true
		}
		return strings.Contains(string(b), "ERROR ")
	})
	if err := ctx.Err(); err != nil {
		_ = netx.Terminate(pid)
		e := toErr(err)
		e.Hint = "vpn " + name + " was stopped before it came up; nothing is left running"
		return 0, "", e
	}
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
var serveCommand = func(self, name, password string, s *store.VpnSession) *exec.Cmd {
	c := exec.Command(self, "vpn", "serve", name, "--password-stdin")
	s.SocksUser, s.SocksPass = "k"+randToken(6), randToken(24)
	c.Stdin = strings.NewReader("SOCKS " + s.SocksUser + " " + s.SocksPass + "\n" + password + "\n")
	vault.PassOnStdin(c)
	return c
}

// systemVPN connects or disconnects a VPN configured in the OS settings.
func systemVPN(cl *call, v *store.Vpn, up bool) error {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("scutil", "--nc", map[bool]string{true: "start", false: "stop"}[up], v.Service)
	case "linux":
		c = exec.Command("nmcli", "connection", map[bool]string{true: "up", false: "down"}[up], "id", v.Service)
	default:
		return out.Usage("connect %s from your computer's settings; komando checks it with --check", v.Name)
	}
	c.Stdin, c.Stdout, c.Stderr = cl.stdin, cl.out.Err, cl.out.Err
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
		Short: "Connect a VPN now and keep it up",
		Args:  cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			v, ok := st.Vpns[args[0]]
			if !ok {
				return out.NotFound("vpn", args[0])
			}
			if err := osModeGone(v); err != nil {
				return err
			}
			if s := netx.LiveSession(cmd.Context(), v); s != nil {
				cl.out.Print("vpn.up", map[string]any{"vpn": v.Name, "already_up": true, "session": sessionView(s)}, nil)
				return nil
			}
			if cl.flags.dryRun {
				cl.out.Print("vpn.up", vpnUpPlan(cl, v), nil)
				return nil
			}
			// VPNs that change this computer's routes get a before/after
			// comparison, so two networks that claim the same addresses are
			// reported instead of silently breaking one of them
			osLevel := v.Kind == "system" && v.Service != ""
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
					if err := systemVPN(cl, v, true); err != nil {
						return err
					}
				}
				r := testVpn(cl, cmd.Context(), st, v)
				if !r.OK {
					return r.Error
				}
				res := map[string]any{"vpn": v.Name, "note": v.Kind + " VPNs connect for each command; nothing stays running"}
				if w := clashes(); len(w) > 0 {
					res["warnings"] = w
				}
				cl.out.Print("vpn.up", res, nil)
				return nil
			}
			person := cl.interactive()
			s, err := startSession(cl, cmd.Context(), st, v, person)
			if err != nil {
				auditVpnUp(cl, st, v, person, err)
				return err
			}
			res := map[string]any{"vpn": v.Name, "session": sessionView(s)}
			if v.Kind == "wireguard" {
				// WireGuard "connects" without a handshake: only an answer
				// from --check shows the tunnel works
				if v.Check == "" {
					res["notes"] = []string{"no --check address, so the connection was not verified; add one with `komando vpn edit " + v.Name + " --check HOST:PORT`"}
				} else if r := testVpn(cl, cmd.Context(), st, v); !r.OK {
					_ = netx.StopSession(s)
					_ = store.UpdateRuntime(cl.storeWrite(), func(st *store.State) error {
						if x := st.Sessions[v.Name]; x != nil && x.PID == s.PID {
							delete(st.Sessions, v.Name)
						}
						return nil
					})
					why := ""
					if v.Kind == "wireguard" {
						why = " (no WireGuard handshake from " + vpnWhere(v) + " yet)"
					}
					err := out.Errf(out.ExitConnect, "VPN_DOWN", netx.DownHint(v), "VPN %s: no answer from %s through the tunnel%s", v.Name, v.Check, why)
					auditVpnUp(cl, st, v, person, err)
					return err
				} else {
					res["checked"] = v.Check
				}
			}
			auditVpnUp(cl, st, v, person, nil)
			if w := clashes(); len(w) > 0 {
				res["warnings"] = w
			}
			cl.out.Print("vpn.up", res, nil)
			return nil
		}),
	}
}

func vpnDownCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:   "down [NAME...]",
		Short: "Disconnect VPN sessions (--all for every one)",
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			if all && len(args) > 0 {
				return out.Errf(out.ExitUsage, "USAGE", "use `komando vpn down --all` or `komando vpn down "+strings.Join(args, " ")+"`", "--all disconnects every VPN session; give names or --all, not both")
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
			if cl.flags.dryRun {
				res := map[string]any{"would_disconnect": names}
				if a := vpnDownAffects(st, names); len(a) > 0 {
					res["affects"] = a
				}
				cl.out.Print("vpn.down", res, nil)
				return nil
			}
			down, idle, notes := []string{}, []string{}, []string{}
			for _, n := range names {
				v, ok := st.Vpns[n]
				if !ok {
					v = &store.Vpn{Name: n} // a session left from a removed VPN
				}
				if s := st.Sessions[n]; s != nil {
					if err := netx.StopSession(s); err != nil {
						return out.Errf(out.ExitError, "VPN_STOP_FAILED", "run `komando vpn down "+n+"` again; if it still fails, end process "+strconv.Itoa(s.PID)+" yourself",
							"could not disconnect %s: %v", n, err)
					}
					down = append(down, n)
				} else if v.Kind == "system" && v.Service != "" {
					if err := systemVPN(cl, v, false); err != nil {
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
			if err := store.UpdateRuntime(cl.storeWrite(), func(s *store.State) error {
				for _, n := range down {
					delete(s.Sessions, n)
				}
				return nil
			}); err != nil {
				return err
			}
			if len(down) > 0 {
				audit(cl, st, "vpn.down", down, "", true, nil)
			}
			cl.out.Print("vpn.down", vpnDownData{Disconnected: down, NotConnected: idle, Notes: notes, Affects: vpnDownAffects(st, down)}, nil)
			return nil
		}),
	}
	c.Flags().BoolVar(&all, "all", false, "disconnect every VPN session")
	return c
}

type vpnDownData struct {
	Disconnected []string            `json:"disconnected"`
	NotConnected []string            `json:"not_connected,omitempty"`
	Notes        []string            `json:"notes,omitempty"`
	Affects      []vpnDownAffectsRow `json:"affects,omitempty"`
}

// vpnDownAffectsRow is what disconnecting one VPN does to the servers and
// conns whose --via path needs it: with a login a person must give, they
// stop answering until `vpn up`; otherwise their next command connects it
// again.
type vpnDownAffectsRow struct {
	Vpn    string   `json:"vpn"`
	UsedBy []string `json:"used_by"`
	Until  string   `json:"until"` // "vpn up" or "next command"
	Next   string   `json:"next,omitempty"`
}

// vpnDownAffects lists, for each VPN in names that something uses, what a
// disconnect does to those users.
func vpnDownAffects(st *store.State, names []string) []vpnDownAffectsRow {
	var rows []vpnDownAffectsRow
	for _, n := range names {
		users := vpnUsers(st, n)
		v := st.Vpns[n]
		if len(users) == 0 || v == nil {
			continue
		}
		r := vpnDownAffectsRow{Vpn: n, UsedBy: users, Until: "next command"}
		if needsPersonLogin(v) {
			r.Until, r.Next = "vpn up", "komando vpn up "+n
		}
		rows = append(rows, r)
	}
	return rows
}

func (r vpnDownAffectsRow) text() string {
	who := strings.Join(r.UsedBy, ", ")
	if len(r.UsedBy) > 3 {
		who = usedByText(r.UsedBy)
	}
	if r.Until == "vpn up" {
		return who + " stop answering until a person runs `" + r.Next + "`"
	}
	return who + " connect " + r.Vpn + " again on their next command"
}

func (d vpnDownData) Text() string {
	var sb strings.Builder
	for _, n := range d.Disconnected {
		sb.WriteString("disconnected " + n + "\n")
	}
	for _, a := range d.Affects {
		sb.WriteString("  " + a.text() + "\n")
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
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			cl.out.Print("vpn.status", vpnStatusData{Vpns: vpnStatusRows(st)}, nil)
			return nil
		}),
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

// osModeGone refuses an OpenVPN saved with the removed --os-mode (which ran
// the openvpn program as root): it is never quietly run another way. Adding
// it again checks its profile against komando's own client.
func osModeGone(v *store.Vpn) error {
	if !v.OSMode {
		return nil
	}
	return out.Errf(out.ExitUsage, "VPN_OS_MODE_REMOVED",
		"add it again with komando's own client: `komando vpn add "+v.Name+" openvpn --config FILE.ovpn --check HOST:PORT --overwrite` (plus --user and --password-ref if it logs in)",
		"VPN %s uses OpenVPN OS mode (--os-mode), which komando no longer has", v.Name)
}

// openconnectCmd is the openconnect command of v, with ocproxy giving its
// SOCKS port. The password and the tunnel's traffic go to these programs:
// an agent gets ones in folders only root can change, or a person's yes.
func openconnectCmd(cl *call, ctx context.Context, v *store.Vpn, protocol, pidFile string, port int, interactive bool) (*exec.Cmd, error) {
	var refs []string
	if !interactive && v.KeyRef != "" {
		refs = []string{v.KeyRef}
	}
	ocBin, err := localTool(cl, "openconnect", refs)
	if err != nil {
		return nil, err
	}
	proxyBin, err := localTool(cl, "ocproxy", refs)
	if err != nil {
		return nil, err
	}
	args := []string{"--protocol=" + protocol, "--background", "--pid-file=" + pidFile,
		"--script-tun", "--script", fmt.Sprintf("%s -D %d", sshx.Q(proxyBin), port)}
	if v.User != "" {
		args = append(args, "--user="+v.User)
	}
	if !interactive {
		args = append(args, "--non-inter", "--passwd-on-stdin")
	}
	return exec.CommandContext(ctx, ocBin, append(args, "--", v.Portal)...), nil
}
