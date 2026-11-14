package cli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// komando login HOST: a person logs in to a server once, answering what
// it asks (the password, a two-factor code), and a background komando
// process keeps that login for the login_for setting (8h). Later commands
// reach the server through it, an AI agent's too, without a person; every
// other check (rules, approvals, audit) still runs in those commands.
// `komando logout SERVER` ends it sooner. See sshx/held.go.

// loginHost runs `komando login SERVER`.
func loginHost(cl *call, ctx context.Context, name string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	h, err := findHost(cl, st, name)
	if err != nil {
		return err
	}
	needsPerson := out.Errf(out.ExitUsage, "NEEDS_TERMINAL", "ask a person to run `komando login "+h.Name+"` in a terminal; after that your commands to "+h.Name+" need no login",
		"logging in to %s needs a person at a terminal to answer its questions", h.Name).NoFlag()
	if !cl.interactive() && !cl.flags.dryRun {
		return needsPerson
	}
	keep, _ := time.ParseDuration(st.Settings.LoginFor)
	if keep <= 0 {
		keep = 8 * time.Hour
	}
	if l := sshx.HeldFor(st, h); l != nil && heldAlive(l) {
		cl.out.Print("login.host", loginResult{Host: h.Name, Until: l.Until, Already: true}, nil)
		return nil
	}
	if cl.flags.dryRun { // never blocked: what the real run would need is in would_be_blocked
		res := map[string]any{"host": h.Name, "would_log_in": true, "keeps_it_for": keep.String()}
		if !cl.interactive() {
			res["would_log_in"] = false
			cl.out.WouldBlock(needsPerson)
		}
		cl.out.Print("login.host", res, nil)
		return nil
	}
	endLogin(st.Logins[h.Name]) // an old one (expired, or for an older address)
	l, err := startHolder(cl, h, keep)
	if err != nil {
		return err
	}
	if err := store.UpdateRuntime(cl.storeWrite(), func(s *store.State) error { s.Logins[h.Name] = l; return nil }); err != nil {
		endLogin(l)
		return err
	}
	audit(cl, st, "login.host", []string{h.Name}, "", true, map[string]any{"until": l.Until})
	cl.out.Print("login.host", loginResult{Host: h.Name, Until: l.Until}, nil)
	return nil
}

type loginResult struct {
	Host    string    `json:"host"`
	Until   time.Time `json:"until"`
	Already bool      `json:"already_logged_in,omitempty"`
}

func (r loginResult) Text() string {
	left := humanAge(time.Until(r.Until))
	if r.Already {
		return fmt.Sprintf("already logged in to %s for %s more; `komando logout %s` ends it\n", cleanText(r.Host), left, cleanText(r.Host))
	}
	return fmt.Sprintf("logged in to %s; commands to it (an AI agent's too) use this login for %s, or until `komando logout %s`\n", cleanText(r.Host), left, cleanText(r.Host))
}

// heldAlive reports whether l's process still runs.
func heldAlive(l *store.SSHLogin) bool {
	return l != nil && netx.SessionAlive(&store.VpnSession{PID: l.PID, Exe: l.Exe})
}

// endLogin stops l's process and removes its socket. It keeps the record:
// the caller removes or replaces it.
func endLogin(l *store.SSHLogin) {
	if l == nil {
		return
	}
	if heldAlive(l) {
		_ = netx.Terminate(l.PID)
	}
	if l.Socket != "" {
		_ = os.Remove(l.Socket)
	}
}

// startHolder starts `komando login-holder NAME` and relays its login's
// questions to the person here until it says READY (or why not).
func startHolder(cl *call, h *store.Host, keep time.Duration) (*store.SSHLogin, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	dir := store.Path("login")
	if err := store.MkdirPrivate("login"); err != nil {
		return nil, err
	}
	if cur, err := store.Load(); err == nil {
		sweepLogs("login", liveLogs(cur)) // logs of logins (some since removed) unused for a week
	}
	logFile := filepath.Join(dir, safeFileName(h.Name)+".log")
	lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer lf.Close()
	l := &store.SSHLogin{Host: h.Name, Target: sshx.TargetOf(h), Token: randToken(24), LogFile: logFile,
		StartedAt: time.Now().UTC(), Until: time.Now().Add(keep).UTC()}
	c := holderCommand(self, h.Name)
	if c.Env == nil { // a test's holderCommand sets its own
		c.Env = cl.environ() // the call's, unlock values out; never nil (nil inherits the process's)
	}
	c.Stderr = lf
	c.SysProcAttr = detachAttr() // it outlives this command and its terminal
	stdin, err := c.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	l.PID = c.Process.Pid
	l.Exe = filepath.Base(self)
	fail := func(e error) (*store.SSHLogin, error) {
		_ = c.Process.Kill()
		_ = c.Wait()
		return nil, e
	}
	// the token, how long to keep the login, the vault passphrase and the
	// other secret stores' unlock values go on its input, never in its
	// arguments or environment
	fmt.Fprintf(stdin, "TOKEN %s\nUNTIL %d\nPASS %s\n", l.Token, l.Until.Unix(), base64.StdEncoding.EncodeToString([]byte(vault.Handoff())))
	var cancelled error
	in := bufio.NewReader(stdout)
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			if cancelled != nil {
				return fail(cancelled)
			}
			why := "it stopped"
			if werr := c.Wait(); werr != nil {
				why = werr.Error()
			}
			if b, _ := os.ReadFile(logFile); len(strings.TrimSpace(string(b))) > 0 {
				why += ": " + finalLine(string(b))
			}
			return nil, out.Errf(out.ExitConnect, "LOGIN_FAILED", "the whole log is "+logFile+" (for a person to read)",
				"the login to %s ended early (%s)", h.Name, why)
		}
		word, rest, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		switch word {
		case "ASK":
			host, rest, _ := strings.Cut(rest, " ")
			hidden, b64, _ := strings.Cut(rest, " ")
			text, _ := base64.StdEncoding.DecodeString(b64)
			hb, _ := base64.StdEncoding.DecodeString(host)
			a, err := askSSH(cl, string(hb), string(text), hidden == "1")
			if err != nil {
				cancelled = err
				fmt.Fprintln(stdin, "CANCEL")
				continue
			}
			fmt.Fprintln(stdin, "ANS "+base64.StdEncoding.EncodeToString([]byte(a)))
		case "READY":
			sock, key, _ := strings.Cut(rest, " ")
			kb, _ := base64.StdEncoding.DecodeString(key)
			l.Socket, l.HostKey = sock, string(kb)
			_ = stdin.Close()
			_ = c.Process.Release()
			return l, nil
		case "ERROR":
			var e holderError
			if json.Unmarshal([]byte(rest), &e) != nil || e.Code == "" {
				return fail(out.Errf(out.ExitConnect, "LOGIN_FAILED", "the whole log is "+logFile, "the login to %s failed: %s", h.Name, cleanText(rest)))
			}
			if cancelled != nil {
				return fail(cancelled)
			}
			return fail(&out.Error{Code: e.Code, Message: e.Message, Hint: e.Hint, Exit: e.Exit, Final: e.Final})
		}
	}
}

// holderCommand is the background process for a login to name; tests
// run it in their own binary.
var holderCommand = func(self, name string) *exec.Cmd {
	return exec.Command(self, "login-holder", name)
}

type holderError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Exit    int    `json:"exit"`
	Final   bool   `json:"final,omitempty"`
}

func finalLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return cleanText(lines[len(lines)-1])
}

// safeFileName is name with only letters, digits, dot, dash and underscore.
func safeFileName(name string) string {
	return strings.Map(func(r rune) rune {
		if r < 128 && (r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return r
		}
		return '_'
	}, name)
}

// loginHolderCmd is the background process of `komando login SERVER`: it
// logs in (its questions go to the person through `login` on its output)
// and then serves the login on a Unix socket until the login_for time, a
// `komando logout`, or the server closing the connection.
func loginHolderCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "login-holder NAME",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			signal.Ignore(syscall.SIGPIPE, syscall.SIGHUP) // `login` exits once it is up
			var outMu sync.Mutex
			say := func(s string) { outMu.Lock(); fmt.Fprintln(cl.out.W, s); outMu.Unlock() }
			fail := func(err error) error {
				e := holderError{Code: "LOGIN_FAILED", Message: err.Error(), Exit: out.ExitConnect}
				var oe *out.Error
				if errors.As(err, &oe) {
					e = holderError{Code: oe.Code, Message: oe.Message, Hint: oe.Hint, Exit: oe.Exit, Final: oe.Final}
				}
				b, _ := json.Marshal(e)
				fmt.Fprintf(cl.out.Err, "%s ERROR %s\n", time.Now().Format("2006/01/02 15:04:05"), e.Message)
				say("ERROR " + string(b))
				return exitCode(1)
			}
			in := bufio.NewReader(cl.stdin)
			token, until, err := holderStdin(in)
			if err != nil {
				return fail(err)
			}
			st, err := loadState()
			if err != nil {
				return fail(err)
			}
			h, err := findHost(cl, st, args[0])
			if err != nil {
				return fail(err)
			}
			relay := relayAsk(in, say)
			sshx.Asker = func() func(host, text string, hidden bool) (string, error) { return relay }
			ctx := cmd.Context()
			o := sshOpts(cl, st)
			o.Fresh = true
			c, err := sshx.Dial(ctx, st, h, o)
			sshx.Asker = nil // logged in: nobody is asked again
			if err != nil {
				return fail(err)
			}
			defer c.Close()
			ln, sock, signer, err := heldSocket()
			if err != nil {
				return fail(err)
			}
			defer os.Remove(sock)
			say("READY " + sock + " " + base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(signer.PublicKey())))
			cl.out.W = cl.out.Err // `login` stops reading now
			started := time.Now()
			fmt.Fprintf(cl.out.Err, "%s READY logged in to %s until %s\n", started.Format("2006/01/02 15:04:05"), h.Name, until.Local().Format("15:04"))
			go sshx.ServeHeld(ln, c.Client, token, signer, nil)
			why := holdUntil(ctx, c, until)
			ln.Close()
			fmt.Fprintf(cl.out.Err, "%s ENDED %s (after %s)\n", time.Now().Format("2006/01/02 15:04:05"), why, time.Since(started).Round(time.Second))
			_ = store.UpdateRuntime(cl.storeWrite(), func(s *store.State) error {
				if x := s.Logins[h.Name]; x != nil && x.PID == os.Getpid() { // not a newer login's record
					delete(s.Logins, h.Name)
				}
				return nil
			})
			return nil
		}),
	}
}

// relayAsk is the question sshx.Asker gives in the holder: each question goes to `login` on
// the output, and its answer comes back on the input. After a cancel every
// later question ends the same way.
func relayAsk(in *bufio.Reader, say func(string)) func(host, text string, hidden bool) (string, error) {
	var mu sync.Mutex
	var stop error
	return func(host, text string, hidden bool) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if stop != nil {
			return "", stop
		}
		hb := "0"
		if hidden {
			hb = "1"
		}
		say("ASK " + base64.StdEncoding.EncodeToString([]byte(host)) + " " + hb + " " + base64.StdEncoding.EncodeToString([]byte(text)))
		line, err := in.ReadString('\n')
		word, rest, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		if err != nil || word != "ANS" {
			stop = (&out.Error{Code: "CANCELLED", Message: "interrupted", Exit: out.ExitError}).Say("Stopped (Ctrl-C); the login was not kept", "")
			return "", stop
		}
		a, err := base64.StdEncoding.DecodeString(rest)
		return string(a), err
	}
}

// heldSocket opens the login's Unix socket (only this user can open it)
// and makes its random key.
func heldSocket() (net.Listener, string, ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", nil, err
	}
	// a short random name: a Unix socket path has a small limit (104 bytes on macOS)
	sock := filepath.Join(store.Path("login"), randToken(6)+".sock")
	if len(sock) > 100 { // a long data folder: the system's temp folder (it is 0600 and needs the token all the same)
		sock = filepath.Join(os.TempDir(), "komando-"+randToken(6)+".sock")
	}
	_ = os.Remove(sock)
	var ln net.Listener
	withUmask(0o077, func() { ln, err = net.Listen("unix", sock) })
	if err != nil {
		return nil, "", nil, err
	}
	_ = os.Chmod(sock, 0o600)
	return ln, sock, signer, nil
}

// holdUntil waits until the login ends and says why: its time is up, a
// logout stopped it, or the server closed the connection.
func holdUntil(ctx context.Context, c *sshx.Client, until time.Time) string {
	ended := make(chan error, 1)
	go func() { ended <- c.Wait() }()
	select {
	case <-time.After(time.Until(until)):
		return "login_for time is up"
	case <-ctx.Done():
		return "stopped (komando logout)"
	case err := <-ended:
		if err != nil {
			return "the server closed the connection: " + err.Error()
		}
		return "the server closed the connection"
	}
}

// holderStdin reads what startHolder sends first: the socket's token, the
// end time and the vault passphrase.
func holderStdin(in *bufio.Reader) (token string, until time.Time, err error) {
	for _, want := range []string{"TOKEN", "UNTIL", "PASS"} {
		line, rerr := in.ReadString('\n')
		word, rest, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		if rerr != nil || word != want {
			return "", time.Time{}, fmt.Errorf("login-holder is started by `komando login`, not by hand")
		}
		switch want {
		case "TOKEN":
			token = rest
		case "UNTIL":
			var sec int64
			if _, err := fmt.Sscan(rest, &sec); err != nil {
				return "", time.Time{}, err
			}
			until = time.Unix(sec, 0)
		case "PASS":
			p, err := base64.StdEncoding.DecodeString(rest)
			if err != nil {
				return "", time.Time{}, err
			}
			if len(p) > 0 {
				if err := vault.ReadPassStdin(strings.NewReader(string(p))); err != nil {
					return "", time.Time{}, err
				}
			}
		}
	}
	if len(token) < 32 {
		return "", time.Time{}, errors.New("no login token")
	}
	return token, until, nil
}

func logoutCmd(cl *call) *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:   "logout [SERVER...]",
		Args:  cobra.ArbitraryArgs, // server names; `aws` is the subcommand
		Short: "End server logins kept by `komando login` (--all for every one)",
		Long: `Ends what ` + "`komando login SERVER`" + ` keeps: the connection closes, and later
commands to that server log in again (a two-factor server asks a person).
` + "`komando status`" + ` lists the logins that are kept. ` + "`komando logout aws`" + ` ends an
AWS IAM Identity Center (SSO) login.`,
		Example: `  komando logout web1
  komando logout --all
  komando logout aws --profile prod`,
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			names := args
			switch {
			case all && len(names) > 0:
				return out.Errf(out.ExitUsage, "USAGE", "use `komando logout --all` or `komando logout "+strings.Join(names, " ")+"`", "--all logs out of every server; give names or --all, not both")
			case all:
				names = mapKeys(st.Logins)
			case len(names) == 0:
				return out.Usage("give the server names to log out of, or --all")
			}
			for _, n := range names {
				// a login of a server removed since still ends
				if _, err := findHost(cl, st, n); err != nil && st.Logins[n] == nil {
					return err
				}
			}
			if cl.flags.dryRun {
				cl.out.Print("logout", map[string]any{"would_log_out": names}, nil)
				return nil
			}
			done, none := []string{}, []string{}
			for _, n := range names {
				l := st.Logins[n]
				if l == nil {
					if h, err := findHost(cl, st, n); err == nil && st.Logins[h.Name] != nil {
						n, l = h.Name, st.Logins[h.Name]
					}
				}
				if l == nil || !heldAlive(l) {
					none = append(none, n)
				} else {
					done = append(done, n)
				}
				endLogin(l)
			}
			if err := store.UpdateRuntime(cl.storeWrite(), func(s *store.State) error {
				for _, n := range append(append([]string{}, done...), none...) {
					delete(s.Logins, n)
				}
				return nil
			}); err != nil {
				return err
			}
			if len(done) > 0 {
				audit(cl, st, "logout", done, "", true, nil)
			}
			cl.out.Print("logout", logoutData{LoggedOut: done, NotLoggedIn: none}, nil)
			return nil
		}),
	}
	c.Flags().BoolVar(&all, "all", false, "end every kept server login")
	c.AddCommand(logoutAWSCmd(cl))
	return c
}

type logoutData struct {
	LoggedOut   []string `json:"logged_out"`
	NotLoggedIn []string `json:"not_logged_in,omitempty"`
}

func (d logoutData) Text() string {
	var sb strings.Builder
	for _, n := range d.LoggedOut {
		sb.WriteString("logged out of " + cleanText(n) + "\n")
	}
	for _, n := range d.NotLoggedIn {
		sb.WriteString(cleanText(n) + " was not logged in\n")
	}
	if sb.Len() == 0 {
		sb.WriteString("no kept logins, so nothing to end (`komando status` lists them)\n")
	}
	return sb.String()
}
