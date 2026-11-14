package cli

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Login ask (`host add NAME ADDRESS --login ask`): the server's password is
// never stored. A person types it whenever komando connects, and it is
// used for that command only:
//
//   - a person at a terminal is asked there (hidden, like ssh);
//   - an app's call is asked in the app's window (engine.Call.AskPassword);
//   - an AI agent's call opens komando's own window, where the person types
//     it: the agent never sees it, and a person who cancels stops the
//     command (DECLINED), and the window stays shut for that server for a
//     minute (loginCoolDown), so an agent cannot ask again and again;
//   - a script, an agent with no screen and ssh-gate get NEEDS_PERSON;
//   - a held login (`komando login NAME`) is used first, without asking.
//
// The person's password goes to whatever answers at the server's address,
// so the address counts as a place a secret goes (hostPlace: an AI agent
// that changes it needs a person's yes), and a first connection, whose
// host key nobody has seen, goes on only with a person at the terminal or
// an app's window that warns them (loginNewKey).
//
// One command asks once per server, however many connections it opens
// (a fleet run, a jump host shared by several servers); a password the
// server refuses is forgotten, and the next connection asks again. The
// typed password is hidden in all output, never written to disk, the audit
// log or a child's environment. komando's own copy is zeroed when the
// command ends; copies the SSH library and Go's strings made cannot be
// zeroed and go when the process ends. A tunnel's background process
// keeps the password in memory for the tunnel's life (its reconnects).

// typedLogins are the passwords typed in one command, by server name.
type typedLogins struct {
	mu   sync.Mutex // held while a person is asked: one question at a time
	pw   map[string][]byte
	stop error // the person cancelled: later questions end the same way
	// background: the command runs in the background (tunnel serve) and
	// asks nobody; it has only what its starter passed on
	background bool
}

// reset forgets every typed password, its bytes zeroed.
func (t *typedLogins) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, b := range t.pw {
		clear(b)
		delete(t.pw, k)
	}
	t.stop, t.background = nil, false
}

// keep stores pw for name and returns what forgets it.
func (t *typedLogins) keep(name, pw string) func() {
	if t.pw == nil {
		t.pw = map[string][]byte{}
	}
	t.pw[name] = []byte(pw)
	return func() { t.forget(name) }
}

// forget drops name's password (the server refused it).
func (t *typedLogins) forget(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if b, ok := t.pw[name]; ok {
		clear(b)
		delete(t.pw, name)
	}
}

// terminalPerson is the question for the person at the terminal (or the
// person `komando login` relays to), or nil.
func terminalPerson() func(host, text string, hidden bool) (string, error) {
	if sshx.Asker == nil {
		return nil
	}
	return sshx.Asker()
}

// loginNewKey is sshx.AskLoginNewKey for this call: may the first
// connection to login-ask server h, whose host key k nobody has seen (or
// that is not checked), go on? A person at the terminal sees the key
// (komando prints it), and an app's window warns them; an AI agent's
// command, a script and a tunnel's background process get NEEDS_PERSON,
// and the key is not pinned, so an agent that sent the server somewhere
// new cannot get a person's password sent there.
func (cl *call) loginNewKey(h *store.Host, k sshx.NewHostKey) error {
	if terminalPerson() != nil {
		return nil
	}
	if !cl.logins.background && !cl.isAgent() && cl.io.AskPassword != nil {
		return nil // the window says it is a first connection
	}
	return sshx.AskLoginNewKeyNeedsPerson(h, k, cl.isAgent())
}

// loginPassword is sshx.LoginPassword for this call: the password typed
// for the server earlier in the command, or a person types it now.
func (cl *call) loginPassword(q sshx.LoginAsk) (string, func(), error) {
	h := q.Host
	t := &cl.logins
	t.mu.Lock()
	defer t.mu.Unlock()
	if q.NewKey != nil {
		// loginNewKey let the connection on; check again, as nothing may
		// send a password to a server nobody has seen for an agent
		if err := cl.loginNewKey(h, *q.NewKey); err != nil {
			return "", nil, err
		}
	}
	if b, ok := t.pw[h.Name]; ok {
		return string(b), func() { t.forget(h.Name) }, nil
	}
	if t.stop != nil {
		return "", nil, t.stop
	}
	if t.background {
		return "", nil, sshx.AskLoginNeedsPerson(h, cl.isAgent())
	}
	pw, err := cl.typeLoginPassword(q)
	if err != nil {
		var oe *out.Error
		if errors.As(err, &oe) && (oe.Code == "DECLINED" || oe.Code == "CANCELLED") {
			t.stop = err // one cancel ends the command's other questions too
		}
		return "", nil, err
	}
	hideTyped(pw)
	return pw, t.keep(h.Name, pw), nil
}

// hideTyped hides a typed password in the output of every running call,
// as values from the vault are (vault.OnResolve).
func hideTyped(pw string) {
	if pw == "" {
		return
	}
	for _, c := range runningCalls() {
		c.out.AddValue(pw)
	}
}

// typeLoginPassword asks the person for the server's password: at the
// terminal (or through `komando login`'s background process), in the
// app's window, or in komando's window for an AI agent.
func (cl *call) typeLoginPassword(q sshx.LoginAsk) (string, error) {
	h := q.Host
	if person := terminalPerson(); person != nil {
		return person(h.Name, "Password: ", true)
	}
	text := loginWindowText(cl, q)
	if cl.io.AskPassword != nil {
		pw, given, shown := cl.io.AskPassword(text)
		return windowAnswer(h, pw, given, shown, false, cl.isAgent())
	}
	if !cl.isAgent() || cl.getenv(engine.GateEnv) != "" {
		return "", sshx.AskLoginNeedsPerson(h, cl.isAgent())
	}
	if err := loginCoolingDown(h); err != nil {
		return "", err
	}
	pw, given, shown := askLoginOnScreen(cl, text)
	gaveUp := tookGaveUp(text)
	if shown && !given && !gaveUp {
		noteLoginDeclined(cl, sshx.LoginID(h))
	}
	return windowAnswer(h, pw, given, shown, gaveUp, true)
}

// declinedHint is the one next step after the person said no to, or did
// not answer, the password window: the same as AGENTS.md, the skill and
// the guide name.
func declinedHint(h *store.Host) string { return "do not retry: " + sshx.AskLoginStep(h, true) }

// windowAnswer is what a password window gave: the password, or why not.
func windowAnswer(h *store.Host, pw string, given, shown, gaveUp, agent bool) (string, error) {
	switch {
	case given:
		return pw, nil
	case !shown:
		return "", sshx.AskLoginNeedsPerson(h, agent)
	case gaveUp:
		return "", out.Errf(out.ExitPolicy, "NEEDS_PERSON", declinedHint(h),
			"%s logs in with a password a person types each time (login ask), and nobody answered the window within 2 minutes", h.Name).NoFlag()
	}
	return "", out.Errf(out.ExitPolicy, "DECLINED", declinedHint(h),
		"the user cancelled the password window: nothing was run on %s", h.Name).NoFlag()
}

// loginCoolDown is how long komando's password window stays shut for a
// server after the person cancelled it for an AI agent: an agent cannot
// wear the person down with one window after another.
const loginCoolDown = 60 * time.Second

// loginCoolingDown is DECLINED, without a window, while h's cool-down
// lasts.
func loginCoolingDown(h *store.Host) error {
	rt, err := store.ReadRuntime()
	if err != nil {
		return nil // no runtime file yet: nothing was declined
	}
	at, ok := rt.LoginDeclined[sshx.LoginID(h)]
	if since := time.Since(at); !ok || since >= loginCoolDown || since < 0 {
		return nil
	}
	return out.Errf(out.ExitPolicy, "DECLINED", declinedHint(h),
		"the user cancelled the password window of %s less than a minute ago; komando does not open it again before %s",
		h.Name, at.Add(loginCoolDown).Local().Format("15:04:05")).NoFlag()
}

// noteLoginDeclined starts the cool-down of the server known as id
// (sshx.LoginID: a rename does not end it). It is kept with the running
// logins (runtime.json), so the next command sees it too.
func noteLoginDeclined(cl *call, id string) {
	_ = store.UpdateRuntime(cl.storeWrite(), func(s *store.State) error {
		if s.LoginDeclined == nil {
			s.LoginDeclined = map[string]time.Time{}
		}
		for n, at := range s.LoginDeclined {
			if time.Since(at) >= loginCoolDown {
				delete(s.LoginDeclined, n)
			}
		}
		s.LoginDeclined[id] = time.Now().UTC()
		return nil
	})
}

// loginWindowText is what the password window says: who asks, for which
// server, user, address and command, whether this is a first connection,
// and that the password stays with komando.
func loginWindowText(cl *call, q sshx.LoginAsk) string {
	h := q.Host
	who := cl.caller().Agent
	if who == "" {
		who = "A komando command"
	}
	name := cleanText(h.Name)
	where := cleanText(q.User) + "@" + cleanText(q.Addr)
	if q.Path != "" {
		where += ", reached through " + cleanText(q.Path)
	}
	text := fmt.Sprintf("%s wants komando to log in to %s as %s", who, name, where)
	if line := commandLine(cl); len(cl.args) > 1 && unshowable(line) == "" && hiddenArgs(cl.args[1:]) == "" {
		text += " for:\n\n" + line + "\n\n"
	} else {
		text += ". The command is hidden here: it has text this window cannot show.\n\n"
	}
	if k := q.NewKey; k != nil {
		if k.NotMet {
			text += "WARNING: first login to " + name + " at " + cleanText(q.Addr) + " with a typed password. Its host key " + cleanText(k.Fingerprint) +
				" was pinned before, but nobody has logged in to " + name + " with it. Type the password only if you expected " + name + " there.\n\n"
		} else if k.Unchecked {
			text += "WARNING: komando does not check who answers at " + cleanText(q.Addr) + " (" + cleanText(k.Type) + "): an impostor there would get your password.\n\n"
		} else {
			text += "WARNING: first connection to " + cleanText(q.Addr) + ". komando trusted its host key " + cleanText(k.Fingerprint) +
				" a moment ago, and nothing proved it is " + name + "'s. Type the password only if you expected a new server there.\n\n"
		}
	}
	text += name + " logs in with a password you type each time; komando never stores it"
	if cl.isAgent() {
		text += ", and the agent never sees it"
	}
	return text + ". Every command that connects asks, even one that only looks (komando test, komando fs ls).\n\n" +
		"Type the password of " + name + " to log in for this command only:"
}

// askLoginOnScreen shows komando's window with a hidden field for the
// password. It returns what was typed, whether the person pressed "Log
// in", and whether a window could be shown at all. Tests set another.
var askLoginOnScreen = func(cl *call, text string) (pw string, given, shown bool) {
	if cl.getenv("KOMANDO_NO_DIALOG") != "" || cl.getenv("SSH_CONNECTION") != "" || cl.getenv("SSH_TTY") != "" {
		return "", false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	switch runtime.GOOS {
	case "darwin":
		const script = `on run argv
set r to display dialog (item 1 of argv) with title "komando: password" default answer "" with hidden answer buttons {"Cancel", "Log in"} default button "Log in" cancel button "Cancel" giving up after 120 with icon caution
if gave up of r then return "gave up"
return (button returned of r) & linefeed & (text returned of r)
end run`
		b, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script, text).Output()
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			return "", false, false
		}
		btn, typed, _ := strings.Cut(strings.TrimSuffix(string(b), "\n"), "\n")
		noteGaveUp(text, btn == "gave up")
		return typed, btn == "Log in", true
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
		if cl.getenv("DISPLAY") == "" && cl.getenv("WAYLAND_DISPLAY") == "" {
			return "", false, false
		}
		if z := systemTool("zenity"); z != "" {
			b, err := exec.CommandContext(ctx, z, "--entry", "--hide-text", "--title=komando: password", "--text="+text, "--ok-label=Log in", "--cancel-label=Cancel", "--no-markup", "--timeout=120").Output()
			noteGaveUp(text, zenityTimedOut(err))
			return strings.TrimSuffix(string(b), "\n"), err == nil, true
		}
		if k := systemTool("kdialog"); k != "" {
			b, err := exec.CommandContext(ctx, k, "--title", "komando: password", "--password", text).Output()
			return strings.TrimSuffix(string(b), "\n"), err == nil, true
		}
	case "windows":
		pw, given, gaveUp, shown := approvalWindow(text, true)
		noteGaveUp(text, gaveUp)
		return pw, given, shown
	}
	return "", false, false
}

// Tunnels run in a background process (tunnel serve), which asks nobody:
// tunnel start asks for the passwords of the login-ask servers on the
// path now and hands them to it on its input, never in its arguments or
// environment. The background process keeps them in memory for its
// reconnects, as `komando login` keeps a login.

// loginsStdinFlag makes tunnel serve read the passwords first on stdin.
const loginsStdinFlag = "--logins-stdin"

// pathLogins asks for the passwords of the login-ask servers on the way to
// h (h included) that no held login covers. They are kept in the call, so
// the command's own connection uses them too. The background process
// cannot show a new host key to anyone, so each of those servers must be
// one komando has met (its key pinned, and checked).
func pathLogins(cl *call, st *store.State, h *store.Host) (map[string]string, error) {
	got := map[string]string{}
	policy := sshOpts(cl, st).HostKeyPolicy
	for _, hop := range sshx.AskHops(st, h) {
		q := sshx.LoginAskFor(st, hop)
		met, err := sshx.LoginMet(hop, q.Addr)
		if err != nil {
			return nil, err
		}
		if !met || policy == "off" {
			k := sshx.NewHostKey{Host: hop.Name, Address: q.Addr, Unchecked: policy == "off", NotMet: policy != "off"}
			return nil, sshx.AskLoginNewKeyNeedsPerson(hop, k, cl.isAgent())
		}
		pw, _, err := cl.loginPassword(q)
		if err != nil {
			return nil, err
		}
		got[hop.Name] = pw
	}
	return got, nil
}

// loginsInput is what pathLogins gave, as tunnel serve reads it.
func loginsInput(logins map[string]string) io.Reader {
	var sb strings.Builder
	for name, pw := range logins {
		sb.WriteString("LOGIN " + base64.StdEncoding.EncodeToString([]byte(name)) + " " + base64.StdEncoding.EncodeToString([]byte(pw)) + "\n")
	}
	sb.WriteString("END\n")
	return strings.NewReader(sb.String())
}

// readLogins reads loginsInput's lines from in into the call; what follows
// them (the vault passphrase) stays in in.
func readLogins(cl *call, in *bufio.Reader) error {
	t := &cl.logins
	for range 1000 {
		line, err := in.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading the typed passwords from stdin: %w", err)
		}
		word, rest, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		if word == "END" {
			return nil
		}
		n, p, _ := strings.Cut(rest, " ")
		name, err1 := base64.StdEncoding.DecodeString(n)
		pw, err2 := base64.StdEncoding.DecodeString(p)
		if word != "LOGIN" || err1 != nil || err2 != nil {
			return errors.New("tunnel serve is started by `komando tunnel start`, not by hand")
		}
		hideTyped(string(pw))
		t.mu.Lock()
		t.keep(string(name), string(pw))
		t.mu.Unlock()
		clear(pw)
	}
	return errors.New("too many typed passwords on stdin")
}
