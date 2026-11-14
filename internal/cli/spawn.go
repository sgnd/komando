package cli

import (
	"bufio"
	"os"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// komando's background commands (vpn serve, tunnel serve, login-holder)
// hold a VPN, a tunnel or a login for the command that started them,
// which already ran every check (a person for an --mfa VPN or a login, a
// protected server's yes) and wrote the audit record. Run by hand they
// would skip all of that: an AI agent would get a SOCKS port into a VPN
// `vpn up` refuses it, with no record. So each runs only with a ticket:
// a random name its parent leaves in komando's home, which agents may not
// read, and sends first on the child's stdin. The ticket holds the
// child's command line, so one taken on the way starts only what the
// parent was starting. The child uses it up as it starts.

// ticketTTL is how long a ticket waits for its child.
const ticketTTL = 5 * time.Minute

// newSpawnTicket leaves a ticket for one background command, the words
// of args (`vpn serve NAME`), and returns the line to send first on its
// stdin.
func newSpawnTicket(args ...string) (string, error) {
	if err := store.MkdirPrivate("spawn"); err != nil {
		return "", err
	}
	if old, err := os.ReadDir(store.Path("spawn")); err == nil {
		for _, e := range old { // tickets of children that never started
			if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > ticketTTL {
				_ = os.Remove(store.Path("spawn", e.Name()))
			}
		}
	}
	t := randToken(16)
	f, err := os.OpenFile(store.Path("spawn", t), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(strings.Join(args, " "))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	return "TICKET " + t + "\n", nil
}

// takeSpawnTicket reads the ticket line from in and uses the ticket up. A
// child without a fresh ticket of its parent for its own command line
// (args) stops: what, started by `komando parent`, was run by hand.
func takeSpawnTicket(in *bufio.Reader, args []string, what, parent string) error {
	byHand := out.Errf(out.ExitPolicy, "NEEDS_PERSON", "run `komando "+parent+"`: it checks and records what "+what+" does",
		"%s is started by `komando %s`, not by hand", what, parent).NoFlag()
	line, _ := in.ReadString('\n')
	word, t, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
	if word != "TICKET" || len(t) != 32 || strings.Trim(t, "0123456789abcdef") != "" {
		return byHand
	}
	p := store.Path("spawn", t)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return byHand
	}
	b, err := os.ReadFile(p)
	if err != nil || os.Remove(p) != nil || time.Since(fi.ModTime()) > ticketTTL { // one child per ticket
		return byHand
	}
	if string(b) != strings.Join(args, " ") {
		return byHand
	}
	return nil
}
