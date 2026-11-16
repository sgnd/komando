package cli

import (
	"bufio"
	"crypto/hmac"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// komando's background commands (vpn serve, tunnel serve, login-holder)
// hold a VPN, a tunnel or a login for the command that started them,
// which already ran every check (a person for an --mfa VPN or a login, a
// protected server's yes) and wrote the audit record. Run by hand they
// would skip all of that: an AI agent would get a SOCKS port into a VPN
// `vpn up` refuses it, with no record. So each runs only with a ticket its
// parent sends first on its stdin: a random nonce, the time, and an HMAC
// of both and of the child's whole command line (flags too) under a key
// made from the store's master key. Only a process that can open the
// store makes one, and a ticket starts only the command it was made for.
// The nonce is also a file in komando's home that the child removes, so a
// ticket works once.

// ticketTTL is how long a ticket waits for its child.
const ticketTTL = 5 * time.Minute

// ticketLine is the ticket for the child whose words after the program are
// args, and leaves its nonce file.
func ticketLine(args []string) (string, error) {
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
	nonce, now := randToken(16), strconv.FormatInt(time.Now().Unix(), 10)
	mac, err := ticketMAC(nonce, now, args)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(store.Path("spawn", nonce), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	f.Close()
	return "TICKET " + nonce + " " + now + " " + hex.EncodeToString(mac) + "\n", nil
}

// sealTicket puts the ticket for c first on its stdin. Call it last, once
// c's arguments are final (after vault.PassOnStdin).
func sealTicket(c *exec.Cmd) error {
	line, err := ticketLine(c.Args[1:])
	if err != nil {
		return err
	}
	var in io.Reader = strings.NewReader(line)
	if c.Stdin != nil {
		in = io.MultiReader(in, c.Stdin)
	}
	c.Stdin = in
	return nil
}

func ticketMAC(nonce, when string, args []string) ([]byte, error) {
	return vault.TicketMAC([]byte("komando spawn v1\x00" + nonce + "\x00" + when + "\x00" + strings.Join(args, "\x00")))
}

// readTicket reads the ticket line, which checkTicket checks once the
// child can open the store (after the vault passphrase on stdin).
func readTicket(in *bufio.Reader) string {
	line, _ := in.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// checkTicket checks line against this process's own command line and
// uses the ticket up. Without a good one the child stops: what, started
// by `komando parent`, was run by hand.
func checkTicket(cl *call, line, what, parent string) error {
	byHand := out.Errf(out.ExitPolicy, "NEEDS_PERSON", "run `komando "+parent+"`: it checks and records what "+what+" does",
		"%s is started by `komando %s`, not by hand", what, parent).NoFlag()
	f := strings.Fields(line)
	if len(f) != 4 || f[0] != "TICKET" || len(f[1]) != 32 || strings.Trim(f[1], "0123456789abcdef") != "" {
		return byHand
	}
	sec, err := strconv.ParseInt(f[2], 10, 64)
	if age := time.Since(time.Unix(sec, 0)); err != nil || age > ticketTTL || age < -time.Minute {
		return byHand
	}
	got, err := hex.DecodeString(f[3])
	if err != nil {
		return byHand
	}
	want, err := ticketMAC(f[1], f[2], cl.args[1:])
	if err != nil || !hmac.Equal(got, want) {
		return byHand
	}
	if os.Remove(store.Path("spawn", f[1])) != nil { // one child per ticket
		return byHand
	}
	return nil
}
