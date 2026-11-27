package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// runBackground runs one of komando's background commands in this
// process with stdin, for at most a few seconds, and returns its output.
func runBackground(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	closeStoreAtEnd(t)
	root := newRoot(tcl)
	t.Cleanup(endCommand)
	root.SetArgs(args)
	var buf bytes.Buffer
	savedW, savedIn := tcl.out.W, tcl.stdin
	tcl.out.W, tcl.stdin = &buf, strings.NewReader(stdin)
	defer func() { tcl.out.W, tcl.stdin = savedW, savedIn }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = root.ExecuteContextC(ctx)
	return buf.String()
}

// The background commands hold what their parent command checked and
// recorded. Run by hand, by an agent above all, they would skip the
// person gate of an --mfa VPN or a login and the audit record: they stop
// unless their parent's ticket comes first on stdin.
func TestBackgroundCommandsNeedTheirParent(t *testing.T) {
	invHome(t)
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	mustRun(t, "vpn", "socks", "add", "office", "--proxy-address", "127.0.0.1:1", "--mfa")
	mustRun(t, "host", "ssh", "add", "web1", "u@127.0.0.1:1")
	for _, c := range [][]string{
		{"vpn", "serve", "office", "--password-stdin"},
		{"tunnel", "serve", "t-1"},
		{"login-holder", "web1"},
	} {
		for _, stdin := range []string{"", "SOCKS u p\n\n", "TICKET " + strings.Repeat("a", 32) + "\n", "TICKET ../../store\n"} {
			got := runBackground(t, stdin, c...)
			if strings.Contains(got, "READY") || !strings.Contains(got, "not by hand") {
				t.Fatalf("%v with stdin %q: %q", c, stdin, got)
			}
		}
	}
}

// A ticket works once, for a while, only for the command line it was
// made for (flags too), and only if made with the store's key: a file
// any program of the user can write in komando's home is not one.
func TestSpawnTicket(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "socks", "add", "x", "--proxy-address", "127.0.0.1:1") // the store the ticket's key comes from
	saved := tcl.args
	t.Cleanup(func() { tcl.args = saved })
	cmd := []string{"vpn", "serve", "x", "--password-stdin"}
	tcl.args = append([]string{"komando"}, cmd...)
	check := func(line string) error {
		return checkTicket(tcl, strings.TrimRight(line, "\n"), "vpn serve", "vpn socks start x")
	}
	line, err := ticketLine(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := check(line); err != nil {
		t.Fatalf("the ticket: %v", err)
	}
	if check(line) == nil {
		t.Fatal("a ticket worked twice")
	}
	// made for other words, or for the same words with other flags
	for _, other := range [][]string{{"vpn", "serve", "y", "--password-stdin"}, {"vpn", "serve", "x"}} {
		l, _ := ticketLine(other)
		if check(l) == nil {
			t.Fatalf("a ticket for %v started %v", other, cmd)
		}
	}
	// forged: a nonce file and a line written by hand, without the key
	nonce := strings.Repeat("ab", 16)
	os.WriteFile(store.Path("spawn", nonce), []byte("vpn serve x"), 0o600)
	now := strconv.FormatInt(time.Now().Unix(), 10)
	for _, forged := range []string{"TICKET " + nonce, "TICKET " + nonce + " " + now + " " + strings.Repeat("00", 32)} {
		if check(forged) == nil {
			t.Fatalf("a forged ticket worked: %q", forged)
		}
	}
	// an old ticket
	old, _ := ticketLine(cmd)
	of := strings.Fields(old)
	stale := strconv.FormatInt(time.Now().Add(-2*ticketTTL).Unix(), 10)
	mac, _ := ticketMAC(of[1], stale, cmd)
	if check("TICKET "+of[1]+" "+stale+" "+hex.EncodeToString(mac)) == nil {
		t.Fatal("an old ticket worked")
	}
}
