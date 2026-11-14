package cli

import (
	"bufio"
	"bytes"
	"context"
	"os"
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
	mustRun(t, "vpn", "add", "office", "socks", "--proxy-address", "127.0.0.1:1", "--mfa")
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:1")
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

// A ticket works once, for a while, and only as a file komando made.
func TestSpawnTicket(t *testing.T) {
	invHome(t)
	line, err := newSpawnTicket()
	if err != nil {
		t.Fatal(err)
	}
	take := func(l string) error {
		return takeSpawnTicket(bufio.NewReader(strings.NewReader(l)), "vpn serve", "vpn up x")
	}
	if err := take(line); err != nil {
		t.Fatalf("the ticket: %v", err)
	}
	if take(line) == nil {
		t.Fatal("a ticket worked twice")
	}
	old, _ := newSpawnTicket()
	name := strings.TrimSpace(strings.TrimPrefix(old, "TICKET "))
	past := time.Now().Add(-2 * ticketTTL)
	os.Chtimes(store.Path("spawn", name), past, past)
	if take(old) == nil {
		t.Fatal("an old ticket worked")
	}
	fresh, _ := newSpawnTicket()
	name = strings.TrimSpace(strings.TrimPrefix(fresh, "TICKET "))
	os.Remove(store.Path("spawn", name))
	os.Mkdir(store.Path("spawn", name), 0o700)
	if take(fresh) == nil {
		t.Fatal("a folder worked as a ticket")
	}
}
