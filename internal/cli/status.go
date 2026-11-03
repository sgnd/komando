package cli

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"golang.org/x/term"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Session status lines tell a person at the terminal where they are typing
// (docs/design/session-status.md). They go to stderr, only when a person is
// at the terminal, so agents, pipes and JSON output see nothing new.

// statusLine is one line: komando: WHAT on TARGET (DETAIL) via ROUTE · PROTECTED (TAIL)
type statusLine struct {
	What, Target, Detail string
	Route                []string // VPN first, then bastions; nil when direct
	Protected            bool
	Tail                 string // e.g. "Ctrl-C stops"
}

func (s statusLine) format(color bool) string {
	var b strings.Builder
	b.WriteString("komando: " + cleanText(s.What) + " on " + cleanText(s.Target))
	if s.Detail != "" {
		b.WriteString(" (" + cleanText(s.Detail) + ")")
	}
	if len(s.Route) > 0 {
		parts := make([]string, len(s.Route))
		for i, r := range s.Route {
			parts[i] = cleanText(r)
		}
		b.WriteString(" via " + strings.Join(parts, " → "))
	}
	if s.Protected {
		if color {
			b.WriteString(" · \x1b[1;31mPROTECTED\x1b[0m")
		} else {
			b.WriteString(" · PROTECTED")
		}
	}
	if s.Tail != "" {
		b.WriteString(" (" + cleanText(s.Tail) + ")")
	}
	return b.String()
}

// showStatus prints the line for a person at the terminal, and nothing for
// agents and scripts.
func showStatus(s statusLine) {
	if interactive() {
		fmt.Fprintln(os.Stderr, s.format(colorOK()))
	}
}

// noticef prints one komando: line for a person at the terminal.
func noticef(format string, args ...any) {
	if interactive() {
		fmt.Fprintln(os.Stderr, "komando: "+cleanText(fmt.Sprintf(format, args...)))
	}
}

// exitLine is the line after an interactive session: how it ended and how
// long it took. lost is a connection that ended without an exit status.
func exitLine(target string, code int, lost bool, took time.Duration) string {
	d := humanAge(took)
	if lost {
		return "komando: connection to " + cleanText(target) + " lost after " + d
	}
	return fmt.Sprintf("komando: left %s (exit %d, %s)", cleanText(target), code, d)
}

func showExit(target string, code int, lost bool, took time.Duration) {
	if interactive() {
		fmt.Fprintln(os.Stderr, exitLine(target, code, lost, took))
	}
}

// colorOK: stderr is a terminal and the person did not turn colour off.
var colorOK = func() bool {
	return os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(os.Stderr.Fd()))
}

// cleanText drops control and bidi characters, so a name or address cannot
// move the cursor, retitle the window or reorder what the line says.
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return -1
		}
		return r
	}, s)
}

// hostRoute is the way to h for a status line: "vpn NAME" first, then the
// bastions. It reads the inventory only. A broken path shows as written;
// connecting reports the real error.
func hostRoute(st *store.State, h *store.Host) []string {
	vpn, hops, err := sshx.Route(st, h)
	if err != nil {
		return viaChain(h.Via)
	}
	var r []string
	if vpn != nil {
		r = append(r, "vpn "+vpn.Name)
	}
	for _, hop := range hops[:len(hops)-1] {
		r = append(r, hop.Name)
	}
	return r
}

// connRoute is hostRoute for a conn's --via path.
func connRoute(st *store.State, c *store.Conn) []string {
	if c.Via == "" {
		return nil
	}
	h, vpn, err := resolveVia(st, c.Via)
	switch {
	case err != nil:
		return viaChain(c.Via)
	case vpn != nil:
		return []string{"vpn " + vpn.Name}
	}
	return append(hostRoute(st, h), h.Name)
}
