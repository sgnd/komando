package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The lists a question picks from (servers, conns, VPNs, each with a short
// detail), and how komando shows and runs a command line it built. They
// were the menu's; the questions of a typed command use them now.

// menuRow is one line a person can choose.
type menuRow struct {
	label, detail string
	value         string // what choosing it gives back (an action or a name)
}

// menuNames is the names a list may offer, sorted. A name the inventory
// would not accept today (a hand-edited state file, or "all" from before it
// was refused) is left out: the menu passes the name as an argument, where
// one starting with - would be read as a flag and "all" would pick
// everything.
func menuNames[T any](m map[string]T, kind string) []string {
	var names []string
	for n := range m {
		if validName(kind, n) == nil {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names
}

func menuHostRows(st *store.State) []menuRow {
	var rows []menuRow
	for _, n := range menuNames(st.Hosts, "host") {
		rows = append(rows, menuRow{label: n, detail: menuHostDetail(st, st.Hosts[n]), value: n})
	}
	return rows
}

// menuConnRows is the conns of one family ("db"), or all with "".
func menuConnRows(st *store.State, family string) []menuRow {
	var rows []menuRow
	for _, n := range menuNames(st.Conns, "conn") {
		c := st.Conns[n]
		if family != "" && connFamily(c) != family {
			continue
		}
		rows = append(rows, menuRow{label: n, detail: menuConnDetail(st, c), value: n})
	}
	return rows
}

func menuVpnRows(st *store.State) []menuRow {
	var rows []menuRow
	for _, n := range menuNames(st.Vpns, "vpn") {
		v := st.Vpns[n]
		parts := []string{"vpn " + v.Kind}
		if menuVpnUp(st, n) {
			parts = []string{"connected", "vpn " + v.Kind}
		}
		if w := vpnWhere(v); w != "-" {
			parts = append(parts, w)
		}
		rows = append(rows, menuRow{label: n, detail: menuDetail(parts, v.Groups, v.Tags), value: n})
	}
	return rows
}

// menuHostDetail is whether the server is protected (first, so it is the
// last of the details a narrow screen cuts off), user@address[:port], the
// way there and its groups and tags.
func menuHostDetail(st *store.State, h *store.Host) string {
	addr := h.Address
	if h.User != "" {
		addr = h.User + "@" + addr
	}
	if h.Port != 0 && h.Port != 22 {
		addr += fmt.Sprintf(":%d", h.Port)
	}
	var parts []string
	if menuProtectedHost(st, h) {
		parts = append(parts, "protected")
	}
	parts = append(parts, addr)
	if h.Via != "" {
		parts = append(parts, "via "+h.Via)
	}
	return menuDetail(parts, h.Groups, h.Tags)
}

// menuConnDetail is protected, kind and where, as `komando list` shows
// them: never the URL itself, which may hold a user or a password.
func menuConnDetail(st *store.State, c *store.Conn) string {
	var parts []string
	if menuProtectedConn(st, c) {
		parts = append(parts, "protected")
	}
	parts = append(parts, c.Kind)
	if t, err := driver.Parse(c.URL); err == nil {
		parts = append(parts, t.Where())
	}
	if c.Via != "" {
		parts = append(parts, "via "+c.Via)
	}
	return menuDetail(parts, c.Groups, c.Tags)
}

// menuProtectedHost is protectedHost without asking DNS: the server's own
// mark, or a protected server at the same address and port, written the
// same way. protectedHost also looks names up (2s at most each), and the
// list must draw at once; the question before the command still checks
// everything.
func menuProtectedHost(st *store.State, h *store.Host) bool {
	if h.Protected {
		return true
	}
	for _, o := range st.Hosts {
		if o.Protected && o.EffectivePort() == h.EffectivePort() && sameHostName(o.Address, h.Address) {
			return true
		}
	}
	return false
}

// menuProtectedConn is protectedConn the same way: the conn's own mark, or
// a protected conn of the same family at the same address (or file, or
// bucket), written the same way.
func menuProtectedConn(st *store.State, c *store.Conn) bool {
	key := func(c *store.Conn) string {
		t, err := driver.Parse(c.URL)
		switch {
		case err != nil:
			return ""
		case t.Kind.File:
			return "file " + t.Path
		case t.Bucket != "":
			return "bucket " + normHostPort(t.Address) + "/" + t.Bucket
		}
		return t.Kind.Family + " " + normHostPort(t.Address)
	}
	if c.Protected {
		return true
	}
	k := key(c)
	for _, o := range st.Conns {
		if o.Protected && k != "" && key(o) == k {
			return true
		}
	}
	// an SFTP conn is an SSH server: protected when a protected host is it
	h := sftpHost(c)
	return h != nil && menuProtectedHost(st, h)
}

// menuDetail adds groups and tags, and cleans it all for the screen.
func menuDetail(parts, groups, tags []string) string {
	for _, g := range groups {
		parts = append(parts, "@"+g)
	}
	parts = append(parts, tags...)
	return cleanText(strings.Join(parts, "  "))
}

// menuRunOne runs one komando command on this terminal: its exit code, -1
// when a signal ended it.
func menuRunOne(self string, args []string) (int, error) {
	err := menuCommand(self, args).Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	}
	return 0, err
}

// menuCommandLine is args as a person would type them: a word a shell
// would read differently is quoted, so the line can be copied.
func menuCommandLine(args []string) string {
	words := make([]string, len(args))
	for i, a := range args {
		words[i] = a
		safe := a != "" && !strings.ContainsFunc(a, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./_-", r))
		})
		if !safe {
			words[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return cleanText(strings.Join(words, " "))
}

// menuCommand is the komando command the menu runs, on this terminal. It
// is not tied to a context: Ctrl-C stops the command, not the menu. Its
// environment is komando's own (vault.SelfEnv): komando took
// KOMANDO_VAULT_PASS out of its environment when it started, and the
// command needs it to open a passphrase vault, as it would when typed. The
// command takes it out again before it starts anything else.
func menuCommand(self string, args []string) *exec.Cmd {
	c := exec.Command(self, args...)
	c.Env = vault.SelfEnv()
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c
}

// menuVpnUp: komando keeps a session of this VPN up. The process is checked
// by its pid only, as `komando status --short` does: the list must draw at once.
func menuVpnUp(st *store.State, name string) bool {
	s := st.Sessions[name]
	return s != nil && netx.Alive(s.PID)
}

// menuWrap cuts text into lines of at most width columns, between words.
func menuWrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, w := range strings.Fields(text) {
		if line != "" && displayWidth(line)+1+displayWidth(w) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	return append(lines, line)
}
