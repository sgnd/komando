package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// menuRun runs komando commands in the normal screen, one after the other
// until one fails: each command line first, so the person learns it, then
// its output, then how the last one ended. Then it waits (Enter goes back,
// q quits) and erases the key help, so the scrollback keeps only the
// commands, their output and how they ended.
//
// back is where Enter goes: "the menu", or "the questions" after Try it
// first.
func menuRun(ctx context.Context, t *menuTerm, self string, cmds [][]string, ownExit bool, back string) (bool, error) {
	t.leave()
	result := "exit 0"
	for _, args := range cmds {
		fmt.Fprintf(os.Stderr, "$ komando %s\n", menuCommandLine(args))
		code, err := menuRunOne(self, args)
		// a command that died without undoing raw mode (killed, crashed) must
		// not leave its terminal modes to the menu or to the next command
		t.restoreOrig()
		if err != nil {
			return false, err
		}
		if code != 0 {
			result = fmt.Sprintf("exit %d", code)
			if code < 0 { // ended by a signal, most likely Ctrl-C
				result = "stopped"
			}
			break
		}
	}
	if ownExit && result == "exit 0" {
		result = "" // "komando: left web1 (exit 0, 12m)" said it already
	}
	keys := "Enter back to " + back + " · q quit "
	if result != "" {
		keys = result + " · " + keys
	}
	// one row at most: "\r\x1b[2K" below erases only the row it is on
	w, _ := t.size()
	fmt.Fprintf(os.Stderr, "\n%s", fit([]seg{{keys, ""}}, w-1, false))
	again, err := menuPause(ctx, t)
	fmt.Fprint(os.Stderr, "\r\x1b[2K")
	if result != "" {
		fmt.Fprintln(os.Stderr, result)
	}
	return again, err
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

// menuPause waits for Enter or Esc (back to the menu) or q (quit). Keys
// typed while the command ran are thrown away first.
func menuPause(ctx context.Context, t *menuTerm) (bool, error) {
	if _, err := term.MakeRaw(t.in); err != nil {
		return false, err
	}
	defer t.restoreOrig()
	_ = dropTypedAhead(t.in)
	t.pending = nil
	for {
		keys, err := t.keys(ctx)
		if err != nil {
			return false, nil
		}
		for _, k := range keys {
			switch {
			case k.kind == keyEnter || k.kind == keyEsc:
				return true, nil
			case k.kind == keyQuit || k.kind == keyRune && (k.r == 'q' || k.r == 'Q'):
				return false, nil
			}
		}
	}
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

// sshConfigNew is how many servers ~/.ssh/config names that komando does
// not know yet.
func sshConfigNew(st *store.State) int {
	hosts, _, err := parseSSHConfig(expandHome("~/.ssh/config"))
	if err != nil {
		return 0
	}
	n := 0
	for _, h := range hosts {
		if _, _, known := st.FindName(h.Name); !known {
			n++
		}
	}
	return n
}

// menuVpnUp: komando keeps a session of this VPN up. The process is checked
// by its pid only, as `komando prompt` does: the list must draw at once.
func menuVpnUp(st *store.State, name string) bool {
	s := st.Sessions[name]
	return s != nil && netx.Alive(s.PID)
}

// The ? text of each screen: what it is for, in one paragraph.
const (
	menuHelpMain     = "This is komando's menu. Pick what you want to work on: your servers, your databases and other services, or your VPNs. Then pick what to do with it. komando shows each command before it runs, so you learn the command as you go. Add something brings in a new server or service, and History and undo shows what changed."
	menuHelpItems    = "These are the things komando knows of this kind. Pick one to see what you can do with it. Type to filter the list when it is long."
	menuHelpTasks    = "These are the things you can do here. komando asks only for what it still needs, shows the command, and runs it after you check it. On a change, Try it first shows what would happen and changes nothing."
	menuHelpAdd      = "Pick what you want to add. komando asks one plain question at a time, shows the commands your answers make, and tests the new item after it is added."
	menuHelpHistory  = "komando keeps a record of every change it made, and who asked for it: you or your AI agent. Here you can read it and put back a file or a rollout."
	menuHelpSettings = "How komando works on this computer: your AI agent, saved passwords, which servers count as production, which commands are blocked, and your SSH keys."
	menuHelpRunning  = "These run on this computer: VPNs, server logins and port forwards. Pick one to stop it. Background jobs run on the servers and keep going when this computer is off; they have their own list here."
	menuHelpConfirm  = "komando asks first because this is hard to take back. No goes back and changes nothing."
)

// menuHelpFor is the ? screen for this text at this width: the paragraph,
// the keys, and where the commands are, each cut to fit.
func menuHelpFor(text string, width int) string {
	var b strings.Builder
	for i, p := range []string{text, "Keys: Enter choose · Esc back · type to filter on long lists · ? help · q quit", "For scripts and AI agents: komando --help"} {
		if i > 0 {
			b.WriteString("\n")
		}
		for _, l := range menuWrap(p, width-1) {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
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

// menuHelp shows a ? screen in the normal screen, at the terminal's width,
// then waits like a command's end: Enter back, q quits.
func menuHelp(ctx context.Context, t *menuTerm, text string) (bool, error) {
	t.leave()
	w, _ := t.size()
	fmt.Fprint(os.Stderr, "\n"+menuHelpFor(text, w))
	fmt.Fprintf(os.Stderr, "\n%s", fit([]seg{{"Enter back · q quit ", ""}}, w-1, false))
	again, err := menuPause(ctx, t)
	fmt.Fprint(os.Stderr, "\r\x1b[2K")
	return again, err
}
