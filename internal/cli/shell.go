package cli

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// shellCmd is the interactive login shell, meant for humans taking over
// from an agent. Agents should use exec / job instead.
func shellCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "shell TARGET",
		Aliases: []string{"ssh", "connect"},
		Short:   "Interactive login shell (for people; agents use exec or job)",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				// `ssh host command` runs a command in ssh; here that is exec
				return out.Errf(out.ExitUsage, "USAGE", "run a command with `komando exec "+args[0]+" -- "+strings.Join(args[1:], " ")+"`",
					"komando %s opens an interactive shell and takes no command", cmd.CalledAs())
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShell(cmd.Context(), args[0])
		},
	}
}

// runShell opens the login shell. Like db shell it is for a person only, and
// once inside anything can be typed, so a protected host needs a yes first.
func runShell(ctx context.Context, target string) error {
	if !interactive() {
		return out.Errf(out.ExitUsage, "NEEDS_TERMINAL",
			"agents and scripts use `komando exec` or `komando job start`",
			"shell is interactive and needs a person at a terminal")
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	h, err := singleHost(st, target)
	if err != nil {
		return err
	} else if h.WinRM() {
		return notOnWindows("an interactive shell over WinRM", []string{h.Name})
	}
	protected := protectedHost(st, h)
	if protected && !yesOK() && !confirmYes(h.Name+" is protected. Open a shell on it anyway?") {
		if err := policyStop(out.Errf(out.ExitPolicy, "PROTECTED_HOST",
			"a shell on a protected server needs a person's yes: re-run with --yes after the user confirms",
			"a shell on protected host %s can change anything", h.Name)); err != nil {
			return err
		}
	}
	if g.dryRun { // before any VPN or SSH contact
		audit(st, "shell", []string{h.Name}, "", true, nil)
		out.P.Print("shell", map[string]any{"host": h.Name, "address": h.Address, "user": h.User, "via": h.Via, "protected": protected, "dry_run": true}, nil)
		return nil
	}
	who := h.Address
	if h.User != "" {
		who = h.User + "@" + h.Address
	}
	if who == h.Name {
		who = "" // an ad-hoc user@address target says it already
	}
	showStatus(statusLine{What: "shell", Target: h.Name, Detail: who, Route: hostRoute(st, h), Protected: protected})
	fd := int(os.Stdin.Fd())
	audit(st, "shell", []string{h.Name}, "", true, nil)
	var started time.Time
	code, lost := 0, false
	// a Windows server over SSH gives its own shell (cmd or PowerShell)
	err = withClient(allowWindows(ctx), st, h, func(c *sshx.Client) error {
		sess, err := c.NewSession()
		if err != nil {
			return err
		}
		defer sess.Close()
		w, hgt, _ := term.GetSize(fd)
		t := os.Getenv("TERM")
		if t == "" {
			t = "xterm-256color"
		}
		if err := sess.RequestPty(t, hgt, w, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
			return err
		}
		old, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		defer term.Restore(fd, old)
		sess.Stdin, sess.Stdout, sess.Stderr = os.Stdin, os.Stdout, os.Stderr
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		go func() {
			for range winch {
				if w, h, err := term.GetSize(fd); err == nil {
					_ = sess.WindowChange(h, w)
				}
			}
		}()
		if err := sess.Shell(); err != nil {
			return err
		}
		started = time.Now()
		err = sess.Wait()
		if ee, ok := err.(*ssh.ExitError); ok {
			code = ee.ExitStatus()
			return exitCode(code)
		}
		lost = err != nil
		return err
	})
	// after the callback: the terminal is out of raw mode again
	if !started.IsZero() {
		showExit(h.Name, code, lost, time.Since(started))
	}
	return err
}
