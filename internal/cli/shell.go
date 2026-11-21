package cli

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// shellCmd is the interactive login shell, meant for humans taking over
// from an agent. Agents should use exec / job instead.
func shellCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "shell SERVER",
		Aliases: []string{"ssh", "connect"},
		Short:   "Open a login shell on one server",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				// `ssh host command` runs a command in ssh; here that is exec
				hint := "run a command with `komando exec " + args[0] + " -- " + strings.Join(args[1:], " ") + "`"
				if err := komandoFlagsAfterDash("exec "+args[0], args[1:]); err != nil {
					hint = toErr(err).Hint
				}
				return out.Errf(out.ExitUsage, "USAGE", hint, "komando %s opens an interactive shell and takes no command", cmd.CalledAs())
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			return runShell(cl, cmd.Context(), args[0])
		}),
	}
}

// runShell opens the login shell. Like db shell it is for a person only, and
// once inside anything can be typed, so a protected host needs a yes first.
func runShell(cl *call, ctx context.Context, target string) error {
	if !cl.interactive() {
		return out.Errf(out.ExitUsage, "NEEDS_TERMINAL",
			"agents and scripts use `komando exec` or `komando job start`",
			"shell needs a person at a terminal")
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	h, err := singleHost(cl, st, target)
	if err != nil {
		return err
	} else if h.WinRM() {
		return notOnWindows("an interactive shell over WinRM", []string{h.Name})
	}
	protected := protectedHost(st, h)
	if protected && !cl.yesOK() && !confirmYes(cl, h.Name+" (protected): this opens a shell on it. Continue?") {
		if err := cl.policyStop(approvalErr(cl, "PROTECTED_TARGET",
			"a shell on protected server "+h.Name+" can change anything")); err != nil {
			return err
		}
	}
	if cl.flags.dryRun { // before any VPN or SSH contact
		audit(cl, st, "shell", []string{h.Name}, "", true, nil)
		cl.out.Print("shell", map[string]any{"host": h.Name, "address": h.Address, "user": h.User, "via": h.Via, "protected": protected, "dry_run": true}, nil)
		return nil
	}
	who := h.Address
	if h.User != "" {
		who = h.User + "@" + h.Address
	}
	if who == h.Name {
		who = "" // an ad-hoc user@address target says it already
	}
	showStatus(cl, statusLine{What: "shell", Target: h.Name, Detail: who, Route: hostRoute(st, h), Protected: protected})
	return openShell(cl, ctx, st, h)
}

// openShell connects to h and runs a login shell there on this terminal
// until it ends.
func openShell(cl *call, ctx context.Context, st *store.State, h *store.Host) error {
	keyed := cl.gated() // a key's session: its own start and end records
	if !keyed {
		audit(cl, st, "shell", []string{h.Name}, "", true, nil)
	} else if err := gateSessionStart(cl, st, h.Name); err != nil {
		return err
	}
	begun := time.Now()
	tt := shellTTY()
	var started time.Time
	code, lost := 0, false
	// a Windows server over SSH gives its own shell (cmd or PowerShell)
	err := shellDial(cl, allowWindows(ctx), st, h, func(conn shellConn) error {
		w, hgt, _ := tt.Size()
		t := cl.getenv("TERM")
		if t == "" {
			t = "xterm-256color"
		}
		if err := conn.RequestPty(t, hgt, w, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
			return err
		}
		restore, err := tt.MakeRaw()
		if err != nil {
			return err
		}
		defer restore()
		err = driveShell(conn, tt, shellIO{cl.stdin, cl.out.W, cl.out.Err}, func() { started = time.Now() })
		if ee, ok := err.(*ssh.ExitError); ok {
			code = ee.ExitStatus()
			return exitCode(code)
		}
		lost = err != nil && !started.IsZero()
		return err
	})
	// after the callback: the terminal is out of raw mode again
	if !started.IsZero() {
		showExit(cl, h.Name, code, lost, time.Since(started))
	}
	if keyed {
		end := sessionExit
		switch {
		case started.IsZero():
			end = sessionError
		case lost:
			end = sessionLost
		}
		if aerr := gateSessionEnd(cl, st, h.Name, time.Since(begun), end, code); err == nil {
			err = aerr
		}
	}
	return err
}
