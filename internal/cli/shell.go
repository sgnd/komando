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
// A --shell-access key's shell does not come here: ssh-gate opens it itself
// (gateRunShell).
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
	return openShell(cl, ctx, st, h, "")
}

// openShell connects to h and runs a login shell there on this terminal
// until it ends. key is the ssh-gate key whose shell it is, or "" for a
// person's: a key's session has its own start and end records and an idle
// limit.
func openShell(cl *call, ctx context.Context, st *store.State, h *store.Host, key string) error {
	keyed := key != ""
	if !keyed {
		audit(cl, st, "shell", []string{h.Name}, "", true, nil)
	} else if err := gateSessionStart(cl, st, key, h.Name); err != nil {
		return err
	}
	begun := shellClock.now()
	tt := shellTTY()
	var started time.Time
	code, lost, stop := 0, false, ""
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
		sio := shellIO{in: cl.stdin, out: cl.out.W, err: cl.out.Err}
		if keyed {
			sio.idle = newIdleWatch(shellIdleLimit, shellClock)
		}
		stop, err = driveShell(ctx, conn, tt, sio, func() { started = time.Now() })
		switch stop {
		case sessionIdle:
			return out.Errf(out.ExitTimeout, "SHELL_IDLE_TIMEOUT", "connect again (ssh -t HOST komando shell "+h.Name+"); run long work as a job: `komando job start "+h.Name+" -- COMMAND`",
				"the shell on %s ended after %s with no input and no output", h.Name, shellIdleLimit)
		case sessionHangup:
			return ctx.Err()
		}
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
		case stop != "":
			end = stop
		case started.IsZero():
			end = sessionError
		case lost:
			end = sessionLost
		}
		if aerr := gateSessionEnd(cl, st, key, h.Name, shellClock.now().Sub(begun), end, code); err == nil {
			err = aerr
		}
	}
	return err
}
