package cli

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// A key whose line has --shell-access (only one that may change things) may also
// open a login shell on one server. Its line says restrict,pty, so sshd
// gives the call a terminal when the key asks for one (ssh -t). The gate
// lets the shell through only as `komando shell SERVER`, word for word,
// with that terminal, for a server in the inventory named as it is written
// there that is not protected, not Windows and not this computer, and
// never while you have deny rules of your own. Anything it cannot read so
// is refused. Every other command, db shell and cluster
// shell too, gets the answer a key without --shell-access gets (gateRule).

// gateTTY: sshd gave the call a terminal. sshd sets SSH_TTY only then, but
// a client may send that variable too (AcceptEnv), so stdin and stderr must
// be a terminal as well.
func gateTTY(cl *call) bool { return cl.terminal && cl.getenv("SSH_TTY") != "" }

// gateShell says whether a --shell-access key may open the shell args asks for (c
// is the shell command, found in args): nil, or the stop.
func gateShell(c *cobra.Command, args []string, key gateKey) *out.Error {
	refuse := func(hint, format string, a ...any) *out.Error {
		return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", hint, format, a...)
	}
	onlyShell := refuse("send exactly: komando shell SERVER", "a key opens a shell only as `komando shell SERVER`, with no other word or flag")
	if len(args) != 2 || args[0] != "shell" || strings.HasPrefix(args[1], "-") {
		return onlyShell
	}
	if err := c.ParseFlags(args[1:]); err != nil || len(c.Flags().Args()) != 1 {
		return onlyShell
	}
	if !key.tty {
		return refuse("connect with a terminal: ssh -t HOST komando shell SERVER",
			"komando shell needs the terminal sshd gives a key that asks for one, and this call has none")
	}
	server := args[1]
	st, err := store.Load()
	if err != nil {
		return refuse("check the inventory on the komando computer (`komando doctor`)", "the inventory could not be read")
	}
	h := st.Hosts[server]
	listed := h != nil && !isSelector(server)
	if listed {
		// komando shell finds the server again by this name: it must be this one, alone
		sel, err := resolveSelection(callOf(c), st, server)
		listed = err == nil && len(sel.Hosts) == 1 && sel.Hosts[0] == h && len(sel.Conns)+len(sel.Vpns) == 0
	}
	if !listed {
		return refuse("name one server exactly as `komando list` shows it",
			"%q is no server in your list; a key opens a shell only on one listed server, named as it is written there", server)
	}
	if why := gateLocalTarget(c, "shell"); why != "" {
		return refuse("a person uses a terminal on the komando computer itself",
			"komando shell is refused for a key: %s; the gate opens shells on servers, not on this computer", why)
	}
	return gateShellHost(st, h)
}

// gateShellHost says why no key opens a shell on h, or nil. The gate checks
// it, and so does the shell it runs (runShell).
func gateShellHost(st *store.State, h *store.Host) *out.Error {
	switch {
	case protectedHost(st, h):
		return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person opens a shell on a protected server at the komando computer itself",
			"the server %s is protected, or is a protected server under another name: a shell there can change anything, and no key opens one", h.Name)
	case h.Windows():
		return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "run PowerShell with `komando exec "+h.Name+" -- ...` instead",
			"the server %s is a Windows server: a key opens a shell only on a Linux or Unix server", h.Name)
	case len(st.Settings.ExtraDenyPattern) > 0:
		return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "send single commands instead (`komando exec "+h.Name+" -- ...`), which your deny rules check; a person opens the shell at the komando computer itself",
			"you have deny rules of your own (`komando policy list`), and komando does not see what is typed in a shell, so a shell would get past them: no key opens one while they are set")
	}
	return nil
}

// gateRunShell opens the shell gateShell allowed, in the gate's own process:
// the gate has checked the key, its words, its terminal and the server, and
// a komando started for it could only learn that from what it inherits. It
// runs as the key (an agent named ssh-gate key LABEL), asks nothing, and
// checks the server again, as the inventory may have changed since.
func gateRunShell(cl *call, ctx context.Context, label, server string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	h := st.Hosts[server]
	if h == nil {
		return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "name one server exactly as `komando list` shows it",
			"%q is no server in your list; a key opens a shell only on one listed server, named as it is written there", server)
	}
	if e := gateShellHost(st, h); e != nil {
		return e
	}
	cl.setCaller(engine.Caller{Kind: engine.Agent, Agent: "ssh-gate key " + label, Actor: cl.caller().Actor})
	return openShell(cl, ctx, st, h, label)
}
