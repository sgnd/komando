package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/vault"
)

// --ask-password lets a person give a server or conn its password in the
// same step as adding it: typed once, hidden, stored in the vault as
// secret:NAME-pass and used as its --password-ref. Without it a password
// login takes three commands and a made-up secret name (secret set, host
// edit --password-ref, test).

func askPasswordFlag(c *cobra.Command, ask *bool) {
	c.Flags().BoolVar(ask, "ask-password", false, "type the password now (hidden, a person at a terminal); it is stored in the vault as secret:NAME-pass and used as --password-ref")
}

// askSecret is a secret a command can ask for now, hidden: a password
// (--ask-password) or a VPN's pre-shared key (--ask-psk).
type askSecret struct {
	flag, refFlag string // ask-password and the reference flag it stands for
	suffix, what  string // stored as NAME-suffix; "password" in the messages
}

var (
	askPasswordSecret = askSecret{"ask-password", "password-ref", "pass", "password"}
	askPSKSecret      = askSecret{"ask-psk", "psk-ref", "psk", "pre-shared key"}
)

// askPassword asks for kind name's password and stores it. It returns the
// reference and undo, which removes a secret it created when the add or
// edit that follows fails. A dry run asks nothing; an AI agent gets
// NEEDS_PERSON (the user types a password, never the agent).
func askPassword(cmd *cobra.Command, kind, name string) (ref string, undo func(), err error) {
	return askSecretNow(cmd, kind, name, askPasswordSecret)
}

// askSecretNow is askPassword for any askSecret.
func askSecretNow(cmd *cobra.Command, kind, name string, a askSecret) (ref string, undo func(), err error) {
	undo = func() {}
	if cmd.Flags().Changed(a.refFlag) {
		return "", undo, out.Usage("use --%s or --%s, not both", a.flag, a.refFlag)
	}
	if err := validName(kind, name); err != nil {
		return "", undo, out.Errf(out.ExitUsage, "USAGE", fmt.Sprintf("give one %s by its name, e.g. komando %s edit web1 --%s", map[string]string{"host": "server", "conn": "conn", "vpn": "VPN"}[kind], kind, a.flag),
			"--%s gives one %s its %s; %q is not one name", a.flag, kind, a.what, name)
	}
	sec := name + "-" + a.suffix
	ref = "secret:" + sec
	if g.dryRun {
		return ref, undo, nil
	}
	if !interactive() {
		if isAgent() {
			return "", undo, out.Errf(out.ExitPolicy, "NEEDS_PERSON",
				"ask the user to run `"+commandLine()+"` in their own terminal; never ask for a "+a.what+" in the chat",
				"--%s needs the user to type the %s, so it never passes through an AI agent", a.flag, a.what)
		}
		hint := fmt.Sprintf("store it with `komando secret set %s` (it reads stdin too), then pass --%s %s", sec, a.refFlag, ref)
		if a.flag == askPasswordSecret.flag {
			return "", undo, out.Errf(out.ExitUsage, "NEEDS_TERMINAL", hint, "--ask-password asks at a terminal, and there is none")
		}
		return "", undo, out.Errf(out.ExitUsage, "NEEDS_TERMINAL", hint, "--ask-psk asks at a terminal, and there is none")
	}
	st, err := loadState()
	if err != nil {
		return "", undo, err
	}
	self := kind + " " + name
	others := slices.DeleteFunc(secretUsers(st, sec), func(u string) bool { return u == self })
	_, getErr := vault.Get(sec)
	existed := getErr == nil
	if existed && len(others) > 0 {
		return "", undo, out.Errf(out.ExitConflict, "SECRET_EXISTS",
			fmt.Sprintf("use it with --%s %s, or store this one under another name: `komando secret set NAME`, then --%s secret:NAME", a.refFlag, ref, a.refFlag),
			"secret %s is used by %s already; --ask-password and --ask-psk do not replace it", sec, strings.Join(others, ", "))
	}
	// a new password for a protected server or conn changes how komando
	// logs in there: the same yes as any change to it
	if prot := protectedUsers(st, []string{self}); len(prot) > 0 && !yesOK() && !confirmProtected(prot) {
		return "", undo, policyStop(approvalErr(map[string]string{"host": "PROTECTED_HOST", "conn": "PROTECTED_TARGET", "vpn": "PROTECTED_TARGET"}[kind],
			name+" is protected; a new password or key changes how komando logs in there"))
	}
	v, err := readPassword(fmt.Sprintf("%s for %s (it stays hidden): ", strings.ToUpper(a.what[:1])+a.what[1:], name))
	if err != nil {
		return "", undo, err
	}
	if v == "" {
		return "", undo, out.Usage("empty %s: nothing was stored", a.what)
	}
	if out.HasHidden(v) {
		return "", undo, hiddenValueErr()
	}
	if err := vault.Set(sec, v); err != nil {
		return "", undo, err
	}
	audit(nil, "secret.set", nil, "", true, map[string]any{"secret": sec, "replaced": existed, "for": self})
	if !existed {
		undo = func() { _ = vault.Delete(sec) }
	}
	return ref, undo, nil
}

// missingSecretWarnings says which secret: references point at nothing in
// the vault yet, with the command that stores each, so a typo shows when it
// is made rather than at the next login.
func missingSecretWarnings(refs ...string) []string {
	var w []string
	for _, r := range refs {
		n, ok := strings.CutPrefix(r, "secret:")
		if !ok || n == "" {
			continue
		}
		if _, err := vault.Get(n); err == vault.ErrNotFound {
			w = append(w, fmt.Sprintf("secret %s is not in the vault yet: store it with `komando secret set %s`", n, n))
		}
	}
	return w
}

// readPassword reads the typed password; tests stand in for the terminal.
var readPassword = readHidden
