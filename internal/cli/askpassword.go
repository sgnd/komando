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
// login took three commands and a secret name the person had to make up
// (secret set, host edit --password-ref, test).

func askPasswordFlag(c *cobra.Command, ask *bool) {
	c.Flags().BoolVar(ask, "ask-password", false, "type the password now (hidden, a person at a terminal); it is stored in the vault as secret:NAME-pass and used as --password-ref")
}

// askPassword asks for kind name's password and stores it. It returns the
// reference and undo, which removes a secret it created when the add or
// edit that follows fails. A dry run asks nothing; an AI agent gets
// NEEDS_PERSON (the user types a password, never the agent).
func askPassword(cmd *cobra.Command, kind, name string) (ref string, undo func(), err error) {
	undo = func() {}
	if cmd.Flags().Changed("password-ref") {
		return "", undo, out.Usage("use --ask-password or --password-ref, not both")
	}
	if err := validName(kind, name); err != nil {
		return "", undo, out.Errf(out.ExitUsage, "USAGE", fmt.Sprintf("give one %s by its name, e.g. komando %s edit web1 --ask-password", map[string]string{"host": "server", "conn": "conn"}[kind], kind),
			"--ask-password gives one %s its password; %q is not one name", kind, name)
	}
	sec := name + "-pass"
	ref = "secret:" + sec
	if g.dryRun {
		return ref, undo, nil
	}
	if !interactive() {
		if isAgent() {
			return "", undo, out.Errf(out.ExitPolicy, "NEEDS_PERSON",
				"ask the user to run `"+commandLine()+"` in their own terminal; never ask for a password in the chat",
				"--ask-password needs the user to type the password, so it never passes through an AI agent")
		}
		return "", undo, out.Errf(out.ExitUsage, "NEEDS_TERMINAL",
			fmt.Sprintf("store it with `komando secret set %s` (it reads stdin too), then pass --password-ref %s", sec, ref),
			"--ask-password asks at a terminal, and there is none")
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
			fmt.Sprintf("use it with --password-ref %s, or store this one under another name: `komando secret set NAME`, then --password-ref secret:NAME", ref),
			"secret %s is used by %s already; --ask-password does not replace it", sec, strings.Join(others, ", "))
	}
	// a new password for a protected server or conn changes how komando
	// logs in there: the same yes as any change to it
	if prot := protectedUsers(st, []string{self}); len(prot) > 0 && !yesOK() && !confirmProtected(prot) {
		return "", undo, policyStop(out.Errf(out.ExitPolicy, map[string]string{"host": "PROTECTED_HOST", "conn": "PROTECTED_TARGET"}[kind],
			"re-run with --yes after the user confirms", "%s is protected; a new password changes how komando logs in there", name))
	}
	v, err := readPassword(fmt.Sprintf("Password for %s (it stays hidden): ", name))
	if err != nil {
		return "", undo, err
	}
	if v == "" {
		return "", undo, out.Usage("empty password: nothing was stored")
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
