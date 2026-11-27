package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// How a server or a conn logs in. --login takes the same words host show,
// conn show and list print in their login field (LoginMode), so what a
// person or an agent reads back is what they can write:
//
//   - ask: a person types the password at every connect; komando never
//     stores it (login_ask.go)
//   - password: a stored password, from --ask-password (typed now) or
//     --password-ref; a server names no key then
//   - key (servers): a key komando names (--key or --identity), with a
//     stored password after it if the server has one
//   - agent (servers): ssh-agent and the keys in ~/.ssh only
//   - none (conns): komando sends no password of its own (the URL's own
//     login, a cloud login, or none)
//
// The settings say it on their own too (--key gives key, --password-ref
// gives password); --login makes it explicit and clears what would
// contradict it. Only "ask" is stored as such (Login).

// loginModes are the words of a server's --login, in order; connLoginModes
// a conn's.
var (
	loginModes     = []string{store.LoginModeAsk, store.LoginModePassword, store.LoginModeKey, store.LoginModeAgent}
	connLoginModes = []string{store.LoginModeAsk, store.LoginModePassword, store.LoginModeNone}
)

// loginFlagUsage is the one usage text of --login (command standard
// S-5.11), on host add/edit and conn add/edit.
const loginFlagUsage = "how komando logs in, as show names it: ask (a person types the password at every connect; never stored), " +
	"password (a stored one: with --ask-password or --password-ref); a server also takes key (with --key or --identity) " +
	"and agent (ssh-agent and ~/.ssh only), a conn none (no password of komando's own)"

// loginCompletions are loginModes with what each means, for the shell;
// connLoginCompletions are a conn's.
var (
	loginCompletions = []string{
		store.LoginModeAsk + "\ta person types the password at every connect; never stored",
		store.LoginModePassword + "\ta stored password (--ask-password or --password-ref)",
		store.LoginModeKey + "\ta key komando names (--key or --identity)",
		store.LoginModeAgent + "\tssh-agent and the keys in ~/.ssh",
	}
	connLoginCompletions = []string{
		store.LoginModeAsk + "\ta person types the password at every connect; never stored",
		store.LoginModePassword + "\ta stored password (--ask-password or --password-ref)",
		store.LoginModeNone + "\tno password of komando's own (the URL's login, a cloud login)",
	}
)

// loginUsage is a USAGE error about --login with the command that fixes it
// as its hint.
func loginUsage(hint, format string, a ...any) *out.Error {
	return out.Errf(out.ExitUsage, "USAGE", hint, format, a...)
}

// errAskStored: --login ask with a stored password.
func errAskStored(kind, name string) *out.Error {
	return loginUsage(fmt.Sprintf("keep one: `komando %s edit %s --login ask` (nothing stored), or --password-ref REF / --ask-password without --login ask", kind, name),
		"--login ask keeps no password, so it cannot go with a stored one (--password-ref, --ask-password)")
}

// checkLogin refuses a stored login komando does not know, and a
// login-ask server with a stored password.
func checkLogin(h *store.Host) error {
	if h.Login != "" && h.Login != store.LoginAsk {
		return loginUsage("`komando host edit "+h.Name+" --login WORD`, with one of: "+strings.Join(loginModes, ", "),
			"unknown login %q", h.Login)
	}
	if h.AskLogin() && h.PasswordRef != "" {
		return errAskStored("host", h.Name)
	}
	return nil
}

// loginWord checks the word of --login against words.
func loginWord(fl *pflag.FlagSet, login string, words []string) error {
	if fl.Changed("login") && !slices.Contains(words, login) {
		return loginUsage("--login takes "+strings.Join(words, ", "), "--login takes %s, not %q", strings.Join(words, ", "), login)
	}
	return nil
}

// editName is the server or conn an edit names, for a hint: NAME when it
// names several.
func editName(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	return "NAME"
}

// loginConflict checks a server's --login against the other login flags
// of one command line, before --ask-password asks for a password. add:
// the server is new, so password and key need the flags that give them.
func loginConflict(fl *pflag.FlagSet, name, login string, askPw, add bool) error {
	if !fl.Changed("login") {
		return nil
	}
	if err := loginWord(fl, login, loginModes); err != nil {
		return err
	}
	stored := askPw || fl.Changed("password-ref")
	named := fl.Changed("key") || fl.Changed("identity")
	switch login {
	case store.LoginModeAsk:
		if stored {
			return errAskStored("host", name)
		}
	case store.LoginModePassword:
		if named {
			return loginUsage("leave out --key and --identity, or use --login key to log in with the key first",
				"--login password logs in with the stored password, no key")
		}
		if add && !stored {
			return loginUsage("add --ask-password (type it now, hidden) or --password-ref REF", "--login password needs the password")
		}
	case store.LoginModeKey:
		if add && !named {
			return loginUsage("add --key NAME (see `komando credential key list`) or --identity PATH", "--login key needs the key")
		}
	case store.LoginModeAgent:
		if stored || named {
			return loginUsage("leave out --key, --identity, --password-ref and --ask-password, or pick the --login they give",
				"--login agent logs in with ssh-agent and ~/.ssh only")
		}
	}
	return nil
}

// applyLogin makes mode the way h logs in, after the command's other
// settings: it clears what would contradict it, then checks that h now
// logs in that way (host show prints mode back).
func applyLogin(h *store.Host, mode string) error {
	switch mode {
	case store.LoginModeAsk:
		h.Login = store.LoginAsk
		h.PasswordRef = "" // never stored: the vault keeps the secret (host edit warns when nothing uses it)
	case store.LoginModePassword:
		h.Login, h.Key, h.Identity = "", "", ""
	case store.LoginModeKey:
		h.Login = ""
	case store.LoginModeAgent:
		h.Login, h.Key, h.Identity, h.PasswordRef = "", "", "", ""
	}
	if h.WinRM() && (mode == store.LoginModeKey || mode == store.LoginModeAgent) {
		return loginUsage("use --login password or --login ask", "a WinRM server logs in with a password, not with --login %s", mode)
	}
	switch got := h.LoginMode(); {
	case got == mode:
		return nil
	case mode == store.LoginModeKey:
		return loginUsage("add --key NAME (see `komando credential key list`) or --identity PATH", "%s has no key", h.Name)
	case mode == store.LoginModePassword:
		return loginUsage("add --ask-password (type it now, hidden) or --password-ref REF", "%s has no stored password", h.Name)
	default:
		return fmt.Errorf("--login %s left %s logging in with %s", mode, h.Name, got) // a bug: applyLogin clears what contradicts mode
	}
}

// connLoginConflict is loginConflict for a conn.
func connLoginConflict(fl *pflag.FlagSet, name, login string, askPw, add bool) error {
	if !fl.Changed("login") {
		return nil
	}
	if err := loginWord(fl, login, connLoginModes); err != nil {
		return err
	}
	stored := askPw || fl.Changed("password-ref")
	switch login {
	case store.LoginModeAsk:
		if stored {
			return errAskStored("conn", name)
		}
	case store.LoginModePassword:
		if add && !stored {
			return loginUsage("add --ask-password (type it now, hidden) or --password-ref REF", "--login password needs the password")
		}
	case store.LoginModeNone:
		if stored {
			return loginUsage("leave out --password-ref and --ask-password, or use --login password",
				"--login none sends no password of komando's own")
		}
	}
	return nil
}

// applyConnLogin makes mode the way c logs in, after the command's other
// settings (conn show prints mode back).
func applyConnLogin(c *store.Conn, mode string) error {
	switch mode {
	case store.LoginModeAsk:
		c.Login, c.PasswordRef = store.LoginAsk, "" // never stored; the vault keeps the secret
	case store.LoginModePassword:
		c.Login = ""
	case store.LoginModeNone:
		c.Login, c.PasswordRef = "", ""
	}
	if c.LoginMode() != mode {
		return loginUsage("add --ask-password (type it now, hidden) or --password-ref REF", "%s has no stored password", c.Name)
	}
	return nil
}

// checkConnLogin refuses a stored login komando does not know, a
// login-ask conn with a stored password, and login ask for a conn whose
// "password" is not one a person types: a file on this computer, or a
// cluster's kubeconfig.
func checkConnLogin(c *store.Conn, k driver.Kind) error {
	if c.Login != "" && c.Login != store.LoginAsk {
		return loginUsage("`komando conn edit "+c.Name+" --login WORD`, with one of: "+strings.Join(connLoginModes, ", "), "unknown login %q", c.Login)
	}
	if !c.AskLogin() {
		return nil
	}
	if c.PasswordRef != "" {
		return errAskStored("conn", c.Name)
	}
	switch {
	case k.File:
		return loginUsage("leave out --login ask: komando opens the file itself", "%s conns are files on this computer, with no login to ask for", k.Name)
	case k.Family == "cluster":
		return loginUsage("import the cluster with `komando import kubeconfig`: its login stays in the vault",
			"a cluster logs in with its kubeconfig, which nobody types: --login ask is for passwords")
	}
	return nil
}

// unlinkedWarnings says which secrets an edit of the login left unused:
// komando never deletes them on its own (another server may come to use
// them, or a person wants them back).
func unlinkedWarnings(names []string) []string {
	var w []string
	for _, n := range names {
		w = append(w, fmt.Sprintf("secret %s is no longer used by any server or conn; remove it with `komando credential password remove %s` when you no longer need it", n, n))
	}
	return w
}

// hostView is a server as host show prints it: its settings and how it
// logs in (login: ask, password, key or agent).
type hostView struct {
	*store.Host
	Login string `json:"login"`
	// HostCA: host show only, the trusted host CA that vouches for this
	// server's host certificate (no pin needed)
	HostCA string `json:"host_ca,omitempty"`
}

func viewOf(h *store.Host) hostView { return hostView{Host: h, Login: h.LoginMode()} }

// connView is a conn as conn show prints it: its settings and how it logs
// in (login: ask, password or none).
type connView struct {
	*store.Conn
	Login string `json:"login"`
}
