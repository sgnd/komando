package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// How a server logs in. --login takes the same words host show and host
// list print in their login field (store.Host.LoginMode), so what a person
// or an agent reads back is what they can write:
//
//   - ask: a person types the password at every connect; komando never
//     stores it (login_ask.go)
//   - password: a stored password, from --ask-password (typed now) or
//     --password-ref; no key is named
//   - key: a key komando names (--key or --identity), with a stored
//     password after it if the server has one
//   - agent: ssh-agent and the keys in ~/.ssh only
//
// The settings say it on their own too (--key gives key, --password-ref
// gives password); --login makes it explicit and clears what would
// contradict it. Only "ask" is stored as such (store.Host.Login).

// loginModes are the words of --login and of the login field, in order.
var loginModes = []string{store.LoginModeAsk, store.LoginModePassword, store.LoginModeKey, store.LoginModeAgent}

const loginFlagUsage = "how komando logs in, as host show names it: ask (a person types the password at every connect; never stored), " +
	"password (a stored one: with --ask-password or --password-ref), key (with --key or --identity), agent (ssh-agent and ~/.ssh only)"

// loginCompletions are loginModes with what each means, for the shell.
var loginCompletions = []string{
	store.LoginModeAsk + "\ta person types the password at every connect; never stored",
	store.LoginModePassword + "\ta stored password (--ask-password or --password-ref)",
	store.LoginModeKey + "\ta key komando names (--key or --identity)",
	store.LoginModeAgent + "\tssh-agent and the keys in ~/.ssh",
}

// checkLogin refuses a stored login komando does not know, and a
// login-ask server with a stored password.
func checkLogin(h *store.Host) error {
	if h.Login != "" && h.Login != store.LoginAsk {
		return out.Usage("unknown login %q: --login takes %s", h.Login, strings.Join(loginModes, ", "))
	}
	if h.AskLogin() && h.PasswordRef != "" {
		return out.Usage("--login ask keeps no password: pass --login ask or a stored password (--password-ref, --ask-password), not both")
	}
	return nil
}

// loginConflict checks --login against the other login flags of one
// command line, before --ask-password asks for a password. add: the
// server is new, so password and key need the flags that give them.
func loginConflict(fl *pflag.FlagSet, login string, askPw, add bool) error {
	if !fl.Changed("login") {
		return nil
	}
	if !slices.Contains(loginModes, login) {
		return out.Usage("--login takes %s, not %q", strings.Join(loginModes, ", "), login)
	}
	stored := askPw || fl.Changed("password-ref")
	named := fl.Changed("key") || fl.Changed("identity")
	switch login {
	case store.LoginModeAsk:
		if stored {
			return out.Usage("--login ask keeps no password: pass --login ask or a stored password (--password-ref, --ask-password), not both")
		}
	case store.LoginModePassword:
		if named {
			return out.Usage("--login password logs in with the stored password, no key: leave out --key and --identity, or use --login key")
		}
		if add && !stored {
			return out.Usage("--login password needs the password: add --ask-password (type it now, hidden) or --password-ref REF")
		}
	case store.LoginModeKey:
		if add && !named {
			return out.Usage("--login key needs the key: add --key NAME (see komando key list) or --identity PATH")
		}
	case store.LoginModeAgent:
		if stored || named {
			return out.Usage("--login agent logs in with ssh-agent and ~/.ssh only: leave out --key, --identity, --password-ref and --ask-password")
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
		return out.Usage("a WinRM server logs in with a password: --login password or --login ask")
	}
	switch got := h.LoginMode(); {
	case got == mode:
		return nil
	case mode == store.LoginModeKey:
		return out.Usage("%s has no key: add --key NAME (see komando key list) or --identity PATH", h.Name)
	case mode == store.LoginModePassword:
		return out.Usage("%s has no stored password: add --ask-password (type it now, hidden) or --password-ref REF", h.Name)
	default:
		return fmt.Errorf("--login %s left %s logging in with %s", mode, h.Name, got) // a bug: applyLogin clears what contradicts mode
	}
}

// unlinkedWarnings says which secrets an edit of the login left unused:
// komando never deletes them on its own (another server may come to use
// them, or a person wants them back).
func unlinkedWarnings(names []string) []string {
	var w []string
	for _, n := range names {
		w = append(w, fmt.Sprintf("secret %s is no longer used by any server or conn; remove it with `komando secret rm %s` when you no longer need it", n, n))
	}
	return w
}

// hostView is a server as host show prints it: its settings and how it
// logs in (login: ask, password, key or agent).
type hostView struct {
	*store.Host
	Login string `json:"login"`
}

func viewOf(h *store.Host) hostView { return hostView{Host: h, Login: h.LoginMode()} }
