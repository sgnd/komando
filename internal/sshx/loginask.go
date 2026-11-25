package sshx

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Login ask (host add --login ask): a server whose password komando never
// stores. A person types it for the command that connects (LoginPassword);
// the host keys keep which servers a person logged in to with which key
// (pinRecord.Logins), so a pin alone never lets a typed password go.

// LoginAsk is one connection's question for the password of a server
// whose login is "ask" (host add --login ask).
type LoginAsk struct {
	Host *store.Host
	User string // the user komando logs in as
	Addr string // host:port, where the password goes
	// Path is the way there komando dials through ("" for straight
	// there): the VPN, each jump host with its user and address, a proxy
	// command. The password goes to Addr at its end.
	Path string
	// NewKey is the host key this connection trusted on first use (or
	// could not check: host_key_policy off); nil for a key komando knew.
	// Nothing proved a new key is the server's.
	NewKey *NewHostKey
}

// LoginAskFor is the question a connection to h asks, before it connects
// (NewKey unknown yet).
func LoginAskFor(st *store.State, h *store.Host) LoginAsk {
	user := loginUser(st, h)
	return LoginAsk{Host: h, User: user, Addr: net.JoinHostPort(h.Address, strconv.Itoa(h.EffectivePort())), Path: wayTo(st, h)}
}

// loginUser is the user komando logs in to h as.
func loginUser(st *store.State, h *store.Host) string {
	user := h.User
	if user == "" && st != nil {
		user = st.Settings.DefaultUser
	}
	if user == "" {
		user = LocalUser()
	}
	return user
}

// WayVia names the steps komando dials through to reach h and h itself,
// as a conn reached --via h names its way.
func WayVia(st *store.State, h *store.Host) string { return way(st, h, true) }

// wayTo names the steps komando dials through to reach h, as Dial takes
// them (resolveChain), or "" when it goes straight there.
func wayTo(st *store.State, h *store.Host) string { return way(st, h, false) }

// way is wayTo, with h itself as the last step when self.
func way(st *store.State, h *store.Host, self bool) string {
	hops := []*store.Host{h}
	var vpn *store.Vpn
	if st != nil {
		v, chain, err := resolveChain(st, h, map[string]bool{})
		if err != nil {
			return "" // Dial says what is wrong with the path
		}
		vpn, hops = v, chain
	}
	var parts []string
	if vpn != nil {
		parts = append(parts, "VPN "+vpn.Name)
	}
	for i, hop := range hops {
		carrier := ""
		switch {
		case builtinSSM(hop):
			carrier = "AWS Session Manager"
		case hop.ProxyCommand != "":
			carrier = "the proxy command `" + hop.ProxyCommand + "`"
		}
		if i == len(hops)-1 && !self {
			if carrier != "" {
				parts = append(parts, carrier)
			}
			break
		}
		where := loginUser(st, hop) + "@" + net.JoinHostPort(hop.Address, strconv.Itoa(hop.EffectivePort()))
		if carrier != "" {
			where += ", carried by " + carrier
		}
		parts = append(parts, hop.Name+" ("+where+")")
	}
	return strings.Join(parts, ", then ")
}

// LoginPassword, when set, gives the password of a server whose login is
// "ask": komando never stores it, so a person types it for the command
// that connects (ctx is that command's Dial). It returns refused, which
// the login calls when the server refuses the password, so the command
// does not send it again. The cli asks the person at the terminal, in an
// app's window, or in komando's own window for an AI agent's command; a
// script, or an agent with no screen, gets NEEDS_PERSON. Unset: the
// person at the terminal (Asker) or NEEDS_PERSON.
var LoginPassword func(ctx context.Context, q LoginAsk) (pw string, refused func(), err error)

// loginPassword is the typed password of a login-ask server.
func loginPassword(ctx context.Context, q LoginAsk) (string, func(), error) {
	if LoginPassword != nil {
		return LoginPassword(ctx, q)
	}
	if person := personFor(q.Host); person != nil {
		pw, err := person("Password: ", true)
		return pw, func() {}, err
	}
	return "", nil, AskLoginNeedsPerson(q.Host, false)
}

// AskLoginNewKey, when set, decides whether a connection may go on with a
// login-ask server whose host key komando has not seen before (k): the
// key is pinned only when it returns nil. The person's password would go
// to whatever answers at the address, so the cli lets a first connection
// through only when a person is at the terminal (who sees the key) or an
// app's window will warn them; an AI agent's or a script's command gets
// NEEDS_PERSON and nothing is pinned. Unset: only with a person at the
// terminal.
var AskLoginNewKey func(ctx context.Context, h *store.Host, k NewHostKey) error

// askLoginNewKey is AskLoginNewKey, or its default.
func askLoginNewKey(ctx context.Context, h *store.Host, k NewHostKey) error {
	if AskLoginNewKey != nil {
		return AskLoginNewKey(ctx, h, k)
	}
	if personFor(h) != nil {
		return nil
	}
	return AskLoginNewKeyNeedsPerson(h, k, false)
}

// AskLoginNewKeyNeedsPerson is NEEDS_PERSON for the first connection to a
// login-ask server h (or one whose key is not checked) with nobody at a
// terminal to see the key: nothing was pinned or sent.
func AskLoginNewKeyNeedsPerson(h *store.Host, k NewHostKey, agent bool) *out.Error {
	name := h.Name
	what := fmt.Sprintf("komando has not met %s at %s before (its %s host key %s is not trusted yet)", name, k.Address, k.Type, k.Fingerprint)
	switch {
	case k.NotMet:
		what = fmt.Sprintf("nobody has logged in to %s at %s with a typed password yet (a pinned host key alone may come from any connection to that address)", name, k.Address)
	case k.Unchecked && k.Fingerprint == "" && k.Type != "":
		what = fmt.Sprintf("nothing checks who answers for %s at %s (%s)", name, k.Address, k.Type)
	case k.Fingerprint == "" && !k.Unchecked:
		what = fmt.Sprintf("komando has not met %s at %s before (no host key of it is pinned)", name, k.Address)
	case k.Unchecked:
		what = fmt.Sprintf("komando does not check the host key of %s at %s (host_key_policy off)", name, k.Address)
	}
	msg := what + ", and " + name + " logs in with a password a person types (login ask): a person's password never goes to a server komando cannot tell from an impostor; nothing was sent"
	return out.Errf(out.ExitPolicy, "NEEDS_PERSON", AskLoginStep(h, agent)+": a person there sees what komando connects to and types the password", "%s", msg).NoFlag()
}

// AskLoginNeedsPerson is NEEDS_PERSON for a login-ask server h nobody can
// type the password for: an AI agent (agent) with no window, or a script.
func AskLoginNeedsPerson(h *store.Host, agent bool) *out.Error {
	if agent {
		return out.Errf(out.ExitPolicy, "NEEDS_PERSON", AskLoginStep(h, true)+"; never ask for the password in the chat",
			"%s logs in with a password a person types each time (login ask), and komando could not ask the user in a window here", h.Name).NoFlag()
	}
	return out.Errf(out.ExitPolicy, "NEEDS_PERSON", AskLoginStep(h, false)+": later commands (scripts too) use that session while it lasts",
		"%s logs in with a password a person types each time (login ask), and no person is at a terminal here", h.Name).NoFlag()
}

// AskLoginStep is the one next step when nobody here can type the password
// of login-ask server h: a person runs `komando test NAME` in their own
// terminal (it keeps the session for a while); a WinRM server has no kept
// session, so the person runs the command there.
func AskLoginStep(h *store.Host, agent bool) string {
	who := "have a person run"
	if agent {
		who = "ask the user to run"
	}
	if h.WinRM() {
		return who + " the command in their own terminal (a WinRM server has no kept session)"
	}
	return who + " `" + PersonStepCmd(h.Name) + "` in their own terminal"
}

// LoginID is what login-ask server h is known by in the host keys'
// logins (and the password window's cool-down): its record ID, which a
// rename keeps, or its name.
func LoginID(h *store.Host) string {
	if h.Rec.ID != "" {
		return h.Rec.ID
	}
	return "name:" + h.Name
}

// loginMet notes, after a login to login-ask server h, that a person
// logged in with the key it offered for the first time (q.NewKey): only
// a person's connection gets that far (askLoginNewKey).
func loginMet(ctx context.Context, h *store.Host, q *LoginAsk) error {
	if q == nil || !h.AskLogin() || q.NewKey == nil || q.NewKey.Unchecked || q.NewKey.key == nil {
		return nil
	}
	k := q.NewKey
	return HostKeys().update(ctx, func(t hostKeyTx) error { return t.MarkLogin(k.Address, LoginID(h), k.key) })
}

// LoginMet reports that a person logged in to login-ask server h at addr
// with a key pinned there now: a connection there needs nobody to see a
// new key first.
func LoginMet(h *store.Host, addr string) (bool, error) {
	met := false
	err := HostKeys().view(context.Background(), func(t hostKeyTx) error {
		keys, _, err := t.Pins(addr)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if ok, err := t.LoginMet(addr, LoginID(h), k); err != nil || ok {
				met = ok
				return err
			}
		}
		return nil
	})
	return met, err
}

// MarkLoginMet pins key for addr and notes that a person logged in to
// login-ask server h there, as their first connection does (for tests,
// and for nothing an agent reaches).
func MarkLoginMet(h *store.Host, addr string, key ssh.PublicKey) error {
	return HostKeys().update(context.Background(), func(t hostKeyTx) error {
		keys, _, err := t.Pins(addr)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(keys, func(k ssh.PublicKey) bool { return SameKey(k, key) }) {
			if err := t.Add(addr, key); err != nil {
				return err
			}
		}
		return t.MarkLogin(addr, LoginID(h), key)
	})
}

// loginKnownKey is the check of a pinned key offered by login-ask server
// h: a pin alone does not let a typed password go there (anyone's
// connection to that address may have made it); a person must have
// logged in to h with it, or decide now (askLoginNewKey).
func loginKnownKey(ctx context.Context, h *store.Host, hostname string, key ssh.PublicKey, q *LoginAsk) error {
	met := false
	if err := HostKeys().view(ctx, func(t hostKeyTx) error {
		var err error
		met, err = t.LoginMet(hostname, LoginID(h), key)
		return err
	}); err != nil {
		return err
	}
	if met {
		return nil
	}
	k := keyNote(h.Name, hostname, key)
	k.NotMet = true
	if err := askLoginNewKey(ctx, h, k); err != nil {
		return &pinRefused{err}
	}
	fmt.Fprintf(hostKeyNote, "komando: first login to %s at %s with a typed password: its %s host key %s was pinned before, but nobody has logged in to %s with it\n",
		h.Name, hostname, k.Type, k.Fingerprint, h.Name)
	q.NewKey = &k
	return nil
}
