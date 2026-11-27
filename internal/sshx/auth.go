package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The login one hop offers: key files, ssh-agent keys and a stored
// password, and the hints when none of them can log in.

// agentState is what SSH_AUTH_SOCK gave.
type agentState int

const (
	agentUnset   agentState = iota // SSH_AUTH_SOCK is not set
	agentDown                      // set, but no agent answers there
	agentEmpty                     // the agent holds no keys
	agentHasKeys                   // the agent holds keys
)

// lockedKey is an explicit key (--key or --identity) that is encrypted and
// has no passphrase ref. Like OpenSSH, komando then logs in with the same
// key from ssh-agent, found by its public key.
type lockedKey struct {
	path    string
	keyName string        // the keychain key (--key); "" for --identity
	pub     ssh.PublicKey // nil when unknown: not in the file, no .pub
	// sk: a security key (FIDO2: sk-ssh-ed25519, sk-ecdsa), which only
	// ssh-agent can sign with (the key asks for a touch); no passphrase helps
	sk bool
}

// loginKeys is what the key files and ssh-agent gave for one login.
type loginKeys struct {
	locked  []lockedKey
	skipped string // the first encrypted default key (~/.ssh/id_*) left out
	agent   agentState
}

// authMethods also returns the ssh-agent connection it opened (or nil).
// ctx is the Dial's: a server whose login is "ask" asks for the password
// for the command that connects (LoginPassword), with q saying where it
// goes (nil: h's own address and user).
func authMethods(ctx context.Context, st *store.State, h *store.Host, timeout time.Duration, q *LoginAsk) (methods []ssh.AuthMethod, agentConn io.Closer, err error) {
	defer func() {
		if err != nil && agentConn != nil {
			agentConn.Close()
			agentConn = nil
		}
	}()
	lk := &loginKeys{}
	var signers []ssh.Signer
	explicit := func(path, passRef string, k *store.Key) error {
		s, err := lk.keyFile(path, passRef, k, true)
		if s != nil {
			signers = append(signers, CertSigners(s, certPathFor(path, k))...)
		}
		return err
	}
	if h.Key != "" {
		k, ok := st.Keys[h.Key]
		if !ok {
			return nil, nil, out.NotFound("key", h.Key)
		}
		if err := explicit(k.Path, k.PassphraseRef, k); err != nil {
			return nil, nil, err
		}
	}
	if h.Identity != "" {
		if err := explicit(h.Identity, "", nil); err != nil {
			return nil, nil, err
		}
	}
	agentKeys, conn, state := openAgent(timeout)
	if conn != nil {
		agentConn = conn
	}
	lk.agent = state
	fromAgent, err := lk.fromAgent(st, h, agentKeys)
	if err != nil {
		return nil, agentConn, err
	}
	signers = append(signers, fromAgent...)
	if h.Key == "" && h.Identity == "" {
		home, _ := store.UserHome()
		for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			p := filepath.Join(home, ".ssh", n)
			if s, _ := lk.keyFile(p, "", nil, false); s != nil {
				signers = append(signers, CertSigners(s, p+"-cert.pub")...)
			}
		}
	}
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	if h.AskLogin() {
		// login ask: the password is never stored; a person types it
		// when the server first wants it (after the keys, as ssh does)
		if q == nil {
			lq := LoginAskFor(st, h)
			q = &lq
		}
		p := &passwordLogin{ask: personFor(h), typed: func() (string, func(), error) { return loginPassword(ctx, *q) }}
		methods = append(methods, p.methods()...)
	} else if h.PasswordRef != "" {
		pw, err := vault.Resolve(h.PasswordRef)
		if err != nil && len(methods) > 0 {
			return methods, agentConn, nil // keys are available; an unresolvable password is not fatal
		}
		if err != nil {
			return nil, agentConn, secretUnresolved(h, err)
		}
		methods = append(methods, (&passwordLogin{pw: pw, ask: personFor(h)}).methods()...)
	} else if ask := personFor(h); ask != nil {
		// no password stored: a person at the terminal types it if the
		// server wants one (after the keys, as ssh does)
		methods = append(methods, (&passwordLogin{ask: ask}).methods()...)
	}
	if len(methods) == 0 {
		return nil, agentConn, lk.noAuth(st, h)
	}
	return methods, agentConn, nil
}

// certPathFor is where a key's user certificate is: the one key add
// --cert named, else KEY-cert.pub next to a key file (as ssh looks for
// it). A key komando keeps sealed has none unless --cert named one.
func certPathFor(path string, k *store.Key) string {
	if k != nil && k.CertPath != "" {
		return k.CertPath
	}
	if strings.HasPrefix(path, "sealed:") {
		return ""
	}
	return expand(path) + "-cert.pub"
}

// CertSigners is s, after it the same key with its OpenSSH user
// certificate from certPath when there is one that belongs to s and has
// not run out: the server picks what it trusts, as with ssh (the
// certificate first). A certificate that is missing, unreadable, for
// another key or out of date is left out.
func CertSigners(s ssh.Signer, certPath string) []ssh.Signer {
	if certPath == "" {
		return []ssh.Signer{s}
	}
	b, err := os.ReadFile(expand(certPath))
	if err != nil {
		return []ssh.Signer{s}
	}
	cert, err := ParseUserCert(b, s.PublicKey())
	if err != nil || !CertCurrent(cert, time.Now()) {
		return []ssh.Signer{s}
	}
	cs, err := ssh.NewCertSigner(cert, s)
	if err != nil {
		return []ssh.Signer{s}
	}
	return []ssh.Signer{cs, s}
}

// ParseUserCert reads an OpenSSH user certificate (KEY-cert.pub) and
// checks that it is for pub.
func ParseUserCert(b []byte, pub ssh.PublicKey) (*ssh.Certificate, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, err
	}
	cert, ok := k.(*ssh.Certificate)
	switch {
	case !ok:
		return nil, errors.New("not an SSH certificate")
	case cert.CertType != ssh.UserCert:
		return nil, errors.New("a host certificate, not a user certificate")
	case pub != nil && !SameKey(cert.Key, pub):
		return nil, errors.New("the certificate is for another key")
	}
	return cert, nil
}

// CertCurrent: now lies in the certificate's valid time.
func CertCurrent(cert *ssh.Certificate, now time.Time) bool {
	u := uint64(now.Unix())
	return u >= cert.ValidAfter && (cert.ValidBefore == ssh.CertTimeInfinity || u < cert.ValidBefore)
}

// personFor is the question for the login to h, or nil when no person can
// be asked.
func personFor(h *store.Host) func(text string, hidden bool) (string, error) {
	ask := ask()
	if ask == nil {
		return nil
	}
	return func(text string, hidden bool) (string, error) { return ask(h.Name, text, hidden) }
}

// keyFile reads a private key. An encrypted key without a passphrase ref
// gives no signer: an explicit one is kept in locked (ssh-agent may hold
// it), a default one in skipped.
func (lk *loginKeys) keyFile(path, passRef string, k *store.Key, explicit bool) (ssh.Signer, error) {
	var (
		b   []byte
		err error
	)
	if k != nil {
		b, err = store.ReadPrivateKey(k)
	} else {
		b, err = os.ReadFile(expand(path))
	}
	if err != nil {
		if explicit {
			return nil, out.Errf(out.ExitConnect, "KEY_UNREADABLE", "check the key path (`komando credential key list` shows the keys komando knows)", "cannot read key %s: %v", path, err)
		}
		return nil, nil
	}
	s, err := ssh.ParsePrivateKey(b)
	var pme *ssh.PassphraseMissingError
	if errors.As(err, &pme) {
		if passRef == "" {
			switch {
			case explicit:
				name := ""
				if k != nil {
					name = k.Name
				}
				lk.locked = append(lk.locked, lockedKey{path: path, keyName: name, pub: publicPart(path, pme.PublicKey, k)})
			case lk.skipped == "":
				lk.skipped = path
			}
			return nil, nil
		}
		pass, perr := vault.Resolve(passRef)
		if perr != nil {
			return nil, perr
		}
		s, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(pass))
	}
	if err != nil {
		if pub := publicPart(path, nil, k); explicit && IsSecurityKey(pub) {
			// a FIDO2 key: ssh-agent signs with it, found by its public key
			name := ""
			if k != nil {
				name = k.Name
			}
			lk.locked = append(lk.locked, lockedKey{path: path, keyName: name, pub: pub, sk: true})
			return nil, nil
		}
		if explicit {
			return nil, out.Errf(out.ExitUsage, "KEY_INVALID", "check that "+path+" is a private key in OpenSSH or PEM format, and that its passphrase ref is right", "cannot parse key %s: %v", path, err)
		}
		return nil, nil
	}
	return s, nil
}

// IsSecurityKey: pub is a FIDO2 security key's (sk-ssh-ed25519@openssh.com,
// sk-ecdsa-sha2-nistp256@openssh.com), which only ssh-agent can sign with.
func IsSecurityKey(pub ssh.PublicKey) bool {
	return pub != nil && strings.HasPrefix(pub.Type(), "sk-")
}

// publicPart is an encrypted key's public key: from the key file itself
// (the OpenSSH format keeps it in the clear), else PATH.pub, else the
// keychain's copy.
func publicPart(path string, inFile ssh.PublicKey, k *store.Key) ssh.PublicKey {
	if inFile != nil {
		return inFile
	}
	lines := []string{}
	if b, err := os.ReadFile(expand(path) + ".pub"); err == nil {
		lines = append(lines, string(b))
	}
	if k != nil && k.PublicKey != "" {
		lines = append(lines, k.PublicKey)
	}
	for _, l := range lines {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil {
			return pub
		}
	}
	return nil
}

// openAgent reads the keys ssh-agent holds. The connection it opens (or
// nil) is the caller's to close once the handshake is over: the agent
// signs during the login.
func openAgent(timeout time.Duration) ([]ssh.Signer, net.Conn, agentState) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, agentUnset
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, agentDown
	}
	var ac io.ReadWriter = conn
	if timeout > 0 {
		// the agent answers now and signs during the handshake: a stuck
		// agent must not hang the command. Each request gets its own
		// deadline, so a slow transport (SSM, a proxy command) opened
		// between the two does not use the agent's time up.
		ac = &agentDeadline{conn: conn, timeout: timeout}
	}
	signers, err := agent.NewClient(ac).Signers()
	switch {
	case err != nil:
		return nil, conn, agentDown
	case len(signers) == 0:
		return nil, conn, agentEmpty
	}
	return signers, conn, agentHasKeys
}

// fromAgent returns the agent's keys in the order they are offered: the
// copies of the locked keys first, as OpenSSH does. A locked key the agent
// does not hold is KEY_PASSPHRASE_REQUIRED.
func (lk *loginKeys) fromAgent(st *store.State, h *store.Host, agentKeys []ssh.Signer) ([]ssh.Signer, error) {
	rest := slices.Clone(agentKeys)
	var first []ssh.Signer
	for _, k := range lk.locked {
		i := slices.IndexFunc(rest, func(s ssh.Signer) bool { return sameAgentKey(s.PublicKey(), k.pub) })
		if i < 0 {
			return nil, lk.passphraseRequired(st, h, k)
		}
		first = append(first, rest[i])
		rest = slices.Delete(rest, i, i+1)
	}
	return append(first, rest...), nil
}

// sameAgentKey matches an agent key, or the key inside its certificate.
func sameAgentKey(a, want ssh.PublicKey) bool {
	if c, ok := a.(*ssh.Certificate); ok {
		a = c.Key
	}
	return SameKey(a, want)
}

// passphraseRequired is the error for an encrypted explicit key that
// ssh-agent does not hold: load it there, or store its passphrase.
func (lk *loginKeys) passphraseRequired(st *store.State, h *store.Host, k lockedKey) *out.Error {
	p := shellPath(k.path)
	if k.sk {
		return lk.securityKeyNeeded(p)
	}
	var why, load string
	switch lk.agent {
	case agentUnset:
		why, load = "no ssh-agent runs", "start ssh-agent and load it with `ssh-add "+p+"`"
	case agentDown:
		why, load = "the ssh-agent at SSH_AUTH_SOCK does not answer", "load it with `ssh-add "+p+"` once ssh-agent answers"
	default:
		why, load = "ssh-agent does not hold it", "load it with `ssh-add "+p+"`"
	}
	hint := load + ", or " + storePassphrase(st, h, k)
	if k.pub == nil && lk.agent == agentHasKeys {
		why = "its public key is unknown (no " + filepath.Base(k.path) + ".pub next to it), so ssh-agent cannot be searched for it"
		hint = storePassphrase(st, h, k)
	}
	return out.Errf(out.ExitUsage, "KEY_PASSPHRASE_REQUIRED", hint, "key %s is encrypted and %s", p, why)
}

// securityKeyNeeded is KEY_PASSPHRASE_REQUIRED for a security key (FIDO2)
// ssh-agent does not hold: no passphrase helps, only ssh-add.
func (lk *loginKeys) securityKeyNeeded(p string) *out.Error {
	why := "ssh-agent does not hold it"
	if lk.agent == agentUnset || lk.agent == agentDown {
		why = "no ssh-agent answers"
	}
	hint := "load it into ssh-agent with `ssh-add " + p + "` (touch the key when it blinks); komando then logs in through the agent"
	return out.Errf(out.ExitUsage, "KEY_PASSPHRASE_REQUIRED", hint, "key %s is a security key (FIDO2), which only ssh-agent can use, and %s", p, why)
}

// storePassphrase says how to keep an encrypted key's passphrase in the
// vault, with commands that work for this key: a keychain key gets its
// passphrase ref, an identity file becomes a keychain key first.
func storePassphrase(st *store.State, h *store.Host, k lockedKey) string {
	if k.keyName != "" {
		sec := secretName(k.keyName, "pass")
		return fmt.Sprintf("store its passphrase: `komando credential password add %s`, then `komando credential key edit %s --passphrase-credential %s`", sec, k.keyName, sec)
	}
	name, have := keychainKeyFor(st, h, k.path)
	use := fmt.Sprintf("`komando host ssh edit %s --key %s --unset identity`", h.Name, name)
	if have != nil && have.PassphraseRef != "" {
		return "use the keychain key " + name + ", which has its passphrase: " + use
	}
	sec := secretName(name, "pass")
	if have != nil {
		return fmt.Sprintf("store its passphrase: `komando credential password add %s`, `komando credential key edit %s --passphrase-credential %s`, then %s", sec, name, sec, use)
	}
	return fmt.Sprintf("store its passphrase: `komando credential password add %s`, `komando credential key add %s %s --passphrase-credential %s`, then %s", sec, name, shellPath(k.path), sec, use)
}

// keychainKeyFor is the keychain key for the file at path: the one that
// has it already, or a free name for a new one.
func keychainKeyFor(st *store.State, h *store.Host, path string) (string, *store.Key) {
	names := make([]string, 0, len(st.Keys))
	for n := range st.Keys {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if expand(st.Keys[n].Path) == expand(path) {
			return n, st.Keys[n]
		}
	}
	name := strings.Map(func(r rune) rune {
		if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-", r)) {
			return r
		}
		return -1
	}, filepath.Base(path))
	if name == "" || len(name) > 50 || st.Keys[name] != nil {
		name = secretName(h.Name, "key")
	}
	return name, nil
}

// noAuth is NO_AUTH: nothing to log in with. The hint follows the reason:
// an encrypted default key, an empty ssh-agent, or no login at all.
func (lk *loginKeys) noAuth(st *store.State, h *store.Host) *out.Error {
	var why, hint string
	add := "`ssh-add " + shellPath(lk.skipped) + "`"
	switch {
	case lk.skipped != "" && lk.agent == agentUnset:
		why, hint = shellPath(lk.skipped)+" is encrypted and no ssh-agent runs", "start ssh-agent, then run "+add
	case lk.skipped != "" && lk.agent == agentEmpty:
		why, hint = shellPath(lk.skipped)+" is encrypted and ssh-agent holds no keys", "run "+add
	case lk.skipped != "":
		why, hint = shellPath(lk.skipped)+" is encrypted and the ssh-agent at SSH_AUTH_SOCK does not answer", "check that ssh-agent answers at SSH_AUTH_SOCK, then run "+add
	case lk.agent == agentEmpty:
		why, hint = "ssh-agent holds no keys", "run `ssh-add` (or `ssh-add PATH`) to load your key, or "+loginWay(st, h)
	case lk.agent == agentUnset:
		why, hint = "no ssh-agent runs", loginWay(st, h)+", or start ssh-agent and load your key with `ssh-add`"
	default:
		why, hint = "the ssh-agent at SSH_AUTH_SOCK does not answer", loginWay(st, h)
	}
	if lk.skipped == "" && ask() == nil && !adhoc(st, h) {
		hint += "; if only a person knows the password or code, " + PersonStep(h.Name)
	}
	return out.Errf(out.ExitConnect, "NO_AUTH", hint, "no authentication method available for %s: it has no key or password, and %s", h.Name, why)
}

// loginWay says how to give h a password (or a key) to log in with.
func loginWay(st *store.State, h *store.Host) string {
	sec := secretName(h.Name, "pass")
	switch {
	case st.Hosts[h.Name] != nil:
		return fmt.Sprintf("save its password: `komando credential password add %s`, then `komando host ssh edit %s --credential %s` (or --key KEY)", sec, h.Name, sec)
	case st.Conns[h.Name] != nil:
		return fmt.Sprintf("save its password: `komando credential password add %s`, then `komando conn edit %s --password-ref credential:%s`", sec, h.Name, sec)
	}
	return "save the server with `komando host ssh add NAME " + h.Name + " --key KEY` (or --credential NAME)"
}

// adhoc reports a server that is not in the inventory: a user@address
// target, a --via user@host step, or a conn's SFTP server.
func adhoc(st *store.State, h *store.Host) bool {
	return st == nil || st.Hosts[h.Name] == nil || strings.ContainsAny(h.Name, "@:")
}

// authFailedHint is the AUTH_FAILED hint: what to check when the server
// refused every way komando tried. It never suggests `key deploy`, which
// logs in the same way and would fail too.
func authFailedHint(st *store.State, h *store.Host) string {
	hint := authFailedCheck(st, h)
	if ask() == nil && !adhoc(st, h) {
		// no person here (an AI agent, a script): one can log in once for it
		hint += "; if only a person knows the password or code, " + PersonStep(h.Name)
	}
	return hint
}

func authFailedCheck(st *store.State, h *store.Host) string {
	name := h.Name
	switch {
	case h.AskLogin():
		return fmt.Sprintf("check the user with `komando host ssh show %s` and run the command again to type the password again; komando never stores it (login ask)", name)
	case adhoc(st, h):
		return "check the user, and that ssh-agent or ~/.ssh holds a key the server accepts; save it with `komando host ssh add NAME " + name + " --key KEY` (or --credential) to log in another way"
	case h.Key == "" && h.Identity == "" && h.PasswordRef != "":
		if sec, ok := strings.CutPrefix(h.PasswordRef, "credential:"); ok {
			return fmt.Sprintf("check the user with `komando host ssh show %s`; if the password changed, store the new one with `komando credential password add %s`", name, sec)
		}
		return fmt.Sprintf("check the user with `komando host ssh show %s`, and the password that %s holds", name, h.PasswordRef)
	case h.PasswordRef != "":
		return fmt.Sprintf("check the user, key and password with `komando host ssh show %s`; the server needs the key's public part in ~/.ssh/authorized_keys", name)
	}
	return fmt.Sprintf("check the user and key with `komando host ssh show %s`; the server needs the key's public part in ~/.ssh/authorized_keys", name)
}

// secretName is a vault or keychain name for host: "web1-pass".
func secretName(host, suffix string) string {
	if n := host + "-" + suffix; len(n) <= 63 && !strings.ContainsAny(host, "@: /") {
		return n
	}
	return "NAME"
}

// shellPath is p as a hint shows it: ~/ for the home folder, quoted when
// a shell would split it.
func shellPath(p string) string {
	prefix := ""
	if home, _ := os.UserHomeDir(); home != "" && strings.HasPrefix(p, home+string(filepath.Separator)) {
		// ~/.ssh/id_ed25519 on Windows too, as OpenSSH's own docs write it
		prefix, p = "~/", filepath.ToSlash(p[len(home)+1:])
	} else if rest, ok := strings.CutPrefix(p, "~/"); ok {
		prefix, p = "~/", rest
	}
	plain := func(r rune) bool {
		return unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-/+@=,:", r)
	}
	if strings.IndexFunc(p, func(r rune) bool { return !plain(r) }) >= 0 {
		p = Q(p)
	}
	return prefix + p
}

// Asker, when set, gives the question for the person at the terminal, or
// nil when nobody can be asked. The question asks what a login wants that
// komando cannot answer by itself: the password when none is stored, a
// one-time code (a two-factor login), or any other question the server
// asks, the way ssh does. host is the server's name in komando; text is
// the server's own words (the question makes them safe to show); hidden
// is false only when the server lets the answer show. The cli gives one
// only for a person at a terminal: AI agents, scripts and background
// processes have no one to ask, so they get NO_AUTH or AUTH_FAILED with a
// hint instead.
var Asker func() func(host, text string, hidden bool) (string, error)

// ask is the question for the person at the terminal, or nil.
func ask() func(host, text string, hidden bool) (string, error) {
	if Asker == nil {
		return nil
	}
	return Asker()
}

// agentDeadline gives every request written to the ssh-agent (and the
// answer read after it) timeout to finish. It is only a reader and writer,
// not a Closer, so the agent client sends one request at a time and no
// reader waits on the socket between requests.
type agentDeadline struct {
	conn    net.Conn
	timeout time.Duration
}

func (c *agentDeadline) Write(b []byte) (int, error) {
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))
	return c.conn.Write(b)
}

func (c *agentDeadline) Read(b []byte) (int, error) { return c.conn.Read(b) }

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := store.UserHome()
		return filepath.Join(home, p[2:])
	}
	return p
}

// secretUnresolved is the error for a password reference that cannot be
// read, with the step for its cause: the exact `secret set` for a missing
// secret, the vault's own error for a locked or broken vault, what the
// reference names otherwise.
func secretUnresolved(h *store.Host, err error) *out.Error {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe // a stop komando made (SENSITIVE_FILE): its own code and hint
	}
	switch {
	case errors.Is(err, vault.ErrNotFound):
		// the code a host's reference always gave (the contract keeps it)
		return out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", netx.SecretHint(h.PasswordRef)+" (an AI agent asks the user to run it in their own terminal)",
			"password for %s: %s is not in the vault", h.Name, h.PasswordRef)
	// the vault cannot be opened: its own codes, as every other command
	// gives them
	case errors.Is(err, vault.ErrLocked):
		return out.Errf(out.ExitError, "VAULT_LOCKED", "the person who set the passphrase exports KOMANDO_VAULT_PASS in the shell that runs komando (an AI agent asks the user; it never sees the passphrase)",
			"password for %s (%s): %v", h.Name, h.PasswordRef, err)
	case errors.Is(err, vault.ErrKey):
		return out.Errf(out.ExitError, "VAULT_KEY", "restore ~/.komando/store.key from a backup, or move the key back with `komando config vault keychain` on the computer whose keychain holds it; `komando doctor` checks the vault",
			"password for %s (%s): %v", h.Name, h.PasswordRef, err)
	case errors.Is(err, vault.ErrDecrypt):
		return out.Errf(out.ExitError, "VAULT_DECRYPT", "KOMANDO_VAULT_PASS is not the passphrase this vault was saved with: set the right one (`komando doctor` says which vault mode is in use)",
			"password for %s (%s): %v; nothing was lost", h.Name, h.PasswordRef, err)
	}
	return out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", netx.SecretHint(h.PasswordRef), "password for %s (%s): %v", h.Name, h.PasswordRef, err)
}
