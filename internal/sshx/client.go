// Package sshx dials hosts from the inventory (with jump-host chains,
// keychain/agent/password auth and TOFU host-key checking) and runs commands.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

type Options struct {
	ConnectTimeout time.Duration
	HostKeyPolicy  string // accept-new | strict | off
	// Fresh logs in anew, never through a held login (`komando login`
	// itself, which makes one)
	Fresh bool

	scan *ssh.PublicKey // FetchHostKey: record the target's key, do not log in
	// WinRM lets Dial reach a server over WinRM: the caller only runs
	// PowerShell through Run and RunPS (no SSH sessions, no tunnels)
	WinRM bool
}

// Client wraps an ssh.Client plus the path of jump hosts it came through
// (shared with other servers behind the same hosts, shared.go).
type Client struct {
	*ssh.Client
	Host  *store.Host
	chain *sharedChain
	vpn   io.Closer // a VPN this connection opened for itself (no jump hosts)
	once  sync.Once
	// silent: the keepalive got no answer and closed the connection
	silent atomic.Bool
	// Win carries the commands of a Windows server reached over WinRM;
	// such a Client has no SSH connection (Client is nil)
	Win WinShell
}

// WinShell runs one command on a Windows server over WinRM
// (internal/winrm).
type WinShell interface {
	Run(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error)
	Close() error
}

func (c *Client) Close() error {
	var err error
	if c.Client != nil {
		err = c.Client.Close()
	}
	if c.Win != nil {
		err = c.Win.Close()
	}
	c.once.Do(func() {
		if c.chain != nil {
			c.chain.release()
		}
		if c.vpn != nil {
			c.vpn.Close()
		}
	})
	return err
}

// Dial connects to h, honouring its --via chain. A chain may start with a
// VPN; it is opened inside this process. The jump hosts are shared with
// other servers behind them (one login per jump host per command).
func Dial(ctx context.Context, st *store.State, h *store.Host, o Options) (*Client, error) {
	if h.WinRM() {
		return dialWinRM(ctx, st, h, o)
	}
	if c := useHeld(ctx, st, h, o); c != nil {
		cl := &Client{Client: c, Host: h}
		go keepalive(cl)
		return cl, nil
	}
	// a fresh home makes its store (and key) before connecting: the
	// keychain may ask the person, which must not eat the connect timeout
	// while a new server's key waits to be pinned
	if o.HostKeyPolicy != "off" {
		if _, err := store.DB(true); err != nil {
			return nil, err
		}
	}
	vpn, hops, err := resolveChain(st, h, map[string]bool{})
	if err != nil {
		return nil, err
	}
	if len(hops) > 1 && HeldFor(st, hops[0]) != nil && !o.Fresh {
		vpn = nil // the first jump host's held login is past the VPN already
	}
	target := hops[len(hops)-1]
	jumps := hops[:len(hops)-1]
	if len(jumps) == 0 {
		first, vpnCloser, err := openFirst(ctx, vpn, o)
		if err != nil {
			return nil, err
		}
		c, err := dialHop(ctx, st, target, o, first, nil, vpn != nil)
		if err != nil {
			if vpnCloser != nil {
				vpnCloser.Close()
			}
			return nil, err
		}
		cl := &Client{Client: c, Host: h, vpn: vpnCloser}
		go keepalive(cl)
		return cl, nil
	}
	for attempt := 0; ; attempt++ {
		sc, err := openJumps(ctx, st, vpn, jumps, o)
		if err != nil {
			return nil, err
		}
		c, err := dialHop(ctx, st, target, o, nil, sc.last(), true)
		if err != nil {
			if attempt == 0 && pathLost(sc.last()) {
				// the shared path broke (the bastion restarted): open it again once
				sc.broken()
				sc.release()
				continue
			}
			sc.release()
			return nil, err
		}
		cl := &Client{Client: c, Host: h, chain: sc}
		go keepalive(cl)
		return cl, nil
	}
}

// useHeld is the connection through h's held login (`komando login`),
// or nil when there is none or it no longer answers.
func useHeld(ctx context.Context, st *store.State, h *store.Host, o Options) *ssh.Client {
	if o.Fresh || o.scan != nil {
		return nil
	}
	l := HeldFor(st, h)
	if l == nil {
		return nil
	}
	c, err := dialHeld(ctx, l, o.ConnectTimeout)
	if err != nil {
		return nil
	}
	return c
}

// pathLost reports a jump host connection that no longer answers.
func pathLost(c *ssh.Client) bool {
	_, _, err := c.SendRequest("keepalive@komando", true, nil)
	return err != nil
}

// keepaliveChain keeps the first jump host's connection alive while the
// path is open.
func keepaliveChain(c *ssh.Client) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		if _, _, err := c.SendRequest("keepalive@komando", true, nil); err != nil {
			return
		}
	}
}

// dialHop opens one SSH connection: through prev (a jump host), or with
// first (direct or a VPN), or with the host's own proxy (SSM, a proxy
// command), which can only start a path.
func dialHop(ctx context.Context, st *store.State, hop *store.Host, o Options, first netx.Dialer, prev *ssh.Client, reached bool) (*ssh.Client, error) {
	if hop.WinRM() {
		return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED", "take "+hop.Name+" out of the --via path: only SSH servers carry other connections",
			"%s is reached over WinRM, which cannot carry other connections", hop.Name)
	}
	if c := useHeld(ctx, st, hop, o); c != nil {
		return c, nil // a jump host a person logged in to with `komando login`
	}
	cfg, agentConn, err := clientConfig(ctx, st, hop, o)
	if err != nil {
		return nil, err
	}
	if agentConn != nil {
		// ssh-agent signs during the login only (komando forwards no agent)
		defer agentConn.Close()
	}
	addr := net.JoinHostPort(hop.Address, strconv.Itoa(hop.EffectivePort()))
	var c *ssh.Client
	switch {
	case hop.ProxyCommand != "" && reached:
		return nil, out.Errf(out.ExitUsage, "PROXY_NOT_FIRST", "a proxy command can only start a path; put that server first in --via",
			"%s has a proxy command but is reached through another hop", hop.Name)
	case builtinSSM(hop):
		// AWS Session Manager, spoken by komando itself
		sc, serr := cloud.SSMDial(ctx, os.Getenv("AWS_PROFILE"), "", hop.Address, strconv.Itoa(hop.EffectivePort()))
		if serr != nil {
			return nil, out.Errf(out.ExitConnect, "SSM_FAILED", "check the instance ID, its SSM agent and your AWS login (`komando login aws`)", "%s: %v", hop.Name, serr)
		}
		c, err = handshake(ctx, sc, addr, cfg, o.ConnectTimeout)
		if err != nil {
			sc.Close()
		}
	case hop.ProxyCommand != "":
		// the program carries the connection (aws ssm, gcloud iap, cloudflared)
		pc, perr := dialProxy(hop)
		if perr != nil {
			return nil, perr
		}
		c, err = handshake(ctx, pc, addr, cfg, o.ConnectTimeout)
		if err != nil {
			pc.Close()
			ce := classify(st, hop, err)
			if tail := pc.stderrTail(); tail != "" {
				if ce.Code != "CONNECT_FAILED" {
					// keep what went wrong (HOSTKEY_MISMATCH, AUTH_FAILED, ...):
					// the proxy's words are only extra detail
					ce.Message += "; the proxy command said: " + tail
					return nil, ce
				}
				return nil, out.Errf(out.ExitConnect, "PROXY_FAILED", "run the proxy command by hand to see why: komando host ssh-command "+hop.Name,
					"%s; the proxy command said: %s", ce.Message, tail)
			}
			return nil, ce
		}
	case prev == nil:
		c, err = dialDirect(ctx, first, addr, cfg, o.ConnectTimeout)
	default:
		c, err = dialVia(ctx, prev, addr, cfg, o.ConnectTimeout)
	}
	if err != nil {
		return nil, classify(st, hop, err)
	}
	return c, nil
}

// keepaliveNS is how often an open connection is asked for a sign of life,
// and how long the answer may take, in nanoseconds. Tests shorten it.
var keepaliveNS atomic.Int64

func init() { keepaliveNS.Store(int64(30 * time.Second)) }

func keepaliveEvery() time.Duration { return time.Duration(keepaliveNS.Load()) }

// keepalive asks the server for a sign of life now and then. A link that
// went silent (a VPN that dropped without a word) sends no error, so a
// command would wait for its exit code until --timeout: when the server
// does not answer in time the connection is closed, and the command
// running on it ends with CONNECTION_LOST.
func keepalive(c *Client) {
	every := keepaliveEvery()
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		if !answers(c.Client, every) {
			if c.silent.CompareAndSwap(false, true) {
				c.Client.Close()
			}
			return
		}
	}
}

// answers reports whether the server replies to a keepalive within wait.
func answers(c *ssh.Client, wait time.Duration) bool {
	done := make(chan error, 1)
	go func() {
		_, _, err := c.SendRequest("keepalive@komando", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(wait):
		return false
	}
}

// Route is the way to h: the VPN it starts with (or nil) and the SSH hops,
// ending with h itself. It reads the inventory only; nothing is dialed.
func Route(st *store.State, h *store.Host) (*store.Vpn, []*store.Host, error) {
	return resolveChain(st, h, map[string]bool{})
}

// resolveChain returns the VPN the path starts with (or nil) and the SSH
// hops [via1, via2, ..., target].
func resolveChain(st *store.State, h *store.Host, seen map[string]bool) (*store.Vpn, []*store.Host, error) {
	if seen[h.Name] {
		return nil, nil, out.Errf(out.ExitError, "VIA_CYCLE", "fix the path: `komando host edit "+h.Name+" --via OTHER` (or --unset via)", "--via cycle detected at %q", h.Name)
	}
	seen[h.Name] = true
	if h.Via == "" {
		return nil, []*store.Host{h}, nil
	}
	var vpn *store.Vpn
	var hops []*store.Host
	for _, j := range strings.Split(h.Via, ",") {
		j = strings.TrimSpace(j)
		if v, ok := st.Vpns[j]; ok {
			if vpn != nil || len(hops) > 0 {
				return nil, nil, out.Errf(out.ExitUsage, "VIA_ORDER", "put the VPN first: --via "+j+",bastion",
					"%s: a VPN can only be the first step of a --via path", h.Name)
			}
			vpn = v
			continue
		}
		jh, ok := st.Hosts[j]
		if !ok {
			// allow ad-hoc user@host:port jump specs
			adhoc, err := ParseAdhoc(j)
			if err != nil {
				return nil, nil, out.NotFound("host", j)
			}
			jh = adhoc
		}
		subVPN, sub, err := resolveChain(st, jh, seen)
		if err != nil {
			return nil, nil, err
		}
		if subVPN != nil {
			if vpn != nil || len(hops) > 0 {
				return nil, nil, out.Errf(out.ExitUsage, "VIA_ORDER", "a path can use one VPN, as its first step",
					"%s: the --via path reaches VPN %s after another step", h.Name, subVPN.Name)
			}
			vpn = subVPN
		}
		hops = append(hops, sub...)
	}
	return vpn, append(hops, h), nil
}

// ParseAdhoc parses user@host:port into a transient host.
func ParseAdhoc(s string) (*store.Host, error) {
	h := &store.Host{Name: s}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		h.User, s = s[:i], s[i+1:]
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		h.Address, h.Port = host, p
	} else {
		h.Address = s
	}
	if h.Address == "" || strings.ContainsAny(h.Address, " /") {
		return nil, fmt.Errorf("the server address is empty or holds a space or a slash")
	}
	return h, nil
}

func dialDirect(ctx context.Context, dial netx.Dialer, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return handshake(ctx, conn, addr, cfg, timeout)
}

func dialVia(ctx context.Context, via *ssh.Client, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	dctx := ctx
	if timeout > 0 {
		// a jump host that never answers the channel open (or waits for a
		// firewalled target's TCP timeout) must not hang the command
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	conn, err := via.DialContext(dctx, "tcp", addr)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, fmt.Errorf("opening a channel through the jump host: i/o timeout after %s", timeout)
		}
		return nil, err
	}
	return handshake(ctx, conn, addr, cfg, timeout)
}

// handshake runs the SSH handshake on conn, bounded by timeout and ctx. It
// does not rely on conn's deadlines: a connection through a jump host (an
// SSH channel) and an SSM stream have none, so a server that never answers
// would hang the command. conn is closed instead.
func handshake(ctx context.Context, conn net.Conn, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	var timedOut atomic.Bool
	stopTimer := func() bool { return true }
	if timeout > 0 {
		t := time.AfterFunc(timeout, func() { timedOut.Store(true); conn.Close() })
		stopTimer = t.Stop
	}
	stopCtx := context.AfterFunc(ctx, func() { conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	stopped := stopTimer()
	stopped = stopCtx() && stopped
	if err == nil && !stopped {
		c.Close() // the timer or ctx closed conn just as the handshake ended
		err = errors.New("connection closed")
	}
	if err != nil {
		conn.Close()
		switch {
		case timedOut.Load():
			return nil, fmt.Errorf("%w (SSH handshake: i/o timeout after %s)", err, timeout)
		case ctx.Err() != nil:
			return nil, fmt.Errorf("%w (%w)", err, ctx.Err())
		}
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// PersonAtTerminal reports whether a person at a terminal (not an AI agent
// or a script) runs komando; the cli package sets it. Only a person is
// told how to re-trust a changed host key.
var PersonAtTerminal = func() bool { return false }

// HostKeyMismatch is the error for a server whose key is not the pinned
// one: offered is the fingerprint the server shows now, pinned the ones
// komando knows (either may be empty). An AI agent must not re-trust the
// key itself: it reports it, and a person checks the new fingerprint
// another way first.
func HostKeyMismatch(host, offered string, pinned []string) *out.Error {
	msg := fmt.Sprintf("host key for %s changed: the server was rebuilt, or someone is intercepting the connection", host)
	switch {
	case offered != "" && len(pinned) > 0:
		msg += fmt.Sprintf("; pinned %s, the server now shows %s", strings.Join(pinned, ", "), offered)
	case offered != "":
		msg += "; the server now shows " + offered
	}
	hint := fmt.Sprintf("possible man-in-the-middle: report this to the user and do not re-trust the key yourself; once they have checked the new fingerprint another way, they can run `komando host trust %s --reset`", host)
	if PersonAtTerminal() {
		hint = fmt.Sprintf("if you rebuilt %s, compare this fingerprint with the one on its console, then run `komando host trust %s --reset`", host, host)
	}
	return out.Errf(out.ExitConnect, "HOSTKEY_MISMATCH", hint, "%s", msg)
}

// hostKeyChanged is the host key check's error for a key that is not the
// pinned one. It keeps the key the server offered, for the message.
type hostKeyChanged struct {
	offered ssh.PublicKey
	err     *knownhosts.KeyError
}

func (e *hostKeyChanged) Error() string { return "HOSTKEY_MISMATCH: " + e.err.Error() }
func (e *hostKeyChanged) Unwrap() error { return e.err }

func (e *hostKeyChanged) outErr(host string) *out.Error {
	var pinned []string
	for _, k := range e.err.Want {
		pinned = append(pinned, ssh.FingerprintSHA256(k.Key))
	}
	return HostKeyMismatch(host, ssh.FingerprintSHA256(e.offered), pinned)
}

func classify(st *store.State, h *store.Host, err error) *out.Error {
	host := h.Name
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe // already a komando error (VPN_DOWN from a VPN on the way): keep its code and words
	}
	var hk *hostKeyChanged
	var ke *knownhosts.KeyError
	var ua *unanswered
	var rv *knownhosts.RevokedError
	msg := err.Error()
	switch {
	case errors.As(err, &rv):
		return out.Errf(out.ExitConnect, "HOSTKEY_REVOKED",
			"this key was revoked (an @revoked line of your known_hosts, moved by `komando seal`): treat the server as compromised and tell its owner; nothing was sent",
			"%s shows the revoked host key %s", host, ssh.FingerprintSHA256(rv.Revoked.Key))
	case errors.As(err, &hk):
		return hk.outErr(host)
	case errors.As(err, &ke) && len(ke.Want) > 0, strings.Contains(msg, "HOSTKEY_MISMATCH"):
		return HostKeyMismatch(host, "", nil)
	case strings.Contains(msg, "HOSTKEY_UNKNOWN"):
		fp := ""
		if _, rest, ok := strings.Cut(msg, "HOSTKEY_UNKNOWN "); ok {
			fp, _, _ = strings.Cut(rest, " ")
		}
		what := "host key for %s is not trusted yet (host keys are strict)"
		args := []any{host}
		if fp != "" {
			what += "; it shows %s"
			args = append(args, fp)
		}
		return out.Errf(out.ExitConnect, "HOSTKEY_UNKNOWN",
			fmt.Sprintf("compare the fingerprint with what the server's owner sees, then run `komando host trust %s` (an AI agent asks the user: its pin needs their yes)", host),
			what, args...)
	case errors.As(err, &ua):
		return ua.authFailed(st, h)
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods"):
		return out.Errf(out.ExitConnect, "AUTH_FAILED", authFailedHint(st, h), "authentication to %s failed: %s", host, msg)
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		return out.Errf(out.ExitTimeout, "CONNECT_TIMEOUT", "a firewall drops the connection, or the server is private: check the address with `komando host show "+host+"`, reach it through a bastion or VPN (`komando host edit "+host+" --via NAME`), or raise --connect-timeout on a slow link", "connecting to %s timed out", host)
	case strings.Contains(msg, "connection refused"):
		return out.Errf(out.ExitConnect, "CONNECTION_REFUSED", "check that sshd runs on the server and listens on this port: `komando host show "+host+"`", "%s: %s", host, msg)
	case strings.Contains(msg, "no such host"):
		return out.Errf(out.ExitConnect, "DNS_ERROR", "the name does not resolve here: check it with `komando host show "+host+"` and fix it with `komando host edit "+host+" --address ADDRESS`; a name only a VPN resolves needs --via that VPN", "%s: %s", host, msg)
	}
	return out.Errf(out.ExitConnect, "CONNECT_FAILED", "check the address and the path with `komando host show "+host+"`; `komando doctor` checks this computer's setup", "%s: %s", host, msg)
}

// clientConfig is the login for one hop. The ssh-agent connection it opens
// (or nil) is the caller's to close once the handshake is over.
func clientConfig(ctx context.Context, st *store.State, h *store.Host, o Options) (*ssh.ClientConfig, io.Closer, error) {
	if o.scan != nil {
		// FetchHostKey: no login, so no keys, agent or vault secrets are used
		scan := o.scan
		return &ssh.ClientConfig{
			User: "komando-keyscan",
			Auth: []ssh.AuthMethod{ssh.Password("x")},
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				*scan = key
				return errKeyScanned
			},
			Timeout: o.ConnectTimeout,
		}, nil, nil
	}
	user := h.User
	if user == "" {
		user = st.Settings.DefaultUser
	}
	if user == "" {
		user = os.Getenv("USER")
	}
	hkc, err := hostKeyCallback(ctx, h.Name, o.HostKeyPolicy)
	if err != nil {
		return nil, nil, err
	}
	auths, agentConn, err := authMethods(st, h, o.ConnectTimeout)
	if err != nil {
		return nil, nil, err
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: hkc,
		Timeout:         o.ConnectTimeout,
	}, agentConn, nil
}

// NewHostKey is a host key komando pinned the first time it reached a
// server (host_key_policy accept-new). Nothing proved that key is the
// server's: the person compares the fingerprint with the server's own.
type NewHostKey struct {
	Host        string `json:"host"`
	Address     string `json:"address"`
	Type        string `json:"key_type"`
	Fingerprint string `json:"fingerprint"` // SHA256:...
}

// HostKeyPinned, when set, is told about every key pinned on first use
// (for the output and the audit log). It is called after the pin is saved,
// while the connection waits: it must be quick.
var HostKeyPinned func(NewHostKey)

// hostKeyNote is where the line about a newly pinned key goes.
var hostKeyNote io.Writer = os.Stderr

// pinnedOnFirstUse tells the person, on stderr, which key was just pinned
// and how to check it, and passes it on to HostKeyPinned.
func pinnedOnFirstUse(name, hostname string, key ssh.PublicKey) {
	k := NewHostKey{Host: name, Address: hostname, Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
	fmt.Fprintf(hostKeyNote, "komando: first connection to %s (%s): trusted its %s host key %s\n"+
		"komando: compare it with the server's own (on the server: ssh-keygen -lf /etc/ssh/ssh_host_%s_key.pub); if this key ever changes, komando refuses the server\n",
		name, hostname, k.Type, k.Fingerprint, keyFileType(k.Type))
	if HostKeyPinned != nil {
		HostKeyPinned(k)
	}
}

// keyFileType is the name part of the server's key file for a key type:
// ssh-ed25519 is in ssh_host_ed25519_key.pub.
func keyFileType(t string) string {
	switch {
	case strings.Contains(t, "ed25519"):
		return "ed25519"
	case strings.HasPrefix(t, "ecdsa"):
		return "ecdsa"
	case strings.Contains(t, "rsa"):
		return "rsa"
	}
	return "*"
}

func hostKeyCallback(ctx context.Context, name, policy string) (ssh.HostKeyCallback, error) {
	if policy == "off" {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// a known server is checked in a read step; only a new one takes
		// the write step that pins it (and checks again inside it)
		var known error
		if verr := HostKeys().view(ctx, func(t hostKeyTx) error { known = t.Check(hostname, remote, key); return nil }); verr != nil {
			return verr
		}
		var ke0 *knownhosts.KeyError
		if !errors.As(known, &ke0) || len(ke0.Want) > 0 {
			if errors.As(known, &ke0) {
				return &hostKeyChanged{offered: key, err: ke0}
			}
			return known
		}
		var err error
		pinned := false
		lockErr := HostKeys().update(ctx, func(t hostKeyTx) error {
			err = t.Check(hostname, remote, key)
			var ke *knownhosts.KeyError
			if errors.As(err, &ke) && len(ke.Want) == 0 {
				if policy == "strict" {
					err = errors.New("HOSTKEY_UNKNOWN " + ssh.FingerprintSHA256(key))
					return nil
				}
				if aerr := t.Add(hostname, key); aerr != nil {
					return aerr
				}
				err, pinned = nil, true
				return nil
			}
			if errors.As(err, &ke) {
				err = &hostKeyChanged{offered: key, err: ke}
			}
			return nil
		})
		if lockErr != nil {
			return lockErr
		}
		if pinned {
			pinnedOnFirstUse(name, hostname, key)
		}
		return err
	}, nil
}

// SameKey reports whether a and b are the same public key.
func SameKey(a, b ssh.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(a.Marshal(), b.Marshal())
}

// PinnedKeys are the keys komando pins for addr (host:port).
func PinnedKeys(addr string) ([]ssh.PublicKey, error) {
	var pins []ssh.PublicKey
	err := HostKeys().view(context.Background(), func(t hostKeyTx) error {
		var err error
		pins, _, err = t.Pins(addr)
		return err
	})
	return pins, err
}

// CountPinned is how many pins addr (host:port) has, as PinHostKey with
// replace would remove them, keys that no longer parse included.
func CountPinned(addr string) (int, error) {
	var n int
	err := HostKeys().view(context.Background(), func(t hostKeyTx) error {
		var err error
		_, n, err = t.Pins(addr)
		return err
	})
	return n, err
}

// PinHostKey pins key for addr (host:port). A key that is pinned already is
// not written again. With replace, every other pin for addr goes in the
// same write, so a failure never leaves the server unpinned; removed is how
// many pins went. Whether a pin may be replaced is the caller's decision
// (`host trust --reset` is for a person at a terminal only).
func PinHostKey(addr string, key ssh.PublicKey, replace bool) (removed int, err error) {
	err = HostKeys().update(context.Background(), func(t hostKeyTx) error {
		pins, matched, err := t.Pins(addr)
		if err != nil {
			return err
		}
		have := false
		for _, k := range pins {
			have = have || SameKey(k, key)
		}
		if !replace {
			if have {
				return nil
			}
			return t.Add(addr, key)
		}
		removed = matched
		if have {
			removed-- // the same key, written again
		}
		return t.Replace(addr, key)
	})
	return removed, err
}

var errKeyScanned = errors.New("keyscan-done")

// FetchHostKey fetches h's host key the way komando reaches h: directly,
// through a VPN, its proxy command or its --via path (those jump hosts are
// checked and logged in to as usual). h itself is not logged in to, and
// nothing is pinned for it: the caller compares and decides.
func FetchHostKey(ctx context.Context, st *store.State, h *store.Host, o Options) (ssh.PublicKey, error) {
	var got ssh.PublicKey
	o.scan = &got
	c, err := Dial(ctx, st, h, o)
	if c != nil {
		c.Close()
	}
	if got != nil {
		return got, nil
	}
	if err == nil {
		err = errors.New("the server sent no host key")
	}
	return nil, err
}

// ssmProxyPrefix is how `host add --ssm` writes its proxy command.
const ssmProxyPrefix = "aws ssm start-session --target %h --document-name AWS-StartSSHSession"

// builtinSSM reports whether komando reaches the host through Session
// Manager itself: when the aws CLI or its session-manager-plugin is not
// installed, or when KOMANDO_EXPERIMENTAL names ssm. With both installed
// they still do it.
func builtinSSM(h *store.Host) bool {
	if !strings.HasPrefix(h.ProxyCommand, ssmProxyPrefix) {
		return false
	}
	for _, k := range strings.Split(os.Getenv("KOMANDO_EXPERIMENTAL"), ",") {
		if k = strings.TrimSpace(k); k == "ssm" || k == "all" {
			return true
		}
	}
	_, e1 := exec.LookPath("aws")
	_, e2 := exec.LookPath("session-manager-plugin")
	return e1 != nil || e2 != nil
}
