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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

type Options struct {
	ConnectTimeout time.Duration
	HostKeyPolicy  string // accept-new | strict | off

	scan *ssh.PublicKey // FetchHostKey: record the target's key, do not log in
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
}

func (c *Client) Close() error {
	err := c.Client.Close()
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
	vpn, hops, err := resolveChain(st, h, map[string]bool{})
	if err != nil {
		return nil, err
	}
	target := hops[len(hops)-1]
	jumps := hops[:len(hops)-1]
	jo := o // jump hosts are logged in to as usual, even when only the target's key is fetched
	jo.scan = nil
	openVPN := func() (netx.Dialer, io.Closer, error) {
		first := (&net.Dialer{Timeout: o.ConnectTimeout}).DialContext
		if vpn == nil {
			return first, nil, nil
		}
		d, c, err := netx.Open(ctx, vpn, o.ConnectTimeout)
		if err != nil {
			return nil, nil, err
		}
		return d, c, nil
	}
	if len(jumps) == 0 {
		first, vpnCloser, err := openVPN()
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
	key := chainKey(vpn, jumps)
	for attempt := 0; ; attempt++ {
		sc, err := acquireChain(key, func() ([]*ssh.Client, io.Closer, error) {
			first, vpnCloser, err := openVPN()
			if err != nil {
				return nil, nil, err
			}
			var chain []*ssh.Client
			closeAll := func() {
				for i := len(chain) - 1; i >= 0; i-- {
					chain[i].Close()
				}
				if vpnCloser != nil {
					vpnCloser.Close()
				}
			}
			var prev *ssh.Client
			for _, hop := range jumps {
				c, err := dialHop(ctx, st, hop, jo, first, prev, vpn != nil || prev != nil)
				if err != nil {
					closeAll()
					return nil, nil, err
				}
				chain = append(chain, c)
				prev = c
			}
			go keepaliveChain(chain[0])
			return chain, vpnCloser, nil
		})
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
	cfg, agentConn, err := clientConfig(st, hop, o)
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
		return nil, out.Errf(out.ExitUsage, "PROXY_NOT_FIRST", "a proxy command can only start a path; put that host first in --via",
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
			ce := classify(hop.Name, err)
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
		return nil, classify(hop.Name, err)
	}
	return c, nil
}

// keepaliveEvery is how often an open connection is asked for a sign of
// life, and how long the answer may take.
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
		return nil, nil, out.Errf(out.ExitError, "VIA_CYCLE", "fix the --via setting with `komando host edit`", "--via cycle detected at %q", h.Name)
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
		return nil, fmt.Errorf("invalid host spec")
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

// HostKeyMismatch is the error for a server whose key is not the pinned
// one. An AI agent must not re-trust the key itself: it reports it, and a
// person checks the new fingerprint another way first.
func HostKeyMismatch(host string) *out.Error {
	return out.Errf(out.ExitConnect, "HOSTKEY_MISMATCH",
		fmt.Sprintf("possible man-in-the-middle: report this to the user and do not re-trust the key yourself; once they have checked the new fingerprint another way, they can run `komando host trust %s --reset`", host),
		"host key for %s changed: possible MITM or server rebuild", host)
}

func classify(host string, err error) *out.Error {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe // already a komando error (VPN_DOWN from a VPN on the way): keep its code and words
	}
	var ke *knownhosts.KeyError
	msg := err.Error()
	switch {
	case errors.As(err, &ke) && len(ke.Want) > 0, strings.Contains(msg, "HOSTKEY_MISMATCH"):
		return HostKeyMismatch(host)
	case strings.Contains(msg, "HOSTKEY_UNKNOWN"):
		return out.Errf(out.ExitConnect, "HOSTKEY_UNKNOWN",
			fmt.Sprintf("run `komando host trust %s` to pin its key (policy is strict)", host),
			"host key for %s is not trusted yet", host)
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods"):
		hint := "check user/key/password with `komando host show " + host + "`; deploy a key with `komando key deploy`"
		if strings.ContainsAny(host, "@:") { // an ad-hoc user@address target, not in the inventory
			hint = "check the user, and that ssh-agent or ~/.ssh holds a key the server accepts; save it with `komando host add NAME " + host + " --key KEY` (or --password-ref) to log in another way"
		}
		return out.Errf(out.ExitConnect, "AUTH_FAILED", hint, "authentication to %s failed: %s", host, msg)
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		return out.Errf(out.ExitTimeout, "CONNECT_TIMEOUT", "check network/firewall or raise --connect-timeout", "connecting to %s timed out", host)
	case strings.Contains(msg, "connection refused"):
		return out.Errf(out.ExitConnect, "CONNECTION_REFUSED", "is sshd running and the port correct?", "%s: %s", host, msg)
	case strings.Contains(msg, "no such host"):
		return out.Errf(out.ExitConnect, "DNS_ERROR", "check the host address", "%s: %s", host, msg)
	}
	return out.Errf(out.ExitConnect, "CONNECT_FAILED", "run `komando host test "+host+"` for diagnostics", "%s: %s", host, msg)
}

// clientConfig is the login for one hop. The ssh-agent connection it opens
// (or nil) is the caller's to close once the handshake is over.
func clientConfig(st *store.State, h *store.Host, o Options) (*ssh.ClientConfig, io.Closer, error) {
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
	hkc, err := hostKeyCallback(h.Name, o.HostKeyPolicy)
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

// authMethods also returns the ssh-agent connection it opened (or nil).
func authMethods(st *store.State, h *store.Host, timeout time.Duration) (methods []ssh.AuthMethod, agentConn io.Closer, err error) {
	defer func() {
		if err != nil && agentConn != nil {
			agentConn.Close()
			agentConn = nil
		}
	}()
	var signers []ssh.Signer

	addKeyFile := func(path, passRef string, explicit bool) error {
		b, err := os.ReadFile(expand(path))
		if err != nil {
			if explicit {
				return out.Errf(out.ExitConnect, "KEY_UNREADABLE", "check the key path", "cannot read key %s: %v", path, err)
			}
			return nil
		}
		s, err := ssh.ParsePrivateKey(b)
		var pme *ssh.PassphraseMissingError
		if errors.As(err, &pme) {
			if passRef == "" {
				if explicit {
					return out.Errf(out.ExitUsage, "KEY_PASSPHRASE_REQUIRED", "set it with `komando key edit <name> --passphrase-ref secret:NAME`", "key %s is encrypted", path)
				}
				return nil
			}
			pass, perr := vault.Resolve(passRef)
			if perr != nil {
				return perr
			}
			s, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(pass))
		}
		if err != nil {
			if explicit {
				return out.Errf(out.ExitUsage, "KEY_INVALID", "check that "+path+" is a private key in OpenSSH or PEM format, and that its passphrase ref is right", "cannot parse key %s: %v", path, err)
			}
			return nil
		}
		signers = append(signers, s)
		return nil
	}

	explicitKey := false
	if h.Key != "" {
		k, ok := st.Keys[h.Key]
		if !ok {
			return nil, nil, out.NotFound("key", h.Key)
		}
		if err := addKeyFile(k.Path, k.PassphraseRef, true); err != nil {
			return nil, nil, err
		}
		explicitKey = true
	}
	if h.Identity != "" {
		if err := addKeyFile(h.Identity, "", true); err != nil {
			return nil, nil, err
		}
		explicitKey = true
	}

	// ssh-agent
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			agentConn = conn
			var ac io.ReadWriter = conn
			if timeout > 0 {
				// the agent answers now and signs during the handshake: a stuck
				// agent must not hang the command. Each request gets its own
				// deadline, so a slow transport (SSM, a proxy command) opened
				// between the two does not use the agent's time up.
				ac = &agentDeadline{conn: conn, timeout: timeout}
			}
			ag := agent.NewClient(ac)
			if as, err := ag.Signers(); err == nil {
				signers = append(signers, as...)
			}
		}
	}
	if !explicitKey {
		home, _ := os.UserHomeDir()
		for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			_ = addKeyFile(filepath.Join(home, ".ssh", n), "", false)
		}
	}
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	if h.PasswordRef != "" {
		pw, err := vault.Resolve(h.PasswordRef)
		if err != nil && len(methods) > 0 {
			return methods, agentConn, nil // keys are available; an unresolvable password is not fatal
		}
		if err != nil {
			return nil, agentConn, out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", "check `komando secret list`", "password for %s: %v", h.Name, err)
		}
		methods = append(methods, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range qs {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	if len(methods) == 0 {
		return nil, agentConn, out.Errf(out.ExitConnect, "NO_AUTH", "add --key, --identity or --password-ref to the host, or start ssh-agent", "no authentication method available for %s", h.Name)
	}
	return methods, agentConn, nil
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
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

var khMu sync.Mutex

func KnownHostsPath() string { return store.Path("known_hosts") }

func hostKeyCallback(name, policy string) (ssh.HostKeyCallback, error) {
	if policy == "off" {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	p := KnownHostsPath()
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			return nil, err
		}
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		khMu.Lock()
		defer khMu.Unlock()
		cb, err := knownhosts.New(p)
		if err != nil {
			return err
		}
		err = cb(hostname, remote, key)
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 {
			if policy == "strict" {
				return errors.New("HOSTKEY_UNKNOWN")
			}
			return appendKnownHost(p, hostname, key)
		}
		if errors.As(err, &ke) {
			return fmt.Errorf("HOSTKEY_MISMATCH: %w", err)
		}
		return err
	}, nil
}

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key))
	return err
}

// knownHostsLines splits known_hosts into the lines that pin addr (host:port
// normalised) and the rest, and returns the keys of the first kind.
func knownHostsLines(p, addr string) (pins []ssh.PublicKey, matched int, keep [][]byte, err error) {
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil, nil
		}
		return nil, 0, nil, err
	}
	norm := knownhosts.Normalize(addr)
	for _, line := range bytes.Split(b, []byte("\n")) {
		f := strings.Fields(string(line))
		if len(f) > 0 && hostsFieldMatches(f[0], norm) {
			matched++
			if _, _, k, _, _, err := ssh.ParseKnownHosts(line); err == nil {
				pins = append(pins, k)
			}
			continue
		}
		if len(line) > 0 {
			keep = append(keep, line)
		}
	}
	return pins, matched, keep, nil
}

func hostsFieldMatches(field, norm string) bool {
	for _, h := range strings.Split(field, ",") {
		if h == norm {
			return true
		}
	}
	return false
}

// SameKey reports whether a and b are the same public key.
func SameKey(a, b ssh.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(a.Marshal(), b.Marshal())
}

// PinnedKeys are the keys komando's known_hosts pins for addr (host:port).
func PinnedKeys(addr string) ([]ssh.PublicKey, error) {
	khMu.Lock()
	defer khMu.Unlock()
	pins, _, _, err := knownHostsLines(KnownHostsPath(), addr)
	return pins, err
}

// PinHostKey pins key for addr (host:port). A key that is pinned already is
// not written again. With replace, every other line for addr goes in the
// same write, so a failure never leaves the server unpinned; removed is how
// many lines went. Whether a pin may be replaced is the caller's decision
// (`host trust --reset` needs a person's yes).
func PinHostKey(addr string, key ssh.PublicKey, replace bool) (removed int, err error) {
	khMu.Lock()
	defer khMu.Unlock()
	p := KnownHostsPath()
	pins, matched, keep, err := knownHostsLines(p, addr)
	if err != nil {
		return 0, err
	}
	have := false
	for _, k := range pins {
		have = have || SameKey(k, key)
	}
	if !replace {
		if have {
			return 0, nil
		}
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				return 0, err
			}
		}
		return 0, appendKnownHost(p, addr, key)
	}
	keep = append(keep, []byte(knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)))
	data := append(bytes.Join(keep, []byte("\n")), '\n')
	removed = matched
	if have {
		removed-- // the same key, written again
	}
	return removed, store.WriteFileAtomic(p, data, 0o600)
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
// installed (before, the host could not be reached at all), or when
// KOMANDO_EXPERIMENTAL names ssm. With both installed they still do it.
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
