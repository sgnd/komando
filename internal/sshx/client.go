// Package sshx dials hosts from the inventory (with jump-host chains,
// keychain/agent/password auth and TOFU host-key checking) and runs commands.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

type Options struct {
	ConnectTimeout time.Duration
	HostKeyPolicy  string // accept-new | strict | off
}

// Client wraps an ssh.Client plus the chain of jump clients that must be
// closed with it.
type Client struct {
	*ssh.Client
	Host  *store.Host
	chain []*ssh.Client
}

func (c *Client) Close() error {
	err := c.Client.Close()
	for i := len(c.chain) - 1; i >= 0; i-- {
		c.chain[i].Close()
	}
	return err
}

// Dial connects to h, honouring its jump chain.
func Dial(ctx context.Context, st *store.State, h *store.Host, o Options) (*Client, error) {
	hops, err := resolveChain(st, h, map[string]bool{})
	if err != nil {
		return nil, err
	}
	var chain []*ssh.Client
	var prev *ssh.Client
	closeAll := func() {
		for i := len(chain) - 1; i >= 0; i-- {
			chain[i].Close()
		}
	}
	for i, hop := range hops {
		cfg, err := clientConfig(st, hop, o)
		if err != nil {
			closeAll()
			return nil, err
		}
		addr := net.JoinHostPort(hop.Address, strconv.Itoa(hop.EffectivePort()))
		var c *ssh.Client
		if prev == nil {
			c, err = dialDirect(ctx, addr, cfg, o.ConnectTimeout)
		} else {
			c, err = dialVia(ctx, prev, addr, cfg, o.ConnectTimeout)
		}
		if err != nil {
			closeAll()
			return nil, classify(hop.Name, err)
		}
		if i < len(hops)-1 {
			chain = append(chain, c)
		}
		prev = c
	}
	cl := &Client{Client: prev, Host: h, chain: chain}
	go keepalive(cl)
	return cl, nil
}

func keepalive(c *Client) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		if _, _, err := c.SendRequest("keepalive@komando", true, nil); err != nil {
			return
		}
	}
}

// resolveChain returns [jump1, jump2, ..., target].
func resolveChain(st *store.State, h *store.Host, seen map[string]bool) ([]*store.Host, error) {
	if seen[h.Name] {
		return nil, out.Errf(out.ExitUsage, "JUMP_CYCLE", "fix the jump setting with `komando host edit`", "jump host cycle detected at %q", h.Name)
	}
	seen[h.Name] = true
	if h.Jump == "" {
		return []*store.Host{h}, nil
	}
	var hops []*store.Host
	for _, j := range strings.Split(h.Jump, ",") {
		j = strings.TrimSpace(j)
		jh, ok := st.Hosts[j]
		if !ok {
			// allow ad-hoc user@host:port jump specs
			adhoc, err := ParseAdhoc(j)
			if err != nil {
				return nil, out.NotFound("host", j)
			}
			jh = adhoc
		}
		sub, err := resolveChain(st, jh, seen)
		if err != nil {
			return nil, err
		}
		hops = append(hops, sub...)
	}
	return append(hops, h), nil
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

func dialDirect(ctx context.Context, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return handshake(conn, addr, cfg, timeout)
}

func dialVia(ctx context.Context, via *ssh.Client, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	conn, err := via.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return handshake(conn, addr, cfg, timeout)
}

func handshake(conn net.Conn, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

func classify(host string, err error) error {
	var ke *knownhosts.KeyError
	msg := err.Error()
	switch {
	case errors.As(err, &ke) && len(ke.Want) > 0, strings.Contains(msg, "HOSTKEY_MISMATCH"):
		return out.Errf(out.ExitConnect, "HOSTKEY_MISMATCH",
			fmt.Sprintf("verify the server is legitimate, then run `komando host trust %s --reset`", host),
			"host key for %s changed: possible MITM or server rebuild", host)
	case strings.Contains(msg, "HOSTKEY_UNKNOWN"):
		return out.Errf(out.ExitConnect, "HOSTKEY_UNKNOWN",
			fmt.Sprintf("run `komando host trust %s` to pin its key (policy is strict)", host),
			"host key for %s is not trusted yet", host)
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods"):
		return out.Errf(out.ExitConnect, "AUTH_FAILED",
			"check user/key/password with `komando host show "+host+"`; deploy a key with `komando key deploy`",
			"authentication to %s failed: %s", host, msg)
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		return out.Errf(out.ExitTimeout, "CONNECT_TIMEOUT", "check network/firewall or raise --connect-timeout", "connecting to %s timed out", host)
	case strings.Contains(msg, "connection refused"):
		return out.Errf(out.ExitConnect, "CONNECTION_REFUSED", "is sshd running and the port correct?", "%s: %s", host, msg)
	case strings.Contains(msg, "no such host"):
		return out.Errf(out.ExitConnect, "DNS_ERROR", "check the host address", "%s: %s", host, msg)
	}
	return out.Errf(out.ExitConnect, "CONNECT_FAILED", "run `komando host test "+host+"` for diagnostics", "%s: %s", host, msg)
}

func clientConfig(st *store.State, h *store.Host, o Options) (*ssh.ClientConfig, error) {
	user := h.User
	if user == "" {
		user = st.Settings.DefaultUser
	}
	if user == "" {
		user = os.Getenv("USER")
	}
	auths, err := authMethods(st, h)
	if err != nil {
		return nil, err
	}
	hkc, err := hostKeyCallback(h.Name, o.HostKeyPolicy)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: hkc,
		Timeout:         o.ConnectTimeout,
	}, nil
}

func authMethods(st *store.State, h *store.Host) ([]ssh.AuthMethod, error) {
	var signers []ssh.Signer
	var methods []ssh.AuthMethod

	addKeyFile := func(path, passRef string, explicit bool) error {
		b, err := os.ReadFile(expand(path))
		if err != nil {
			if explicit {
				return out.Errf(out.ExitUsage, "KEY_UNREADABLE", "check the key path", "cannot read key %s: %v", path, err)
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
				return out.Errf(out.ExitUsage, "KEY_INVALID", "", "cannot parse key %s: %v", path, err)
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
			return nil, out.NotFound("key", h.Key)
		}
		if err := addKeyFile(k.Path, k.PassphraseRef, true); err != nil {
			return nil, err
		}
		explicitKey = true
	}
	if h.Identity != "" {
		if err := addKeyFile(h.Identity, "", true); err != nil {
			return nil, err
		}
		explicitKey = true
	}

	// ssh-agent
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			ag := agent.NewClient(conn)
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
			return methods, nil // keys are available; an unresolvable password is not fatal
		}
		if err != nil {
			return nil, out.Errf(out.ExitUsage, "SECRET_UNRESOLVED", "check `komando secret list`", "password for %s: %v", h.Name, err)
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
		return nil, out.Errf(out.ExitUsage, "NO_AUTH", "add --key, --identity or --password-ref to the host, or start ssh-agent", "no authentication method available for %s", h.Name)
	}
	return methods, nil
}

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

// ForgetHost removes known_hosts lines for addr (host:port normalised).
func ForgetHost(addr string) (int, error) {
	p := KnownHostsPath()
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	norm := knownhosts.Normalize(addr)
	var keep [][]byte
	removed := 0
	for _, line := range bytes.Split(b, []byte("\n")) {
		f := strings.Fields(string(line))
		if len(f) > 0 && hostsFieldMatches(f[0], norm) {
			removed++
			continue
		}
		if len(line) > 0 {
			keep = append(keep, line)
		}
	}
	data := bytes.Join(keep, []byte("\n"))
	if len(data) > 0 {
		data = append(data, '\n')
	}
	return removed, store.WriteFileAtomic(p, data, 0o600)
}

func hostsFieldMatches(field, norm string) bool {
	for _, h := range strings.Split(field, ",") {
		if h == norm {
			return true
		}
	}
	return false
}

// ScanHostKey fetches the server's host key without authenticating.
func ScanHostKey(ctx context.Context, addr string, timeout time.Duration) (ssh.PublicKey, error) {
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "komando-keyscan",
		Auth: []ssh.AuthMethod{ssh.Password("x")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errors.New("keyscan-done")
		},
		Timeout: timeout,
	}
	_, err := dialDirect(ctx, addr, cfg, timeout)
	if got != nil {
		return got, nil
	}
	return nil, err
}

func TrustKey(addr string, key ssh.PublicKey) error {
	khMu.Lock()
	defer khMu.Unlock()
	p := KnownHostsPath()
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		_ = os.WriteFile(p, nil, 0o600)
	}
	return appendKnownHost(p, addr, key)
}
