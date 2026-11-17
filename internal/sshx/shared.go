package sshx

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
)

// Servers behind the same jump hosts share one connection to them within
// one command: `exec -P 10` through a bastion logs in to the bastion once
// and opens a channel per server, so the bastion's MaxStartups and its
// login logs see one client, as with OpenSSH's ControlMaster. The shared
// path stays open a few seconds after its last server closes, for the
// next one in a fleet. Another command never uses it (ChainOwner).

type sharedChain struct {
	key     string
	clients []*ssh.Client // the jump hosts, in order
	vpn     io.Closer
	refs    int
	timer   *time.Timer
	dead    bool
}

var chains = struct {
	sync.Mutex
	m       map[string]*sharedChain
	dialing map[string]*dialLock
}{m: map[string]*sharedChain{}, dialing: map[string]*dialLock{}}

// dialLock lets one dial of a path run at a time; users counts the dials
// that hold or wait for it, and the last one takes it out of the map (each
// command has keys of its own, so the map would grow in a long-lived app).
type dialLock struct {
	sync.Mutex
	users int
}

// chainLinger is how long an unused shared path stays open.
var chainLinger = 5 * time.Second

// ChainOwner, when set, names the command a path through jump hosts is
// opened for, from the context of the Dial. A path is shared only within
// one owner: a path one command opened (a person's, who answered a login
// question or approved a VPN) never serves another command in the same
// process (an app), which may be an AI agent's or carry other approvals.
var ChainOwner func(ctx context.Context) string

// chainKey names a path: whose it is (ChainOwner), how its host keys were
// checked, its VPN and each jump host's identity. The check is part of
// it: a path dialed with --host-key-policy off (or accept-new) is never
// handed to a command that checks keys more strictly.
func chainKey(owner string, vpn *store.Vpn, hops []*store.Host, hostKeyPolicy string) string {
	var b strings.Builder
	b.WriteString("owner:" + strconv.Quote(owner) + "|")
	switch hostKeyPolicy {
	case "off", "strict":
		b.WriteString("keys:" + hostKeyPolicy + "|")
	default: // "" is the setting's default, accept-new
		b.WriteString("keys:accept-new|")
	}
	if vpn != nil {
		b.WriteString("vpn:" + vpn.Name + "|")
	}
	for _, h := range hops {
		b.WriteString(h.Name + "=" + h.User + "@" + h.Address + ":" + strconv.Itoa(h.EffectivePort()) + "|" + h.Identity + "|" + h.ProxyCommand + ">")
	}
	return b.String()
}

// acquireChain returns the open path for key, or opens it with open.
func acquireChain(key string, open func() ([]*ssh.Client, io.Closer, error)) (*sharedChain, error) {
	chains.Lock()
	mu := chains.dialing[key]
	if mu == nil {
		mu = &dialLock{}
		chains.dialing[key] = mu
	}
	mu.users++
	chains.Unlock()
	mu.Lock() // one dial per path at a time; the others wait and share it
	defer func() {
		mu.Unlock()
		chains.Lock()
		if mu.users--; mu.users == 0 {
			delete(chains.dialing, key)
		}
		chains.Unlock()
	}()
	chains.Lock()
	if c := chains.m[key]; c != nil && !c.dead {
		c.refs++
		if c.timer != nil {
			c.timer.Stop()
			c.timer = nil
		}
		chains.Unlock()
		return c, nil
	}
	chains.Unlock()
	clients, vpn, err := open()
	if err != nil {
		return nil, err
	}
	c := &sharedChain{key: key, clients: clients, vpn: vpn, refs: 1}
	chains.Lock()
	chains.m[key] = c
	chains.Unlock()
	return c, nil
}

func (c *sharedChain) last() *ssh.Client { return c.clients[len(c.clients)-1] }

// release drops one user; the last one closes the path after chainLinger
// (at once when the path broke).
func (c *sharedChain) release() {
	chains.Lock()
	defer chains.Unlock()
	c.refs--
	if c.refs > 0 {
		return
	}
	if c.dead || chainLinger <= 0 {
		c.closeLocked()
		return
	}
	c.timer = time.AfterFunc(chainLinger, func() {
		chains.Lock()
		defer chains.Unlock()
		if c.refs == 0 {
			c.closeLocked()
		}
	})
}

// broken marks the path dead: the next server opens a new one.
func (c *sharedChain) broken() {
	chains.Lock()
	c.dead = true
	if chains.m[c.key] == c {
		delete(chains.m, c.key)
	}
	chains.Unlock()
}

func (c *sharedChain) closeLocked() {
	if chains.m[c.key] == c {
		delete(chains.m, c.key)
	}
	for i := len(c.clients) - 1; i >= 0; i-- {
		c.clients[i].Close()
	}
	if c.vpn != nil {
		c.vpn.Close()
	}
}

// openFirst is how a path starts: a plain dialer, or the VPN it begins
// with, opened inside this process (its closer ends it).
func openFirst(ctx context.Context, vpn *store.Vpn, o Options) (netx.Dialer, io.Closer, error) {
	first := (&net.Dialer{Timeout: o.ConnectTimeout}).DialContext
	if vpn == nil {
		return first, nil, nil
	}
	return netx.Open(ctx, vpn, o.ConnectTimeout)
}

// openJumps logs in to the jump hosts in order, or shares the path another
// server behind the same hosts opened (one login per jump host per
// command). Jump hosts are logged in to as usual, even when only the
// target's key is fetched.
func openJumps(ctx context.Context, st *store.State, vpn *store.Vpn, jumps []*store.Host, o Options) (*sharedChain, error) {
	jo := o
	jo.scan = nil
	owner := ""
	if ChainOwner != nil {
		owner = ChainOwner(ctx)
	}
	return acquireChain(chainKey(owner, vpn, jumps, o.HostKeyPolicy), func() ([]*ssh.Client, io.Closer, error) {
		first, vpnCloser, err := openFirst(ctx, vpn, o)
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
}
