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

// Servers behind the same jump hosts share one connection to them: `exec
// -P 10` through a bastion logs in to the bastion once and opens a channel
// per server, so the bastion's MaxStartups and its login logs see one
// client, as with OpenSSH's ControlMaster. The shared path stays open a
// few seconds after its last server closes, for the next one in a fleet.

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
	dialing map[string]*sync.Mutex
}{m: map[string]*sharedChain{}, dialing: map[string]*sync.Mutex{}}

// chainLinger is how long an unused shared path stays open.
var chainLinger = 5 * time.Second

// chainKey names a path: how its host keys were checked, its VPN and
// each jump host's identity. The check is part of it: a path dialed with
// --host-key-policy off (or accept-new) is never handed to a command that
// checks keys more strictly, which may run in the same process (an app).
func chainKey(vpn *store.Vpn, hops []*store.Host, hostKeyPolicy string) string {
	var b strings.Builder
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
		mu = &sync.Mutex{}
		chains.dialing[key] = mu
	}
	chains.Unlock()
	mu.Lock() // one dial per path at a time; the others wait and share it
	defer mu.Unlock()
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
	return acquireChain(chainKey(vpn, jumps, o.HostKeyPolicy), func() ([]*ssh.Client, io.Closer, error) {
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
