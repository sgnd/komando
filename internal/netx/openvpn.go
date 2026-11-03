package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/sgnd/komando/internal/openvpn"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// OpenVPN (and Pritunl) run inside komando: its own OpenVPN client feeds a
// userspace network stack, so no openvpn program, Docker or admin rights
// are needed and the computer's network is not changed.

// SessionSecret is what a person gave for this session: a typed OpenVPN
// password, or the cookie of a VPN login done at the terminal. It reaches
// `komando vpn serve` on its stdin, never on a command line.
var SessionSecret string

func openOpenVPN(ctx context.Context, v *store.Vpn, timeout time.Duration) (Dialer, io.Closer, error) {
	text, err := vault.Resolve(v.ConfigRef)
	if err != nil {
		return nil, nil, configErr(v, fmt.Errorf("the profile: %v", err))
	}
	cfg, err := openvpn.Parse(text)
	if err != nil {
		return nil, nil, configErr(v, err)
	}
	login := openvpn.Login{User: v.User, Password: SessionSecret}
	if cfg.AuthUserPass && login.Password == "" {
		if v.KeyRef == "" {
			return nil, nil, LoginRequired(v)
		}
		if login.Password, err = secret(v, v.KeyRef); err != nil {
			return nil, nil, err
		}
	}
	cctx, cancel := context.WithTimeout(ctx, max(timeout, 60*time.Second))
	defer cancel()
	c, err := openvpn.Connect(cctx, cfg, login, nil)
	if err != nil {
		var ae *openvpn.AuthError
		if errors.As(err, &ae) {
			return nil, nil, Down(v, fmt.Errorf("%v (check --user and the password)", err))
		}
		return nil, nil, Down(v, err)
	}
	p := c.Pushed()
	var addrs []netip.Addr
	if p.Address.IsValid() {
		addrs = append(addrs, p.Address.Addr())
	}
	if p.Address6.IsValid() {
		addrs = append(addrs, p.Address6.Addr())
	}
	return stackDialer(v, ovpnTun{c}, addrs, p.DNS, p.MTU)
}

// ovpnTun adapts the OpenVPN client to packetTun.
type ovpnTun struct{ c *openvpn.Client }

func (o ovpnTun) WritePacket(p []byte) error { return o.c.WritePacket(p) }
func (o ovpnTun) Packets() <-chan []byte     { return o.c.Packets }
func (o ovpnTun) Done() <-chan struct{}      { return o.c.Done() }
func (o ovpnTun) Err() error                 { return o.c.Err() }
func (o ovpnTun) Close() error               { return o.c.Close() }

// packetTun is a connected VPN that carries IP packets.
type packetTun interface {
	WritePacket([]byte) error
	Packets() <-chan []byte
	Done() <-chan struct{}
	Err() error
	Close() error
}

// stackDialer puts a userspace network stack on a packet tunnel and dials
// through it.
func stackDialer(v *store.Vpn, t packetTun, addrs, dns []netip.Addr, mtu int) (Dialer, io.Closer, error) {
	if len(addrs) == 0 {
		t.Close()
		return nil, nil, Down(v, errors.New("the server gave no address"))
	}
	if mtu <= 0 || mtu > 1500 {
		mtu = 1500
	}
	dev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		t.Close()
		return nil, nil, Down(v, err)
	}
	// stack -> VPN
	go func() {
		bufs := [][]byte{make([]byte, 65536)}
		sizes := []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				t.WritePacket(append([]byte{}, bufs[i][:sizes[i]]...))
			}
		}
	}()
	// VPN -> stack
	go func() {
		for {
			select {
			case <-t.Done():
				dev.Close()
				return
			case pkt := <-t.Packets():
				dev.Write([][]byte{pkt}, 0)
			}
		}
	}()
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
			select {
			case <-t.Done():
				return nil, Down(v, fmt.Errorf("the session ended: %v", t.Err()))
			default:
			}
			return tnet.DialContext(ctx, network, addr)
		}, tunCloser{t}, nil
}

// tunCloser closes a packet tunnel and tells when it ended by itself, so
// `komando vpn serve` can stop and the session is seen as down.
type tunCloser struct{ t packetTun }

func (c tunCloser) Close() error          { return c.t.Close() }
func (c tunCloser) Done() <-chan struct{} { return c.t.Done() }
