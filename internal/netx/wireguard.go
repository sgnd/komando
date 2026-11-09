package netx

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/sgnd/komando/internal/store"
)

// WGConfig is a wg-quick file ([Interface] and [Peer] sections).
type WGConfig struct {
	PrivateKey string
	Addresses  []netip.Addr
	DNS        []netip.Addr
	MTU        int
	Peers      []WGPeer
}

type WGPeer struct {
	PublicKey    string
	PresharedKey string
	Endpoint     string
	AllowedIPs   []netip.Prefix
	Keepalive    int
}

// ParseWG reads a wg-quick file. Keys stay base64, as in the file.
func ParseWG(text string) (*WGConfig, error) {
	c := &WGConfig{MTU: 1420}
	var peer *WGPeer
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			if section == "peer" {
				c.Peers = append(c.Peers, WGPeer{})
				peer = &c.Peers[len(c.Peers)-1]
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected Key = Value", n)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		list := func() []string {
			var l []string
			for _, s := range strings.Split(v, ",") {
				if s = strings.TrimSpace(s); s != "" {
					l = append(l, s)
				}
			}
			return l
		}
		switch {
		case section == "interface" && k == "privatekey":
			c.PrivateKey = v
		case section == "interface" && k == "address":
			for _, a := range list() {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					ad, err2 := netip.ParseAddr(a)
					if err2 != nil {
						return nil, fmt.Errorf("line %d: bad Address %q", n, a)
					}
					p = netip.PrefixFrom(ad, ad.BitLen())
				}
				c.Addresses = append(c.Addresses, p.Addr())
			}
		case section == "interface" && k == "dns":
			for _, a := range list() {
				if ad, err := netip.ParseAddr(a); err == nil {
					c.DNS = append(c.DNS, ad) // search domains are ignored
				}
			}
		case section == "interface" && k == "mtu":
			m, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad MTU", n)
			}
			c.MTU = m
		case section == "peer" && k == "publickey":
			peer.PublicKey = v
		case section == "peer" && k == "presharedkey":
			peer.PresharedKey = v
		case section == "peer" && k == "endpoint":
			peer.Endpoint = v
		case section == "peer" && k == "allowedips":
			for _, a := range list() {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					return nil, fmt.Errorf("line %d: bad AllowedIPs %q", n, a)
				}
				peer.AllowedIPs = append(peer.AllowedIPs, p)
			}
		case section == "peer" && k == "persistentkeepalive":
			peer.Keepalive, _ = strconv.Atoi(v)
		}
		// other keys (ListenPort, PostUp, Table, ...) do not apply to a
		// VPN that lives inside one process
	}
	if len(c.Addresses) == 0 {
		return nil, fmt.Errorf("[Interface] needs an Address")
	}
	if len(c.Peers) == 0 {
		return nil, fmt.Errorf("needs at least one [Peer]")
	}
	for i, p := range c.Peers {
		if p.PublicKey == "" || len(p.AllowedIPs) == 0 {
			return nil, fmt.Errorf("[Peer] %d needs PublicKey and AllowedIPs", i+1)
		}
	}
	return c, nil
}

// StripWGKeys removes PrivateKey and PresharedKey lines from a wg-quick
// file, returning the rest and the keys, so only the vault holds them.
// komando supports one preshared key per VPN.
func StripWGKeys(text string) (clean, private, psk string, err error) {
	c, err := ParseWG(text)
	if err != nil {
		return "", "", "", err
	}
	if c.PrivateKey == "" {
		return "", "", "", fmt.Errorf("[Interface] needs a PrivateKey")
	}
	for _, p := range c.Peers {
		if p.PresharedKey != "" {
			if psk != "" && psk != p.PresharedKey {
				return "", "", "", fmt.Errorf("different PresharedKeys per peer are not supported")
			}
			psk = p.PresharedKey
		}
	}
	var keep []string
	for _, line := range strings.Split(text, "\n") {
		k, _, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "privatekey", "presharedkey":
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n"), c.PrivateKey, psk, nil
}

func hexKey(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("not a WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

// UAPI turns the config into WireGuard's configuration protocol.
// Endpoints are resolved here, since the protocol takes IP:port.
func (c *WGConfig) UAPI() (string, error) {
	var sb strings.Builder
	k, err := hexKey(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("the WireGuard private key does not parse (%w)", err)
	}
	fmt.Fprintf(&sb, "private_key=%s\nreplace_peers=true\n", k)
	for _, p := range c.Peers {
		pk, err := hexKey(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("PublicKey: %w", err)
		}
		fmt.Fprintf(&sb, "public_key=%s\n", pk)
		if p.PresharedKey != "" {
			psk, err := hexKey(p.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("PresharedKey: %w", err)
			}
			fmt.Fprintf(&sb, "preshared_key=%s\n", psk)
		}
		if p.Endpoint != "" {
			addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return "", fmt.Errorf("peer endpoint %s: %w", p.Endpoint, err)
			}
			fmt.Fprintf(&sb, "endpoint=%s\n", addr.String())
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&sb, "allowed_ip=%s\n", a.String())
		}
	}
	return sb.String(), nil
}

type wgCloser struct{ dev *device.Device }

func (w wgCloser) Close() error { w.dev.Close(); return nil }

// StartWG brings up a userspace WireGuard device for c and returns a
// dialer into its network.
func StartWG(c *WGConfig) (Dialer, io.Closer, error) {
	uapi, err := c.UAPI()
	if err != nil {
		return nil, nil, err
	}
	tunDev, tnet, err := netstack.CreateNetTUN(c.Addresses, c.DNS, c.MTU)
	if err != nil {
		return nil, nil, err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, err
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return tnet.DialContext(ctx, network, addr)
	}, wgCloser{dev}, nil
}

func openWireGuard(v *store.Vpn) (Dialer, io.Closer, error) {
	c, err := ParseWG(v.Config)
	if err != nil {
		return nil, nil, configErr(v, err)
	}
	if c.PrivateKey, err = secret(v, v.KeyRef); err != nil {
		return nil, nil, err
	}
	if v.PSKRef != "" {
		psk, err := secret(v, v.PSKRef)
		if err != nil {
			return nil, nil, err
		}
		for i := range c.Peers {
			c.Peers[i].PresharedKey = psk
		}
	}
	d, closer, err := StartWG(c)
	if err != nil {
		return nil, nil, configErr(v, err)
	}
	endpoint := ""
	if len(c.Peers) > 0 {
		endpoint = c.Peers[0].Endpoint
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		start := time.Now()
		cn, err := d(ctx, network, addr)
		if err != nil {
			return nil, Down(v, wgDialErr(err, addr, endpoint, time.Since(start)))
		}
		return cn, nil
	}, closer, nil
}

// wgDialErr explains a timeout: through WireGuard, no answer almost always
// means no handshake with the peer (wrong endpoint, keys or firewall).
func wgDialErr(err error, addr, endpoint string, waited time.Duration) error {
	msg := err.Error()
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) &&
		!strings.Contains(msg, "deadline exceeded") && !strings.Contains(msg, "timed out") && !strings.Contains(msg, "i/o timeout") {
		return err
	}
	peer := "the peer"
	if endpoint != "" {
		peer = endpoint
	}
	return fmt.Errorf("no answer from %s within %s: no WireGuard handshake from %s; check its endpoint, its public key and that UDP gets through", addr, waited.Round(time.Second), peer)
}
