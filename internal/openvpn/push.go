package openvpn

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// parsePush reads the options of a PUSH_REPLY. What it holds comes from
// the server, so every number is checked.
func (c *Client) parsePush(opts []string) Pushed {
	p := Pushed{PeerID: -1, Ping: 10 * time.Second, PingRestart: 120 * time.Second, MTU: c.cfg.TunMTU, Raw: opts}
	for _, o := range opts {
		f := strings.Fields(o)
		if len(f) == 0 {
			continue
		}
		arg := func(i int) string {
			if i < len(f) {
				return f[i]
			}
			return ""
		}
		switch f[0] {
		case "ifconfig":
			ip, err1 := netip.ParseAddr(arg(1))
			mask := net.ParseIP(arg(2))
			bits := 32
			if err1 == nil && mask != nil && mask.To4() != nil {
				ones, _ := net.IPMask(mask.To4()).Size()
				if ones > 0 {
					bits = ones
				}
			}
			if err1 == nil {
				p.Address = netip.PrefixFrom(ip, bits)
			}
		case "ifconfig-ipv6":
			if pf, err := netip.ParsePrefix(arg(1)); err == nil {
				p.Address6 = pf
			}
		case "dhcp-option":
			if strings.EqualFold(arg(1), "DNS") || strings.EqualFold(arg(1), "DNS6") {
				if a, err := netip.ParseAddr(arg(2)); err == nil {
					p.DNS = append(p.DNS, a)
				}
			}
		case "dns":
			if arg(1) == "server" && arg(3) == "address" {
				if a, err := netip.ParseAddr(arg(4)); err == nil {
					p.DNS = append(p.DNS, a)
				}
			}
		case "cipher":
			p.Cipher = strings.ToUpper(arg(1))
		case "peer-id":
			if n, err := strconv.Atoi(arg(1)); err == nil {
				p.PeerID = n
			}
		case "ping":
			if d, ok := pushedSeconds(arg(1)); ok {
				p.Ping = d
			}
		case "ping-restart":
			if d, ok := pushedSeconds(arg(1)); ok {
				p.PingRestart = d
			}
		case "key-derivation":
			p.EKM = arg(1) == "tls-ekm"
		case "tun-mtu":
			if n, err := strconv.Atoi(arg(1)); err == nil {
				p.MTU = n
			}
		}
	}
	if p.Cipher == "" {
		p.Cipher = c.cfg.Ciphers[0]
	}
	if !supportedCipher(p.Cipher) {
		c.fail(fmt.Errorf("the server chose cipher %s, which komando does not support", p.Cipher))
	}
	return p
}

// pushedSeconds reads a pushed ping or ping-restart, kept to at most a
// day: a huge number overflowed the Duration to a negative one, and the
// keepalive loop spun without waiting.
func pushedSeconds(v string) (time.Duration, bool) {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, false
	}
	return time.Duration(min(n, 24*3600)) * time.Second, true
}
