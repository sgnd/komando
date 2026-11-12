// Package openvpn is komando's own OpenVPN client: the control channel
// (TLS over OpenVPN's reliable transport, with tls-auth or tls-crypt), the
// key exchange (key-method 2, TLS-EKM or the OpenVPN PRF), the data channel
// (AES-GCM, ChaCha20-Poly1305, or AES-CBC with HMAC) and the pushed
// options. It hands IP packets to a userspace network stack, so the
// computer's own network is never changed and no admin rights are needed.
//
// It is written from the OpenVPN protocol documentation; no OpenVPN code
// is used. Options it does not implement are refused by name at Parse, so
// a profile never half works.
package openvpn

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Remote is one server to try.
type Remote struct {
	Host, Port, Proto string // proto: udp or tcp
}

// Config is what komando uses from a .ovpn profile.
type Config struct {
	Remotes        []Remote
	CA, Cert, Key  []byte // PEM
	TLSAuth        []byte // the 256-byte static key
	KeyDirection   int    // -1 none, 0 or 1 (tls-auth)
	TLSCrypt       []byte // the 256-byte static key
	Ciphers        []string
	Auth           string // digest for tls-auth and CBC: SHA1, SHA256, SHA512
	AuthUserPass   bool
	RemoteCertTLS  bool // the server's certificate must be for a TLS server
	NSCertServer   bool // ns-cert-type server: the Netscape cert type must say SSL server
	RemoteCertEKU  string
	RemoteCertKU   []uint16 // OpenSSL bit order; not nil: the key usage must hold all bits of one (none listed: any)
	VerifyName     string
	VerifyNameType string // subject (full DN), name (CN), name-prefix
	TLSMin         string
	Compress       string // "", "lzo-no" (comp-lzo no), "stub-v2" (compress stub-v2)
	Setenv         map[string]string
	TunMTU         int
	// Warnings are things in the profile a person should know about (no
	// secrets); the caller shows them.
	Warnings []string
}

// ignored directives change nothing for komando: it never touches the
// computer's network, runs no scripts and keeps the session in memory.
var ignored = map[string]bool{
	"client": true, "dev": true, "nobind": true, "persist-key": true, "persist-tun": true, "pull": true, "verb": true,
	"mute": true, "resolv-retry": true, "auth-nocache": true, "script-security": true, "up": true, "down": true,
	"route-up": true, "route-pre-down": true, "ipchange": true, "redirect-gateway": true, "route": true, "route-ipv6": true,
	"dhcp-option": true, "mssfix": true, "explicit-exit-notify": true, "remote-random": true, "float": true,
	"mute-replay-warnings": true, "route-delay": true, "route-method": true, "block-outside-dns": true, "user": true,
	"group": true, "chroot": true, "daemon": true, "log": true, "log-append": true, "status": true, "connect-retry": true,
	"connect-retry-max": true, "server-poll-timeout": true, "hand-window": true, "tran-window": true, "push-peer-info": true,
	"tls-client": true, "auth-retry": true, "pull-filter": true, "ignore-unknown-option": true,
	"key-method": true, "sndbuf": true, "rcvbuf": true, "fast-io": true, "txqueuelen": true, "tun-mtu-extra": true,
	"allow-compression": true, "tls-cipher": true, "tls-ciphersuites": true, "tls-groups": true, "reneg-sec": true,
	"ping": true, "ping-restart": true, "ping-exit": true, "keepalive": true, "inactive": true,
	"tls-timeout": true, "dev-type": true, "topology": true, "route-nopull": true,
	"setenv-safe": true, "static-challenge": true, "data-ciphers-fallback": true, "ncp-disable": true, "ncp-ciphers": true,
	"tls-version-max": true, "auth-token-user": true, "machine-readable-output": true, "windows-driver": true,
	"disable-dco": true, "lport": true, "rport": true, "bind": true, "management": true, "management-query-passwords": true,
	"management-hold": true, "redirect-private": true, "ip-win32": true, "register-dns": true, "dhcp-renew": true,
	"dhcp-release": true, "pkcs11-providers": true, "cryptoapicert": true, "proto-force": true, "allow-recursive-routing": true,
}

// Parse reads a .ovpn profile with its inline <ca>, <cert>, <key>,
// <tls-auth> and <tls-crypt> blocks.
func Parse(text string) (*Config, error) {
	c := &Config{KeyDirection: -1, Auth: "SHA1", Setenv: map[string]string{}, TunMTU: 1500}
	proto := "udp"
	port := "1194"
	var remotes [][]string
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	var block string
	var body strings.Builder
	for line := 1; sc.Scan(); line++ {
		raw := strings.TrimSpace(sc.Text())
		if block != "" {
			if strings.EqualFold(raw, "</"+block+">") {
				if err := c.setBlock(block, body.String()); err != nil {
					return nil, err
				}
				block = ""
				body.Reset()
				continue
			}
			body.WriteString(raw + "\n")
			continue
		}
		if raw == "" || raw[0] == '#' || raw[0] == ';' {
			continue
		}
		if strings.HasPrefix(raw, "<") && strings.HasSuffix(raw, ">") && !strings.HasPrefix(raw, "</") {
			block = strings.ToLower(raw[1 : len(raw)-1])
			continue
		}
		f := fields(raw)
		name := strings.ToLower(strings.TrimPrefix(f[0], "--"))
		args := f[1:]
		arg := func(i int) string {
			if i < len(args) {
				return args[i]
			}
			return ""
		}
		switch name {
		case "remote":
			remotes = append(remotes, args)
		case "proto":
			proto = arg(0)
		case "port":
			port = arg(0)
		case "ca", "cert", "key", "tls-auth", "tls-crypt":
			if arg(0) != "[inline]" && arg(0) != "" {
				return nil, fmt.Errorf("line %d: %s %s points at a file; put it inline in the profile (<%s>...</%s>)", line, name, arg(0), name, name)
			}
			if name == "tls-auth" && arg(1) != "" {
				d, err := strconv.Atoi(arg(1))
				if err != nil || d < 0 || d > 1 {
					return nil, fmt.Errorf("line %d: the tls-auth direction is 0 or 1", line)
				}
				c.KeyDirection = d
			}
		case "key-direction":
			d, err := strconv.Atoi(arg(0))
			if err != nil || d < 0 || d > 1 {
				return nil, fmt.Errorf("line %d: key-direction is 0 or 1", line)
			}
			c.KeyDirection = d
		case "cipher":
			c.Ciphers = append(c.Ciphers, strings.ToUpper(arg(0)))
		case "data-ciphers":
			c.Ciphers = nil
			for _, x := range strings.Split(arg(0), ":") {
				c.Ciphers = append(c.Ciphers, strings.ToUpper(x))
			}
		case "auth":
			c.Auth = strings.ToUpper(strings.ReplaceAll(arg(0), "-", ""))
		case "auth-user-pass":
			if arg(0) != "" {
				return nil, fmt.Errorf("line %d: auth-user-pass %s reads a file; komando takes the login from --user and --password-ref", line, arg(0))
			}
			c.AuthUserPass = true
		case "remote-cert-tls":
			if !strings.EqualFold(arg(0), "server") {
				return nil, fmt.Errorf("line %d: remote-cert-tls %s: only server makes sense for a client", line, arg(0))
			}
			c.RemoteCertTLS = true
		case "ns-cert-type":
			if !strings.EqualFold(arg(0), "server") {
				return nil, fmt.Errorf("line %d: ns-cert-type %s: only server makes sense for a client", line, arg(0))
			}
			c.NSCertServer = true
		case "remote-cert-eku":
			if ekuOID(arg(0)) == "" {
				return nil, fmt.Errorf("line %d: remote-cert-eku %q: give an OID (1.3.6.1.5.5.7.3.1) or a name such as \"TLS Web Server Authentication\"", line, arg(0))
			}
			c.RemoteCertEKU = arg(0)
		case "remote-cert-ku":
			c.RemoteCertKU = []uint16{}
			for _, a := range args {
				// OpenVPN reads these with %x, which takes a 0x prefix too
				h := strings.TrimPrefix(strings.ToLower(a), "0x")
				n, err := strconv.ParseUint(h, 16, 16)
				if err != nil || n == 0 {
					return nil, fmt.Errorf("line %d: remote-cert-ku %s: key usages are hex, such as a0", line, a)
				}
				c.RemoteCertKU = append(c.RemoteCertKU, uint16(n))
			}
		case "verify-x509-name":
			c.VerifyName, c.VerifyNameType = arg(0), strings.ToLower(arg(1))
			if c.VerifyNameType == "" {
				c.VerifyNameType = "subject"
			}
		case "tls-version-min":
			c.TLSMin = arg(0)
		case "comp-lzo":
			if strings.ToLower(arg(0)) != "no" {
				return nil, errors.New("comp-lzo compresses before encrypting, which leaks data (VORACLE); use comp-lzo no, or remove it on the server too")
			}
			c.Compress = "lzo-no"
		case "compress":
			switch strings.ToLower(arg(0)) {
			case "stub-v2":
				c.Compress = "stub-v2"
			case "", "stub":
				c.Compress = "lzo-no" // stub framing uses the same no-compress byte
			default:
				return nil, fmt.Errorf("compress %s compresses before encrypting, which leaks data (VORACLE); use compress stub-v2 or none", arg(0))
			}
		case "setenv":
			// Pritunl (UV_*) and IV_* values go to the server as peer info
			if k := arg(0); strings.HasPrefix(k, "UV_") || strings.HasPrefix(k, "IV_GUI_VER") {
				c.Setenv[k] = strings.Join(args[1:], " ")
			}
		case "tun-mtu":
			n, err := strconv.Atoi(arg(0))
			if err != nil || n < 576 || n > 9000 {
				return nil, fmt.Errorf("line %d: tun-mtu %q is not a number", line, arg(0))
			}
			c.TunMTU = n
		case "dev-node", "tls-crypt-v2", "pkcs12", "secret", "http-proxy", "socks-proxy", "fragment", "tls-server", "server",
			"mode", "askpass", "extra-certs", "tls-export-cert", "peer-fingerprint", "x509-username-field", "auth-gen-token":
			return nil, fmt.Errorf("line %d: %s is not supported by komando's OpenVPN client yet", line, name)
		default:
			if name == "dev" || ignored[name] {
				if name == "dev" && strings.HasPrefix(strings.ToLower(arg(0)), "tap") {
					return nil, errors.New("dev tap (layer 2) is not supported; komando's OpenVPN client is dev tun")
				}
				continue
			}
			return nil, fmt.Errorf("line %d: komando does not know the option %s (it refuses options it does not understand)", line, name)
		}
	}
	if block != "" {
		return nil, fmt.Errorf("<%s> is not closed", block)
	}
	for _, r := range remotes {
		if len(r) == 0 {
			continue
		}
		rm := Remote{Host: r[0], Port: port, Proto: proto}
		if len(r) > 1 {
			rm.Port = r[1]
		}
		if len(r) > 2 {
			rm.Proto = r[2]
		}
		rm.Proto = strings.ToLower(rm.Proto)
		switch {
		case strings.HasPrefix(rm.Proto, "udp"):
			rm.Proto = "udp"
		case strings.HasPrefix(rm.Proto, "tcp"):
			rm.Proto = "tcp"
		default:
			return nil, fmt.Errorf("proto %s is not supported (udp or tcp)", rm.Proto)
		}
		c.Remotes = append(c.Remotes, rm)
	}
	switch {
	case len(c.Remotes) == 0:
		return nil, errors.New("the profile has no remote")
	case c.CA == nil:
		return nil, errors.New("the profile has no <ca>")
	case (c.Cert == nil) != (c.Key == nil):
		return nil, errors.New("the profile has a <cert> without a <key>, or the other way round")
	case c.Cert == nil && !c.AuthUserPass:
		return nil, errors.New("the profile has neither a client certificate nor auth-user-pass")
	case c.TLSAuth != nil && c.TLSCrypt != nil:
		return nil, errors.New("use tls-auth or tls-crypt, not both")
	}
	if c.TLSAuth != nil && c.KeyDirection < 0 {
		c.KeyDirection = -1 // both directions use the same key
	}
	if len(c.Ciphers) == 0 {
		c.Ciphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	}
	for _, x := range c.Ciphers {
		if !supportedCipher(x) {
			return nil, fmt.Errorf("cipher %s is not supported (AES-128/256-GCM, CHACHA20-POLY1305, AES-128/256-CBC)", x)
		}
	}
	if _, ok := digests[c.Auth]; !ok && c.Auth != "NONE" {
		return nil, fmt.Errorf("auth %s is not supported (SHA1, SHA256, SHA384, SHA512)", c.Auth)
	}
	return c.withWarnings(), nil
}

func (c *Config) setBlock(name, body string) error {
	switch name {
	case "ca":
		c.CA = []byte(body)
	case "cert":
		c.Cert = []byte(body)
	case "key":
		c.Key = []byte(body)
	case "tls-auth", "tls-crypt":
		k, err := parseStaticKey(body)
		if err != nil {
			return fmt.Errorf("<%s>: %w", name, err)
		}
		if name == "tls-auth" {
			c.TLSAuth = k
		} else {
			c.TLSCrypt = k
		}
	case "tls-crypt-v2":
		return errors.New("tls-crypt-v2 is not supported by komando's OpenVPN client yet")
	case "extra-certs", "connection", "http-proxy-user-pass", "pkcs12", "secret", "dh":
		return fmt.Errorf("<%s> is not supported by komando's OpenVPN client yet", name)
	case "auth-user-pass":
		return errors.New("<auth-user-pass> in the profile: give the login with --user and --password-ref instead")
	}
	return nil
}

// parseStaticKey reads an "OpenVPN Static key V1" block (256 bytes, hex).
func parseStaticKey(s string) ([]byte, error) {
	var h strings.Builder
	in := false
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "-----BEGIN OpenVPN Static key V1-----"):
			in = true
		case strings.HasPrefix(l, "-----END OpenVPN Static key V1-----"):
			in = false
		case in && l != "" && l[0] != '#':
			h.WriteString(l)
		}
	}
	k, err := hex.DecodeString(h.String())
	if err != nil || len(k) != 256 {
		return nil, errors.New("not an OpenVPN static key (256 bytes of hex)")
	}
	return k, nil
}

// fields splits a directive line, honouring "quotes" and backslashes.
func fields(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, has := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
			has = true
		case c == '"':
			inQ, has = !inQ, true
		case (c == ' ' || c == '\t') && !inQ:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		case c == '#' && !inQ && !has:
			i = len(s)
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}
