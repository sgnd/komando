package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Tunnel specs (-L, -R, -D), where a tunnel may listen, and whether its
// background process still runs.

// tunnelAlive reports whether t's background process still runs, and is
// komando: after a crash or a restart its pid may belong to another
// program, which tunnel stop must never signal.
func tunnelAlive(t *store.Tunnel) bool {
	return alive(t.PID) && netx.SessionAlive(&store.VpnSession{PID: t.PID, Exe: tunnelExe()})
}

// tunnelExe is the program name tunnel processes run as: this komando's
// (they are started from os.Executable).
var tunnelExe = func() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Base(self)
}

type tunnelSpec struct {
	Kind       string
	BindAddr   string
	TargetAddr string
}

// guardBind asks for --yes before a tunnel listens on anything but this
// computer's loopback (or, for -R, the server's): other machines on the
// network could then use it, without a login (docs/design/network.md).
func guardBind(t tunnelSpec) error {
	host, _, err := net.SplitHostPort(t.BindAddr)
	if err != nil || host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if yesOK() {
		return nil
	}
	where := "this computer"
	if t.Kind == "remote" {
		where = "the server"
	}
	return policyStop(approvalErr("OPEN_BIND",
		fmt.Sprintf("the tunnel would listen on %s of %s, open to its network (the default 127.0.0.1 keeps it to that computer)", host, where)))
}

func portInUse(addr, where string, err error) error {
	return out.Errf(out.ExitConflict, "PORT_IN_USE", "pick another port, or 0 for a free one",
		"%s on %s is already in use (%v)", addr, where, err)
}

// specParts splits a forward spec at its colons, keeping an IPv6 address
// in brackets as one part without them (8080:[::1]:80, as ssh takes it).
func specParts(spec string) ([]string, bool) {
	var parts []string
	for spec != "" {
		var p string
		if strings.HasPrefix(spec, "[") {
			end := strings.Index(spec, "]")
			if end < 0 || (end+1 < len(spec) && spec[end+1] != ':') {
				return nil, false
			}
			p, spec = spec[1:end], spec[end+1:]
		} else if i := strings.IndexByte(spec, ':'); i >= 0 {
			p, spec = spec[:i], spec[i:]
		} else {
			p, spec = spec, ""
		}
		if strings.ContainsAny(p, "[]") {
			return nil, false
		}
		parts = append(parts, p)
		if rest, ok := strings.CutPrefix(spec, ":"); ok {
			spec = rest
			if spec == "" {
				parts = append(parts, "")
			}
		}
	}
	return parts, true
}

func parseTunnel(kind, spec string) (tunnelSpec, error) {
	parts, ok := specParts(spec)
	if !ok {
		parts = nil // reported below as an invalid spec
	}
	t := tunnelSpec{Kind: kind}
	switch kind {
	case "local", "remote":
		switch len(parts) {
		case 3:
			t.BindAddr = "127.0.0.1:" + parts[0]
			t.TargetAddr = net.JoinHostPort(parts[1], parts[2])
		case 4:
			t.BindAddr = net.JoinHostPort(parts[0], parts[1])
			t.TargetAddr = net.JoinHostPort(parts[2], parts[3])
		default:
			return t, out.Usage("invalid forward spec %q: use PORT:HOST:HOSTPORT or ADDRESS:PORT:HOST:HOSTPORT", spec)
		}
	case "dynamic":
		switch len(parts) {
		case 1:
			t.BindAddr = "127.0.0.1:" + parts[0]
		case 2:
			t.BindAddr = net.JoinHostPort(parts[0], parts[1])
		default:
			return t, out.Usage("invalid SOCKS spec %q: use PORT or ADDRESS:PORT", spec)
		}
	}
	if _, p, _ := net.SplitHostPort(t.BindAddr); !tunnelPort(p, 0) {
		return t, out.Usage("%q in %q is not a port: use 0 (a free one) to 65535", p, spec)
	}
	if t.TargetAddr != "" {
		if _, p, _ := net.SplitHostPort(t.TargetAddr); !tunnelPort(p, 1) {
			return t, out.Usage("%q in %q is not a port: use 1 to 65535", p, spec)
		}
	}
	return t, nil
}
