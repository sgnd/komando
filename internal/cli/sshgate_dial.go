package cli

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
)

// gateDialFor is how a run for a gate key connects from this computer
// (sshx's first step, a conn without --via), or nil for anyone else's
// run, which dials as before.
func gateDialFor(cl *call, timeout time.Duration) netx.Dialer {
	if !cl.gated() {
		return nil
	}
	return gateDial((&net.Dialer{Timeout: timeout}).DialContext)
}

// gateDial resolves a name once, refuses the whole name when the lookup
// fails or any answer is this computer, and dials only the addresses it
// judged, in their order: DNS cannot answer the gate's check one address
// and the connection another (C655).
func gateDial(dial netx.Dialer) netx.Dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		addrs, err := gateDialAddrs(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		var errs []error
		for i, a := range addrs {
			c, err := gateDialShare(ctx, dial, network, a, len(addrs)-i)
			if err == nil {
				return c, nil
			}
			errs = append(errs, err)
		}
		return nil, errors.Join(errs...)
	}
}

// gateDialShare dials a with its share of the time left among the left
// addresses: a dead one (an IPv6 black hole) leaves the next time to answer.
func gateDialShare(ctx context.Context, dial netx.Dialer, network, a string, left int) (net.Conn, error) {
	if end, ok := ctx.Deadline(); ok && left > 1 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Until(end)/time.Duration(left))
		defer cancel() // a connection made is not tied to its dial's context
	}
	return dial(ctx, network, a)
}

// gateDialAddrs are the addresses gateDial may connect to for addr.
func gateDialAddrs(ctx context.Context, network, addr string) ([]string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
		return nil, gateDialErr("the gate connects a key only to a host and port, never to a socket on this computer")
	}
	if strings.Contains(host, "%") {
		return nil, gateDialErr("%s names a network interface; the gate connects a key only to an address without a zone", host)
	}
	if gateLocalAsWritten(host) {
		return nil, gateDialErr("%s is this computer; the gate connects a key to servers, not to this computer", host)
	}
	if net.ParseIP(host) != nil {
		return []string{addr}, nil
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := gateLookup(lctx, host)
	if err != nil || len(ips) == 0 {
		return nil, gateDialErr("the gate cannot resolve %s; a key connects only to an address it can tell is not this computer", host)
	}
	if slices.ContainsFunc(ips, gateLocalIP) {
		return nil, gateDialErr("%s is this computer; the gate connects a key to servers, not to this computer", host)
	}
	res := make([]string, len(ips))
	for i, ip := range ips {
		res[i] = net.JoinHostPort(ip.String(), port)
	}
	return res, nil
}

func gateDialErr(format string, a ...any) error {
	return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person runs it in a terminal on the komando computer itself", format, a...)
}
