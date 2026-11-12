package cli

import (
	"context"
	"net"
	"strings"
)

// pinDial sends connections for the address from (host:port) to the
// address to, like curl --resolve: a conn URL's ?resolve=IP. Connections to
// any other address go through unchanged, so a token service or a redirect
// to another host is looked up as usual. dial is the --via path (nil: this
// computer), so with --via the last server connects to the IP. TLS and HTTP
// take the server name and the Host header from the request URL, not from
// the address dialed, so the certificate is still checked against the name.
func pinDial(dial func(ctx context.Context, network, addr string) (net.Conn, error), from, to string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if to == "" {
		return dial
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if sameAddr(addr, from) {
			addr = to
		}
		return dial(ctx, network, addr)
	}
}

// sameAddr compares two host:port addresses; host names ignore case and a
// trailing dot.
func sameAddr(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	return err1 == nil && err2 == nil && ap == bp &&
		strings.EqualFold(strings.TrimSuffix(ah, "."), strings.TrimSuffix(bh, "."))
}
