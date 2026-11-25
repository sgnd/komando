package inventory

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

// NormAddr is a host name the way DNS compares it: lower case, without the
// root dot ("Target." is "target") or IPv6 brackets.
func NormAddr(a string) string {
	a = strings.TrimSpace(a)
	a = strings.TrimSuffix(strings.TrimPrefix(a, "["), "]")
	return strings.TrimSuffix(strings.ToLower(a), ".")
}

// LookupHost is the resolver (tests replace it).
var LookupHost = net.DefaultResolver.LookupHost

// LookupIPs resolves a name with a short timeout; an IP is itself.
func LookupIPs(ctx context.Context, host string) []string {
	host = NormAddr(host)
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	addrs, err := LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	return addrs
}

// ConnAddrKey is what makes two conns the same resource (as in
// protectedConn): the file, the bucket, or the family and address.
func ConnAddrKey(c *store.Conn) string {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return ""
	}
	switch {
	case t.Kind.File:
		return "file " + t.Path
	case t.Bucket != "":
		return "bucket " + invHostPort(t.Address) + "/" + t.Bucket
	}
	return t.Kind.Family + " " + invHostPort(t.Address)
}

func invHostPort(a string) string {
	h, p, err := net.SplitHostPort(a)
	if err != nil {
		return NormAddr(a)
	}
	return net.JoinHostPort(NormAddr(h), p)
}

func ExpandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}
