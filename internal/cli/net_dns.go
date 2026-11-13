package cli

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sgnd/komando/internal/sshx"
)

// dnsWithoutDig answers net dns --type on a server without dig: the
// command printed the server's resolvers (/etc/resolv.conf), and komando
// asks the first one that answers over TCP through the SSH connection,
// so the answer is the server's own view of DNS. The records are written
// as dig +short writes them. When no resolver answers (none listed, or
// the server forwards no TCP), the result stays and says dig is missing.
func dnsWithoutDig(ctx context.Context, c *sshx.Client, name, typ string, rr *sshx.RunResult) *sshx.RunResult {
	if rr == nil || marker(rr.Stdout) != "no-dig" || c.Client == nil {
		return rr
	}
	qt, ok := dnsQueryType(strings.ToUpper(typ))
	if !ok {
		return rr
	}
	q := name
	if strings.ToUpper(typ) == "PTR" {
		if ip := net.ParseIP(name); ip != nil {
			q = reverseName(ip)
		}
	}
	for _, ns := range resolvConfServers(rr.Stdout) {
		recs, err := dnsAsk(ctx, func() (net.Conn, error) { return c.Dial("tcp", net.JoinHostPort(ns, "53")) }, q, qt)
		if err != nil {
			continue
		}
		out := *rr
		out.Stdout = strings.Join(recs, "\n")
		if len(recs) > 0 {
			out.Stdout += "\n"
		}
		return &out
	}
	return rr
}

// resolvConfServers are the nameserver lines the command printed.
func resolvConfServers(s string) []string {
	var ns []string
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && strings.EqualFold(f[0], "nameserver") && net.ParseIP(strings.Split(f[1], "%")[0]) != nil {
			ns = append(ns, f[1])
		}
	}
	return ns
}

func dnsQueryType(t string) (dnsmessage.Type, bool) {
	m := map[string]dnsmessage.Type{"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "CNAME": dnsmessage.TypeCNAME,
		"MX": dnsmessage.TypeMX, "NS": dnsmessage.TypeNS, "TXT": dnsmessage.TypeTXT, "SOA": dnsmessage.TypeSOA,
		"SRV": dnsmessage.TypeSRV, "PTR": dnsmessage.TypePTR, "CAA": dnsmessage.Type(257)}
	v, ok := m[t]
	return v, ok
}

// reverseName is the PTR name of ip (5.0.0.10.in-addr.arpa.).
func reverseName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
	}
	var sb strings.Builder
	for i := len(ip) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", ip[i]&0xf, ip[i]>>4)
	}
	return sb.String() + "ip6.arpa."
}

// dnsAsk sends one recursive query over a TCP connection from dial and
// returns the answer's records of type qt, as dig +short shows them.
func dnsAsk(ctx context.Context, dial func() (net.Conn, error), name string, qt dnsmessage.Type) ([]string, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	id := uint16(time.Now().UnixNano())
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: qt, Class: dnsmessage.ClassINET}}}
	b, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return nil, err
	}
	if m.Header.ID != id {
		return nil, fmt.Errorf("a DNS answer to another question")
	}
	var recs []string
	for _, a := range m.Answers {
		if a.Header.Type != qt {
			continue // the CNAME chain to an A record: dig +short -t A shows the addresses
		}
		if s := dnsShort(a.Body); s != "" {
			recs = append(recs, s)
		}
	}
	return recs, nil
}

// dnsShort is one record's data as dig +short writes it.
func dnsShort(b dnsmessage.ResourceBody) string {
	switch r := b.(type) {
	case *dnsmessage.AResource:
		return net.IP(r.A[:]).String()
	case *dnsmessage.AAAAResource:
		return net.IP(r.AAAA[:]).String()
	case *dnsmessage.CNAMEResource:
		return r.CNAME.String()
	case *dnsmessage.MXResource:
		return strconv.Itoa(int(r.Pref)) + " " + r.MX.String()
	case *dnsmessage.NSResource:
		return r.NS.String()
	case *dnsmessage.PTRResource:
		return r.PTR.String()
	case *dnsmessage.TXTResource:
		q := make([]string, len(r.TXT))
		for i, t := range r.TXT {
			q[i] = strconv.Quote(t)
		}
		return strings.Join(q, " ")
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s %s %d %d %d %d %d", r.NS, r.MBox, r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL)
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target)
	case *dnsmessage.UnknownResource:
		if r.Type == 257 && len(r.Data) >= 2 && int(r.Data[1])+2 <= len(r.Data) { // CAA: flags, tag, value
			tag := string(r.Data[2 : 2+int(r.Data[1])])
			return fmt.Sprintf("%d %s %q", r.Data[0], tag, string(r.Data[2+int(r.Data[1]):]))
		}
	}
	return ""
}
