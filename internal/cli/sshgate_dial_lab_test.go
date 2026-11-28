package cli

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/storex"
	"github.com/sgnd/komando/internal/storex/ftptest"
)

// The lab checks of C663: a library a key's conn uses connects to each
// address a server hands back through the gate's dialer, which refuses
// one at this computer. Here with a test server: Kafka (kfake) and FTP
// (ftptest); Redis Cluster, Redis Sentinel and NATS in their own packages
// (TestRedisClusterNodesUseTheDialer, TestRedisSentinelMasterUsesTheDialer,
// TestNatsIgnoresHandedBackServers).
// Mongo, SQL Server and Oracle have no test server here: the e2e lab
// checks them.

// gateLabIP is the public address lab.example resolves to; it stands for
// the test server, which listens on loopback.
const gateLabIP = "203.0.113.77"

// gateLab logs what a library asked the gate's dialer for, what the gate
// refused, and what the gate dialed.
type gateLab struct {
	mu      sync.Mutex
	asked   []string
	refused []string
	dialed  []string
}

// newGateLab is a key's gate dialer whose network has one server,
// lab.example at gateLabIP, which is the test server on 127.0.0.1.
// answers, when given, are what lab.example resolves to in turn.
func newGateLab(t *testing.T, answers ...[]net.IP) (*gateLab, func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	if len(answers) == 0 {
		answers = [][]net.IP{ips(gateLabIP)}
	}
	gateStubInterfaces(t)
	gateStubDNS(t, map[string][][]net.IP{"lab.example": answers})
	l := &gateLab{}
	gate := gateDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
		l.mu.Lock()
		l.dialed = append(l.dialed, addr)
		l.mu.Unlock()
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host != gateLabIP {
			return nil, errors.New("the lab has no " + addr)
		}
		c, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			return nil, err
		}
		return gateLabConn{c}, nil
	})
	return l, func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := gate(ctx, network, addr)
		var e *out.Error
		l.mu.Lock()
		defer l.mu.Unlock()
		l.asked = append(l.asked, addr)
		if errors.As(err, &e) && e.Code == "SSH_GATE_REFUSED" {
			l.refused = append(l.refused, addr)
		}
		return c, err
	}
}

// gateLabConn says it is connected to gateLabIP, as a connection to the
// public server would.
type gateLabConn struct{ net.Conn }

func (c gateLabConn) RemoteAddr() net.Addr {
	a := *c.Conn.RemoteAddr().(*net.TCPAddr)
	a.IP = net.ParseIP(gateLabIP)
	return &a
}

// onlyLab: the gate dialed nothing but the lab server's judged address.
func (l *gateLab) onlyLab(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, a := range l.dialed {
		if h, _, _ := net.SplitHostPort(a); h != gateLabIP {
			t.Errorf("the gate dialed %s (asked %q)", a, l.asked)
		}
	}
}

// A Kafka broker hands back its listener, 127.0.0.1: the gate refuses it,
// so a key's run reaches no broker at this computer through the seed.
func TestGateLabKafka(t *testing.T) {
	c, err := kfake.NewCluster(kfake.NumBrokers(1))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	listener := c.ListenAddrs()[0]
	_, port, _ := net.SplitHostPort(listener)
	lab, dial := newGateLab(t)
	tg, err := driver.Parse("kafka://lab.example:" + port)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	q, err := queuex.Open(ctx, tg, "", dial, 3*time.Second, "komando-test")
	if err == nil {
		_, err = q.Create(ctx, queuex.TopicSpec{Topic: "orders", Partitions: 1, Replicas: 1}, false)
		q.Close()
	}
	lab.mu.Lock()
	refused := slices.Contains(lab.refused, listener)
	lab.mu.Unlock()
	if err == nil || !refused {
		t.Errorf("the broker at %s: err %v, gate refused %v", listener, err, lab.refused)
	}
	lab.onlyLab(t)
}

// ftpLab is an FTP server reached as lab.example; with pasv its EPSV answers
// 550, so the client falls back to PASV, which hands back 127.0.0.1.
func ftpLab(t *testing.T, pasv bool) driver.Target {
	t.Helper()
	s := ftptest.New(t)
	if pasv {
		s.Reply550 = "EPSV"
	}
	_, port, _ := net.SplitHostPort(s.Ln.Addr().String())
	tg := s.Target()
	tg.Address = "lab.example:" + port
	return tg
}

// An FTP data connection goes through the gate by the server's name, which
// the gate resolves and judges again: EPSV hands back only a port, and the
// library uses no PASV address (storex hides the control connection's IP).
func TestGateLabFTP(t *testing.T) {
	for _, mode := range []string{"EPSV", "PASV"} {
		t.Run(mode, func(t *testing.T) {
			tg := ftpLab(t, mode == "PASV")
			lab, dial := newGateLab(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			b, err := storex.OpenFTP(ctx, tg, "pw", dial, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if _, _, err := b.List(ctx, "", false, 10); err != nil {
				t.Fatal(err)
			}
			lab.mu.Lock()
			asked := slices.Clone(lab.asked)
			lab.mu.Unlock()
			if len(asked) < 2 || asked[0] != tg.Address || !strings.HasPrefix(asked[1], "lab.example:") || asked[1] == tg.Address {
				t.Errorf("asked the gate for %q, want the control connection, then a data connection, both by the server's name", asked)
			}
			lab.onlyLab(t)
		})
	}
}

// A data connection asks the gate for the server's name again: a name that
// answered public for the control connection and answers this computer for
// the data connection is refused.
func TestGateLabFTPRebind(t *testing.T) {
	for _, mode := range []string{"EPSV", "PASV"} {
		t.Run(mode, func(t *testing.T) {
			tg := ftpLab(t, mode == "PASV")
			lab, dial := newGateLab(t, ips(gateLabIP), ips("127.0.0.1"))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			b, err := storex.OpenFTP(ctx, tg, "pw", dial, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			_, _, err = b.List(ctx, "", false, 10)
			lab.mu.Lock()
			refused := slices.ContainsFunc(lab.refused, func(a string) bool { return strings.HasPrefix(a, "lab.example:") && a != tg.Address })
			asked := slices.Clone(lab.asked)
			lab.mu.Unlock()
			if err == nil || !refused {
				t.Errorf("list: %v; asked the gate for %q, want a data connection refused", err, asked)
			}
			lab.onlyLab(t)
		})
	}
}
