package cachex

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
)

// fakeRedis speaks just enough RESP2 for `cache keys`: PING, SCAN, TYPE,
// PTTL and (as a one-node Cluster) CLUSTER SLOTS. It holds every TYPE and
// PTTL reply until it has read all of them, so a client that waits for
// each reply before sending the next one stalls and the test fails: the
// page must go in one pipeline.
type fakeRedis struct {
	ln       net.Listener
	keys     map[string][2]string // name -> {type, pttl}
	denyType bool                 // TYPE answers NOPERM, as under an ACL without it
	mu       sync.Mutex
	stalled  bool
	gets     int // GET/HGETALL/... commands: a key list never reads values
}

func newFakeRedis(t *testing.T, keys map[string][2]string) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis{ln: ln, keys: keys}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil {
		return nil, err
	}
	args := make([]string, n)
	for i := range args {
		l, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, "$")))
		b := make([]byte, size+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		args[i] = string(b[:size])
	}
	return args, nil
}

func bulk(s string) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }

func (f *fakeRedis) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	var held []string // replies to TYPE/PTTL, sent once the whole page is in
	for {
		if len(held) > 0 {
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
		} else {
			c.SetReadDeadline(time.Time{})
		}
		args, err := readCommand(r)
		if err != nil {
			if len(held) > 0 {
				f.mu.Lock()
				f.stalled = true
				f.mu.Unlock()
			}
			return
		}
		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "HELLO":
			io.WriteString(c, "-ERR unknown command 'HELLO'\r\n")
		case "PING":
			io.WriteString(c, "+PONG\r\n")
		case "CLUSTER":
			_, port, _ := net.SplitHostPort(f.ln.Addr().String())
			fmt.Fprintf(c, "*1\r\n*3\r\n:0\r\n:16383\r\n*2\r\n%s:%s\r\n", bulk("127.0.0.1"), port)
		case "SCAN":
			var b strings.Builder
			for k := range f.keys {
				b.WriteString(bulk(k))
			}
			fmt.Fprintf(c, "*2\r\n%s*%d\r\n%s", bulk("0"), len(f.keys), b.String())
		case "TYPE", "PTTL":
			k := f.keys[args[1]]
			switch {
			case cmd == "TYPE" && f.denyType:
				held = append(held, "-NOPERM this user has no permissions to run the 'type' command\r\n")
			case cmd == "TYPE" && k[0] == "":
				held = append(held, "+none\r\n")
			case cmd == "TYPE":
				held = append(held, "+"+k[0]+"\r\n")
			case k[1] == "":
				held = append(held, ":-2\r\n")
			default:
				held = append(held, ":"+k[1]+"\r\n")
			}
			if len(held) == 2*len(f.keys) {
				io.WriteString(c, strings.Join(held, ""))
				held = nil
			}
		case "GET", "HGETALL", "LRANGE", "SMEMBERS", "ZRANGE", "XRANGE", "DUMP":
			f.mu.Lock()
			f.gets++
			f.mu.Unlock()
			io.WriteString(c, "$-1\r\n")
		default:
			io.WriteString(c, "+OK\r\n")
		}
	}
}

var fakeKeys = map[string][2]string{
	"session:1": {"string", "90400"}, // 90.4 s: rounds to 90
	"session:2": {"hash", "-1"},      // no expiry
	"queue":     {"list", "1500"},
}

func openFake(t *testing.T, f *fakeRedis, query string) Store {
	t.Helper()
	tg, err := driver.Parse("redis://" + f.ln.Addr().String() + query)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	s, err := OpenStore(ctx, tg, "", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func keyLine(k KeyInfo) string {
	typ, ttl := "null", "null"
	if k.Type != nil {
		typ = *k.Type
	}
	if k.TTL != nil {
		ttl = strconv.FormatInt(*k.TTL, 10)
	}
	return k.Key + " " + typ + " " + ttl
}

func TestRedisKeysTypeAndTTL(t *testing.T) {
	for _, tc := range []struct{ name, query string }{{"server", ""}, {"cluster", "?cluster=1"}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRedis(t, fakeKeys)
			s := openFake(t, f, tc.query)
			got, more, err := s.Keys(context.Background(), "*", 100)
			if err != nil || more {
				t.Fatalf("keys: %v %v", more, err)
			}
			lines := map[string]bool{}
			for _, k := range got {
				lines[keyLine(k)] = true
			}
			for _, want := range []string{"session:1 string 90", "session:2 hash -1", "queue list 2"} {
				if !lines[want] {
					t.Errorf("want %q in %v", want, lines)
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.stalled || len(got) != 3 {
				t.Errorf("TYPE and PTTL must go in one pipeline (stalled %v, %d keys)", f.stalled, len(got))
			}
			if f.gets != 0 {
				t.Errorf("a key list read %d values", f.gets)
			}
		})
	}
}

// A user whose ACL refuses TYPE still gets the list; the type is unknown.
// A key deleted between SCAN and PTTL has no time to live.
func TestRedisKeysPartlyUnknown(t *testing.T) {
	f := newFakeRedis(t, map[string][2]string{"a": {"string", "-1"}, "gone": {"", ""}})
	f.denyType = true
	got, _, err := openFake(t, f, "").Keys(context.Background(), "*", 100)
	if err != nil || len(got) != 2 {
		t.Fatalf("keys: %v %v", got, err)
	}
	for _, k := range got {
		want := map[string]string{"a": "a null -1", "gone": "gone null null"}[k.Key]
		if keyLine(k) != want {
			t.Errorf("got %q, want %q", keyLine(k), want)
		}
	}
}

func TestTTLSeconds(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-1: "-1", -2: "null", 0: "0", 499 * time.Millisecond: "0", 500 * time.Millisecond: "1", time.Hour: "3600",
	} {
		got := "null"
		if s := ttlSeconds(d); s != nil {
			got = strconv.FormatInt(*s, 10)
		}
		if got != want {
			t.Errorf("ttlSeconds(%v) = %s, want %s", d, got, want)
		}
	}
}

func TestMetadumpKey(t *testing.T) {
	for _, tc := range []struct {
		line string
		now  int64
		want string
	}{
		{"key=session%3A1 exp=-1 la=1731500000 cas=3 fetch=no cls=1 size=63", 1731500100, "session:1 string -1"},
		{"key=a exp=1731500160 la=1731500000 cas=4 fetch=yes cls=1 size=60", 1731500100, "a string 60"},
		{"key=a exp=1731500160 la=1731500000 cas=4 fetch=yes cls=1 size=60", -1, "a string null"},
		{"key=old exp=1731500000 la=1731500000 cas=4 fetch=yes cls=1 size=60", 1731500100, "old string 0"},
	} {
		k, ok := metadumpKey(tc.line, tc.now)
		if !ok || keyLine(k) != tc.want {
			t.Errorf("%s: got %q %v, want %q", tc.line, keyLine(k), ok, tc.want)
		}
	}
	if _, ok := metadumpKey("ITEM no key here", 0); ok {
		t.Error("a line without key= is not a key")
	}
}

// The memcached list sends `stats` and the metadump in one write and reads
// the server's clock from `stats`.
func TestMemcacheKeysThenClock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	writes := make(chan string, 2)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		// metadump first, on its own: the crawler takes over the connection
		l1, _ := r.ReadString('\n')
		writes <- l1
		io.WriteString(c, "key=s%3A1 exp=1731500130 la=1731500000 cas=1 fetch=no cls=1 size=60\r\n"+
			"key=s%3A2 exp=-1 la=1731500000 cas=2 fetch=no cls=1 size=60\r\n"+
			"key=other exp=-1 la=1731500000 cas=3 fetch=no cls=1 size=60\r\nEND\r\n")
		// then stats for the server's clock
		l2, _ := r.ReadString('\n')
		writes <- l2
		io.WriteString(c, "STAT pid 1\r\nSTAT time 1731500100\r\nEND\r\n")
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	m := &memcache{c: c, r: bufio.NewReader(c), tmo: 5 * time.Second}
	defer m.Close()
	got, more, err := m.Keys(context.Background(), "s:*", 100)
	if err != nil || more || len(got) != 2 || keyLine(got[0]) != "s:1 string 30" || keyLine(got[1]) != "s:2 string -1" {
		t.Errorf("keys %v %v %v", got, more, err)
	}
	if w1, w2 := <-writes, <-writes; w1 != "lru_crawler metadump all\r\n" || w2 != "stats\r\n" {
		t.Errorf("metadump then stats, got %q then %q", w1, w2)
	}
}
