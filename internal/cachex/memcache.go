package cachex

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// Memcached, through its text protocol (github.com/memcached/memcached
// doc/protocol.txt): get/set/delete, the meta commands (mg) for the time to
// live, `stats` for info, and `lru_crawler metadump` to list keys (1.5.19+).
// A user name and password use the text protocol's auth (1.5.15+,
// memcached -Y); TLS with memcacheds://.

type memcache struct {
	c    net.Conn
	r    *bufio.Reader
	tmo  time.Duration
	meta bool // the server has the meta commands (1.6+)
}

func openMemcache(ctx context.Context, t driver.Target, password string, dial DialFunc, timeout time.Duration) (*memcache, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	c, err := dial(ctx, "tcp", t.Address)
	if err != nil {
		return nil, connectErr(t, err)
	}
	if t.Secure {
		host, _, _ := net.SplitHostPort(t.Address)
		pool, err := t.RootCAs()
		if err != nil {
			c.Close()
			return nil, err
		}
		tc := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: pool})
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, connectErr(t, err)
		}
		c = tc
	}
	m := &memcache{c: c, r: bufio.NewReader(c), tmo: timeout}
	if t.User != "" || password != "" {
		cred := t.User + " " + password
		line, err := m.cmd(ctx, fmt.Sprintf("set auth 0 0 %d\r\n%s", len(cred), cred))
		if err != nil && !strings.Contains(line, "authentication") {
			m.Close()
			return nil, connectErr(t, err)
		}
		if line != "STORED" {
			m.Close()
			return nil, out.Errf(out.ExitConnect, "CACHE_AUTH", "check the user in the URL and the password reference", "memcached refused the login: %s", line)
		}
	}
	if _, err := m.cmd(ctx, "version"); err != nil {
		m.Close()
		return nil, connectErr(t, err)
	}
	line, err := m.cmd(ctx, "mn") // the meta no-op: only 1.6+ answers MN
	m.meta = err == nil && line == "MN"
	return m, nil
}

func (m *memcache) Close() error { return m.c.Close() }

// cmd sends one command line and reads the first reply line.
func (m *memcache) cmd(ctx context.Context, line string) (string, error) {
	if err := m.send(ctx, line); err != nil {
		return "", err
	}
	return m.line()
}

func (m *memcache) send(ctx context.Context, line string) error {
	dl := time.Now().Add(m.tmo)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	m.c.SetDeadline(dl)
	_, err := io.WriteString(m.c, line+"\r\n")
	return err
}

func (m *memcache) line() (string, error) {
	s, err := m.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	s = strings.TrimRight(s, "\r\n")
	if strings.HasPrefix(s, "CLIENT_ERROR") || strings.HasPrefix(s, "SERVER_ERROR") || s == "ERROR" {
		return s, &mcError{s}
	}
	return s, nil
}

type mcError struct{ msg string }

func (e *mcError) Error() string { return "memcached: " + e.msg }

// validKey: memcached keys are up to 250 bytes, no spaces or control bytes.
func validKey(k string) error {
	if k == "" || len(k) > 250 {
		return out.Usage("a memcached key is 1 to 250 bytes")
	}
	for i := 0; i < len(k); i++ {
		if k[i] <= ' ' || k[i] == 0x7f {
			return out.Usage("a memcached key has no spaces or control characters: %q", k)
		}
	}
	return nil
}

func (m *memcache) block(n int) ([]byte, error) {
	b := make([]byte, n+2)
	if _, err := io.ReadFull(m.r, b); err != nil {
		return nil, err
	}
	return b[:n], nil
}

func (m *memcache) Get(ctx context.Context, key string, _ int64, maxBytes int) (*Value, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	if !m.meta {
		return m.classicGet(ctx, key, maxBytes)
	}
	// meta get: the value (v), the time to live (t) and the size (s)
	line, err := m.cmd(ctx, "mg "+key+" v t s")
	if err != nil {
		return nil, mcErr(err)
	}
	if line == "EN" {
		return nil, notFound(key)
	}
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "VA" {
		return nil, mcErr(fmt.Errorf("unexpected answer %q", line))
	}
	n, err := strconv.Atoi(f[1])
	if err != nil {
		return nil, mcErr(err)
	}
	data, err := m.block(n)
	if err != nil {
		return nil, mcErr(err)
	}
	v := &Value{Key: key, Type: "string", Size: int64(n)}
	for _, fl := range f[2:] {
		if s, ok := strings.CutPrefix(fl, "t"); ok {
			if ttl, err := strconv.ParseInt(s, 10, 64); err == nil && ttl >= 0 {
				v.TTL = &ttl
			}
		}
	}
	if maxBytes > 0 && len(data) > maxBytes {
		data, v.Truncated = data[:maxBytes], true
	}
	v.Value = text(string(data))
	return v, nil
}

func (m *memcache) classicGet(ctx context.Context, key string, maxBytes int) (*Value, error) {
	line, err := m.cmd(ctx, "get "+key)
	if err != nil {
		return nil, mcErr(err)
	}
	if line == "END" {
		return nil, notFound(key)
	}
	f := strings.Fields(line) // VALUE key flags bytes
	if len(f) < 4 || f[0] != "VALUE" {
		return nil, mcErr(fmt.Errorf("unexpected answer %q", line))
	}
	n, _ := strconv.Atoi(f[3])
	data, err := m.block(n)
	if err != nil {
		return nil, mcErr(err)
	}
	if _, err := m.line(); err != nil { // END
		return nil, mcErr(err)
	}
	v := &Value{Key: key, Type: "string", Size: int64(n)}
	if maxBytes > 0 && len(data) > maxBytes {
		data, v.Truncated = data[:maxBytes], true
	}
	v.Value = text(string(data))
	return v, nil
}

func notFound(key string) error {
	return out.Errf(out.ExitNotFound, "KEY_NOT_FOUND", "list keys with `komando cache keys CONN 'pattern*'`", "key %q does not exist", key)
}

// mcMaxRelative is the longest expiry memcached reads as seconds from now
// (30 days); a larger number is a Unix time.
const mcMaxRelative = 30 * 24 * 60 * 60

// mcExptime is the exptime field for a ttl: seconds from now, or for more
// than 30 days the Unix time it ends, which memcached would otherwise read
// as a moment in 1970 and drop the item at once.
func mcExptime(ttl time.Duration, now time.Time) int64 {
	exp := int64(ttl / time.Second)
	if ttl > 0 && exp == 0 {
		exp = 1
	}
	if exp > mcMaxRelative {
		exp += now.Unix()
	}
	return exp
}

func (m *memcache) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if err := validKey(key); err != nil {
		return err
	}
	line, err := m.cmd(ctx, fmt.Sprintf("set %s 0 %d %d\r\n%s", key, mcExptime(ttl, time.Now()), len(value), value))
	if err != nil {
		return mcErr(err)
	}
	if line != "STORED" {
		return mcErr(fmt.Errorf("not stored: %s", line))
	}
	return nil
}

func (m *memcache) Exists(ctx context.Context, key string) (bool, error) {
	if err := validKey(key); err != nil {
		return false, err
	}
	if !m.meta {
		v, err := m.classicGet(ctx, key, 1)
		return v != nil, ignoreNotFound(err)
	}
	line, err := m.cmd(ctx, "mg "+key)
	if err != nil {
		return false, mcErr(err)
	}
	return line == "HD", nil
}

func ignoreNotFound(err error) error {
	var oe *out.Error
	if errors.As(err, &oe) && oe.Code == "KEY_NOT_FOUND" {
		return nil
	}
	return err
}

func (m *memcache) Del(ctx context.Context, keys ...string) (int64, error) {
	var n int64
	for _, k := range keys {
		if err := validKey(k); err != nil {
			return n, err
		}
		line, err := m.cmd(ctx, "delete "+k)
		if err != nil {
			return n, mcErr(err)
		}
		if line == "DELETED" {
			n++
		}
	}
	return n, nil
}

// Keys lists keys with `lru_crawler metadump all` and matches them like
// a shell pattern (`session:*`).
func (m *memcache) Keys(ctx context.Context, pattern string, limit int) ([]string, bool, error) {
	if pattern == "" {
		pattern = "*"
	}
	if err := m.send(ctx, "lru_crawler metadump all"); err != nil {
		return nil, false, mcErr(err)
	}
	keys, more := []string{}, false
	for {
		line, err := m.line()
		if err != nil {
			if strings.Contains(line, "lru crawler") || line == "ERROR" {
				return nil, false, out.Errf(out.ExitRemote, "CACHE_ERROR", "start memcached with the LRU crawler on (the default since 1.5); `cache get` works without it",
					"this memcached cannot list keys: %s", line)
			}
			return nil, false, mcErr(err)
		}
		if line == "END" {
			return keys, more, nil
		}
		for _, f := range strings.Fields(line) {
			k, ok := strings.CutPrefix(f, "key=")
			if !ok {
				continue
			}
			if d, err := url.QueryUnescape(k); err == nil {
				k = d
			}
			if ok, _ := path.Match(pattern, k); ok {
				if len(keys) >= limit {
					more = true
				} else {
					keys = append(keys, k)
				}
			}
		}
	}
}

// MemcacheSections are the sections `stats` takes ("" is the general one).
var MemcacheSections = []string{"items", "slabs", "settings", "sizes", "conns"}

func (m *memcache) Info(ctx context.Context, section string) (map[string]map[string]string, error) {
	line := "stats"
	name := "stats"
	if section != "" {
		line += " " + section
		name = section
	}
	if err := m.send(ctx, line); err != nil {
		return nil, mcErr(err)
	}
	res := map[string]map[string]string{name: {}}
	for {
		l, err := m.line()
		if err != nil {
			return nil, mcErr(err)
		}
		if l == "END" {
			return res, nil
		}
		f := strings.SplitN(l, " ", 3)
		if len(f) == 3 && f[0] == "STAT" {
			res[name][f[1]] = f[2]
		}
	}
}

// memcacheSummary is the general `stats` boiled down like Redis's INFO.
func memcacheSummary(info map[string]map[string]string) Summary {
	st := info["stats"]
	n := func(k string) int64 { v, _ := strconv.ParseInt(st[k], 10, 64); return v }
	s := Summary{Version: st["version"] + " (memcached)", Role: "memcached", UptimeSeconds: n("uptime"), UsedMemory: n("bytes"),
		MaxMemory: n("limit_maxbytes"), EvictionPolicy: "lru", Clients: n("curr_connections"),
		Keys: map[string]int64{"items": n("curr_items")}, Expires: map[string]int64{}, Hits: n("get_hits"), Misses: n("get_misses")}
	if s.Hits+s.Misses > 0 {
		r := float64(s.Hits) / float64(s.Hits+s.Misses)
		s.HitRate = &r
	}
	return s
}

// Run sends one command line (no data block: use `cache set` to store) and
// returns the reply lines; values come with their data.
func (m *memcache) Run(ctx context.Context, args []string) (any, error) {
	args, err := MemcacheWords(args) // again here, so no caller can skip it
	if err != nil {
		return nil, err
	}
	if storeCmds[args[0]] {
		return nil, out.Usage("%s needs a data block; use `komando cache set CONN KEY VALUE`", args[0])
	}
	if err := m.send(ctx, strings.Join(args, " ")); err != nil {
		return nil, mcErr(err)
	}
	var lines []any
	for {
		l, err := m.line()
		if err != nil {
			return nil, mcErr(err)
		}
		f := strings.Fields(l)
		switch {
		case len(f) >= 4 && f[0] == "VALUE":
			n, _ := strconv.Atoi(f[3])
			data, err := m.block(n)
			if err != nil {
				return nil, mcErr(err)
			}
			lines = append(lines, map[string]any{"key": f[1], "value": text(string(data))})
			continue
		case len(f) >= 2 && f[0] == "VA":
			n, _ := strconv.Atoi(f[1])
			data, err := m.block(n)
			if err != nil {
				return nil, mcErr(err)
			}
			return map[string]any{"flags": f[2:], "value": text(string(data))}, nil
		case len(f) > 0 && (f[0] == "STAT" || f[0] == "ITEM" || strings.HasPrefix(f[0], "key=")):
			lines = append(lines, l)
			continue
		case l == "END":
			if lines == nil {
				lines = []any{}
			}
			return lines, nil
		}
		if lines == nil {
			return l, nil // a one-line answer: OK, DELETED, HD, a number...
		}
		lines = append(lines, l)
		return lines, nil
	}
}

var storeCmds = set("set add replace append prepend cas ms")

// MemcacheWords are the words memcached reads from a `cache run` line.
// memcached splits a line at spaces and ends it at a newline, so the words
// are re-split the same way here, before the command is rated: otherwise
// "get" plus an argument holding "\r\nflush_all" is rated a read and sends
// flush_all, " flush_all" is not seen as flush_all, and "mg" plus "key T30"
// hides the touch flag. A control byte cannot be in a memcached command, so
// a word with one is refused.
func MemcacheWords(args []string) ([]string, error) {
	for _, a := range args {
		for i := 0; i < len(a); i++ {
			if a[i] < ' ' || a[i] == 0x7f {
				return nil, out.Usage("a memcached command line has no newlines or other control characters: %q", a)
			}
		}
	}
	words := strings.Fields(strings.Join(args, " "))
	if len(words) == 0 {
		return nil, out.Usage("give a memcached command, e.g. `stats` or `get KEY`")
	}
	if words[0] = strings.ToLower(words[0]); words[0] == "watch" {
		return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"cache run sends one command and prints its reply; watch streams until the connection closes",
			"watch waits for data that keeps coming, so cache run would never return")
	}
	return words, nil
}

// ClassifyMemcache rates a memcached command line.
func ClassifyMemcache(args []string) driver.Verdict {
	if len(args) == 0 {
		return driver.Verdict{Risk: driver.RiskRead}
	}
	cmd := strings.ToLower(args[0])
	switch {
	case cmd == "flush_all":
		return driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"memcached-flush"}, Reasons: []string{"deletes every key (flush_all)"}}
	case cmd == "shutdown" || cmd == "cache_memlimit" || cmd == "verbosity" || cmd == "slabs" ||
		cmd == "lru" || cmd == "lru_crawler" && !(len(args) > 1 && strings.EqualFold(args[1], "metadump")):
		return driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"memcached-server"}, Reasons: []string{"changes or stops the server"}}
	case cmd == "delete" || cmd == "md":
		return driver.DataDelete()
	case cmd == "stats" && len(args) > 1 && (strings.EqualFold(args[1], "reset") ||
		strings.EqualFold(args[1], "detail") && !(len(args) > 2 && strings.EqualFold(args[2], "dump"))):
		// stats reset clears the counters and stats detail on|off switches
		// per-prefix counting on the server; only stats detail dump reads
		return driver.Verdict{Risk: driver.RiskWrite}
	case cmd == "get" || cmd == "gets" || cmd == "stats" || cmd == "version" || cmd == "mn" || cmd == "me" || cmd == "lru_crawler":
		return driver.Verdict{Risk: driver.RiskRead}
	case cmd == "mg":
		for _, f := range args[2:] {
			if strings.HasPrefix(f, "T") || strings.HasPrefix(f, "N") || f == "I" { // touch, vivify, invalidate change the item
				return driver.Verdict{Risk: driver.RiskWrite}
			}
		}
		return driver.Verdict{Risk: driver.RiskRead}
	}
	return driver.Verdict{Risk: driver.RiskWrite}
}

func mcErr(err error) error {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "memcached did not answer in time")
	}
	return out.Errf(out.ExitRemote, "CACHE_ERROR", "check the command and its arguments (memcached's protocol.txt)", "%s", err)
}

// MemcacheRules are the rules ClassifyMemcache can report.
func MemcacheRules() []driver.Rule {
	r := []driver.Rule{
		{ID: "memcached-flush", Reason: "deletes every key (flush_all)"},
		{ID: "memcached-server", Reason: "changes or stops the server"},
	}
	sort.Slice(r, func(i, j int) bool { return r[i].ID < r[j].ID })
	return r
}
