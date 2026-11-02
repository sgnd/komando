// Package cachex talks to Redis-compatible caches (Redis, Valkey, KeyDB,
// Dragonfly) and classifies their commands by risk. Redis has no read-only
// transactions, so the classifier is the safety layer: without --write only
// commands known to be reads are sent.
package cachex

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// DialFunc opens a TCP connection, possibly through an SSH host.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Open connects to a redis conn and checks it answers.
func Open(ctx context.Context, t driver.Target, password string, dial DialFunc, timeout time.Duration) (*redis.Client, error) {
	db, _ := strconv.Atoi(t.Database)
	o := &redis.Options{
		Addr: t.Address, Username: t.User, Password: password, DB: db,
		DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout,
		PoolSize: 1, MaxRetries: -1, DisableIdentity: true,
	}
	if t.Secure {
		host, _, _ := net.SplitHostPort(t.Address)
		o.TLSConfig = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	if dial != nil {
		o.Dialer = dial
	}
	c := redis.NewClient(o)
	if err := c.Ping(ctx).Err(); err != nil {
		c.Close()
		return nil, connectErr(t, err)
	}
	return c, nil
}

// Rule is a named command check, listed by `komando policy`.
var rules = []driver.Rule{
	{ID: "redis-flush", Reason: "deletes every key (FLUSHALL, FLUSHDB, SWAPDB)"},
	{ID: "redis-blocking", Reason: "blocks the server on large data sets (KEYS, SAVE, DEBUG); use `cache keys` for SCAN"},
	{ID: "redis-server-config", Reason: "changes server, replication or cluster configuration"},
	{ID: "redis-kill", Reason: "kills clients or shuts the server down"},
	{ID: "redis-acl", Reason: "changes users or permissions"},
	{ID: "redis-scripts", Reason: "deletes stored scripts or functions"},
	{ID: "redis-script-run", Reason: "runs a server-side script komando cannot inspect (EVAL, EVALSHA, FCALL)"},
}

// Rules lists the rules Classify can report.
func Rules() []driver.Rule { return append([]driver.Rule(nil), rules...) }

func reason(id string) string {
	for _, r := range rules {
		if r.ID == id {
			return r.Reason
		}
	}
	return id
}

var readCmds = set(`GET MGET STRLEN GETRANGE SUBSTR EXISTS TYPE TTL PTTL EXPIRETIME PEXPIRETIME SCAN
HSCAN SSCAN ZSCAN HGET HMGET HGETALL HKEYS HVALS HLEN HEXISTS HSTRLEN HRANDFIELD LRANGE LLEN LINDEX LPOS
SMEMBERS SISMEMBER SMISMEMBER SCARD SRANDMEMBER SINTER SUNION SDIFF SINTERCARD ZRANGE ZRANGEBYSCORE
ZRANGEBYLEX ZREVRANGE ZREVRANGEBYSCORE ZREVRANGEBYLEX ZSCORE ZMSCORE ZCARD ZCOUNT ZLEXCOUNT ZRANK ZREVRANK
ZRANDMEMBER ZINTER ZUNION ZDIFF ZINTERCARD XRANGE XREVRANGE XLEN XPENDING BITCOUNT BITPOS GETBIT BITFIELD_RO
PFCOUNT GEOPOS GEODIST GEOHASH GEOSEARCH GEORADIUS_RO GEORADIUSBYMEMBER_RO INFO DBSIZE PING ECHO TIME LASTSAVE
ROLE RANDOMKEY TOUCH LCS SORT_RO EVAL_RO EVALSHA_RO FCALL_RO DUMP COMMAND
JSON.GET JSON.MGET JSON.TYPE JSON.STRLEN JSON.ARRLEN JSON.ARRINDEX JSON.OBJKEYS JSON.OBJLEN JSON.RESP
FT.SEARCH FT.AGGREGATE FT.INFO FT._LIST FT.EXPLAIN FT.EXPLAINCLI FT.PROFILE FT.TAGVALS FT.SPELLCHECK
FT.DICTDUMP FT.SYNDUMP TS.GET TS.MGET TS.RANGE TS.REVRANGE TS.MRANGE TS.MREVRANGE TS.INFO TS.QUERYINDEX
BF.EXISTS BF.MEXISTS BF.INFO BF.CARD CF.EXISTS CF.MEXISTS CF.COUNT CF.INFO CMS.QUERY CMS.INFO TOPK.QUERY
TOPK.LIST TOPK.INFO TOPK.COUNT TDIGEST.INFO TDIGEST.MIN TDIGEST.MAX TDIGEST.QUANTILE TDIGEST.CDF
TDIGEST.RANK TDIGEST.REVRANK TDIGEST.BYRANK TDIGEST.BYREVRANK TDIGEST.TRIMMED_MEAN`)

// read-only subcommands of otherwise mixed commands
var readSub = map[string]map[string]bool{
	"CONFIG":   set("GET HELP"),
	"CLIENT":   set("LIST INFO GETNAME ID HELP TRACKINGINFO"),
	"MEMORY":   set("USAGE STATS DOCTOR HELP MALLOC-STATS"),
	"OBJECT":   set("ENCODING FREQ IDLETIME REFCOUNT HELP"),
	"SLOWLOG":  set("GET LEN HELP"),
	"LATENCY":  set("LATEST HISTORY DOCTOR GRAPH HELP HISTOGRAM"),
	"CLUSTER":  set("INFO NODES SLOTS SHARDS MYID KEYSLOT COUNTKEYSINSLOT GETKEYSINSLOT HELP"),
	"XINFO":    set("STREAM GROUPS CONSUMERS HELP"),
	"ACL":      set("LIST USERS WHOAMI GETUSER CAT LOG HELP"),
	"SCRIPT":   set("EXISTS HELP"),
	"FUNCTION": set("LIST DUMP STATS HELP"),
	"PUBSUB":   set("CHANNELS NUMSUB NUMPAT SHARDCHANNELS SHARDNUMSUB HELP"),
	"MODULE":   set("LIST HELP"),
}

var destructive = map[string]string{
	"FLUSHALL": "redis-flush", "FLUSHDB": "redis-flush", "SWAPDB": "redis-flush",
	"KEYS": "redis-blocking", "SAVE": "redis-blocking", "DEBUG": "redis-blocking",
	"SHUTDOWN": "redis-kill", "REPLICAOF": "redis-server-config", "SLAVEOF": "redis-server-config",
	"FAILOVER": "redis-server-config", "MIGRATE": "redis-flush",
	"EVAL": "redis-script-run", "EVALSHA": "redis-script-run", "FCALL": "redis-script-run",
}

var destructiveSub = map[string]map[string]string{
	"CONFIG":   {"SET": "redis-server-config", "REWRITE": "redis-server-config", "RESETSTAT": "redis-server-config"},
	"CLIENT":   {"KILL": "redis-kill", "PAUSE": "redis-kill", "NO-EVICT": "redis-server-config"},
	"CLUSTER":  {"RESET": "redis-server-config", "FAILOVER": "redis-server-config", "FORGET": "redis-server-config", "DELSLOTS": "redis-server-config", "SETSLOT": "redis-server-config"},
	"ACL":      {"SETUSER": "redis-acl", "DELUSER": "redis-acl", "LOAD": "redis-acl", "SAVE": "redis-acl"},
	"SCRIPT":   {"FLUSH": "redis-scripts"},
	"FUNCTION": {"FLUSH": "redis-scripts", "DELETE": "redis-scripts", "RESTORE": "redis-scripts"},
	"MODULE":   {"LOAD": "redis-server-config", "LOADEX": "redis-server-config", "UNLOAD": "redis-server-config"},
}

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

// Classify rates a raw command. Unknown commands are writes.
func Classify(args []string) driver.Verdict {
	if len(args) == 0 {
		return driver.Verdict{Risk: driver.RiskRead}
	}
	cmd := strings.ToUpper(args[0])
	sub := ""
	if len(args) > 1 {
		sub = strings.ToUpper(args[1])
	}
	flag := func(id string) driver.Verdict {
		return driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{id}, Reasons: []string{reason(id)}}
	}
	if id, ok := destructive[cmd]; ok {
		return flag(id)
	}
	if cmd == "DEL" || cmd == "UNLINK" || cmd == "GETDEL" || cmd == "RENAME" || expiresNow(cmd, args) {
		// same as `cache rm`: the key (or RENAME's target) is gone afterwards
		return driver.DataDelete()
	}
	if cmd == "ACL" && sub == "LOG" && len(args) > 2 && strings.EqualFold(args[2], "RESET") {
		return driver.Verdict{Risk: driver.RiskWrite}
	}
	if id, ok := destructiveSub[cmd][sub]; ok {
		return flag(id)
	}
	if readCmds[cmd] || readSub[cmd][sub] {
		return driver.Verdict{Risk: driver.RiskRead}
	}
	return driver.Verdict{Risk: driver.RiskWrite}
}

// expiresNow reports EXPIRE/PEXPIRE with a time of zero or less, and
// EXPIREAT/PEXPIREAT with a time in the past: Redis deletes the key at once.
func expiresNow(cmd string, args []string) bool {
	if len(args) < 3 {
		return false
	}
	n, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil {
		return false
	}
	switch cmd {
	case "EXPIRE", "PEXPIRE":
		return n <= 0
	case "EXPIREAT":
		return n <= time.Now().Unix()
	case "PEXPIREAT":
		return n <= time.Now().UnixMilli()
	}
	return false
}

// Value is a key with its type, time to live and (part of) its content.
type Value struct {
	Key       string `json:"key"`
	Type      string `json:"type"`
	TTL       *int64 `json:"ttl_seconds"` // null = no expiry
	Size      int64  `json:"size"`        // bytes for strings, items for collections
	Value     any    `json:"value"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Get reads a key of any type. Collections return at most limit items.
func Get(ctx context.Context, c *redis.Client, key string, limit int64, maxBytes int) (*Value, error) {
	typ, err := c.Type(ctx, key).Result()
	if err != nil {
		return nil, cmdErr(err)
	}
	if typ == "none" {
		return nil, out.Errf(out.ExitNotFound, "KEY_NOT_FOUND", "list keys with `komando cache keys CONN 'pattern*'`", "key %q does not exist", key)
	}
	v := &Value{Key: key, Type: typ}
	if ttl, err := c.TTL(ctx, key).Result(); err == nil && ttl >= 0 {
		s := int64(ttl / time.Second)
		v.TTL = &s
	}
	if limit <= 0 {
		limit = 100
	}
	switch typ {
	case "string":
		s, err := c.Get(ctx, key).Result()
		if err != nil {
			return nil, cmdErr(err)
		}
		v.Size = int64(len(s))
		if maxBytes > 0 && len(s) > maxBytes {
			s, v.Truncated = s[:maxBytes], true
		}
		v.Value = text(s)
	case "hash":
		v.Size, _ = c.HLen(ctx, key).Result()
		m := map[string]any{}
		keys, cur, err := c.HScan(ctx, key, 0, "*", limit).Result()
		for err == nil {
			for i := 0; i+1 < len(keys); i += 2 {
				m[keys[i]] = text(keys[i+1])
			}
			if cur == 0 || int64(len(m)) >= limit {
				break
			}
			keys, cur, err = c.HScan(ctx, key, cur, "*", limit).Result()
		}
		if err != nil {
			return nil, cmdErr(err)
		}
		v.Value, v.Truncated = m, int64(len(m)) < v.Size
	case "list":
		v.Size, _ = c.LLen(ctx, key).Result()
		items, err := c.LRange(ctx, key, 0, limit-1).Result()
		if err != nil {
			return nil, cmdErr(err)
		}
		v.Value, v.Truncated = texts(items), int64(len(items)) < v.Size
	case "set":
		v.Size, _ = c.SCard(ctx, key).Result()
		items, _, err := c.SScan(ctx, key, 0, "*", limit).Result()
		if err != nil {
			return nil, cmdErr(err)
		}
		v.Value, v.Truncated = texts(items), int64(len(items)) < v.Size
	case "zset":
		v.Size, _ = c.ZCard(ctx, key).Result()
		items, err := c.ZRangeWithScores(ctx, key, 0, limit-1).Result()
		if err != nil {
			return nil, cmdErr(err)
		}
		res := make([]map[string]any, len(items))
		for i, z := range items {
			res[i] = map[string]any{"member": text(fmt.Sprint(z.Member)), "score": z.Score}
		}
		v.Value, v.Truncated = res, int64(len(items)) < v.Size
	case "stream":
		v.Size, _ = c.XLen(ctx, key).Result()
		msgs, err := c.XRangeN(ctx, key, "-", "+", limit).Result()
		if err != nil {
			return nil, cmdErr(err)
		}
		res := make([]map[string]any, len(msgs))
		for i, m := range msgs {
			res[i] = map[string]any{"id": m.ID, "fields": m.Values}
		}
		v.Value, v.Truncated = res, int64(len(msgs)) < v.Size
	default:
		v.Value = nil // module types (JSON, time series...): read them with `cache run`
	}
	return v, nil
}

// Keys lists keys matching pattern with SCAN (never KEYS), up to limit.
func Keys(ctx context.Context, c *redis.Client, pattern string, limit int) (keys []string, more bool, err error) {
	if pattern == "" {
		pattern = "*"
	}
	keys = []string{}
	var cur uint64
	for {
		batch, next, err := c.Scan(ctx, cur, pattern, 500).Result()
		if err != nil {
			return nil, false, cmdErr(err)
		}
		for _, k := range batch {
			if len(keys) >= limit {
				return keys, true, nil
			}
			keys = append(keys, k)
		}
		if next == 0 {
			return keys, false, nil
		}
		cur = next
	}
}

// Info returns the INFO reply as sections of key/value pairs.
func Info(ctx context.Context, c *redis.Client, section string) (map[string]map[string]string, error) {
	args := []string{}
	if section != "" {
		args = append(args, section)
	}
	s, err := c.Info(ctx, args...).Result()
	if err != nil {
		return nil, cmdErr(err)
	}
	res := map[string]map[string]string{}
	cur := "server"
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "# "):
			cur = strings.ToLower(strings.TrimPrefix(line, "# "))
		default:
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			if res[cur] == nil {
				res[cur] = map[string]string{}
			}
			res[cur][k] = v
		}
	}
	return res, nil
}

// Run sends a raw command and converts the reply to JSON-safe values.
func Run(ctx context.Context, c *redis.Client, args []string) (any, error) {
	a := make([]any, len(args))
	for i, s := range args {
		a[i] = s
	}
	v, err := c.Do(ctx, a...).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, cmdErr(err)
	}
	return reply(v), nil
}

func reply(v any) any {
	switch x := v.(type) {
	case string:
		return text(x)
	case []any:
		res := make([]any, len(x))
		for i, e := range x {
			res[i] = reply(e)
		}
		return res
	case map[any]any:
		res := map[string]any{}
		for k, e := range x {
			res[fmt.Sprint(k)] = reply(e)
		}
		return res
	}
	return v
}

func texts(items []string) []any {
	res := make([]any, len(items))
	for i, s := range items {
		res[i] = text(s)
	}
	return res
}

// text keeps valid UTF-8 as a string and wraps binary as {"base64": ...}.
func text(s string) any {
	return driver.JSONValue([]byte(s))
}

// CmdErr maps a redis error to a komando error code.
func CmdErr(err error) error { return cmdErr(err) }

func cmdErr(err error) error {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "redis did not answer in time")
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "NOPERM") || strings.HasPrefix(msg, "NOAUTH") {
		return out.Errf(out.ExitConnect, "CACHE_AUTH", "check the user in the URL and the password reference", "%s", msg)
	}
	return out.Errf(out.ExitRemote, "CACHE_ERROR", "check the command and its arguments (redis.io/commands)", "%s", msg)
}

func connectErr(t driver.Target, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "WRONGPASS"), strings.Contains(msg, "NOAUTH"), strings.Contains(msg, "invalid password"):
		return out.Errf(out.ExitConnect, "CACHE_AUTH", "check the user in the URL and the password reference (`komando conn show NAME`)", "%s", msg)
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "check the address or raise --connect-timeout", "connecting to %s timed out", t.Address)
	}
	return out.Errf(out.ExitConnect, "CACHE_CONNECT", "run `komando conn test NAME` to check reachability", "cannot connect to %s: %s", t.Address, msg)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
