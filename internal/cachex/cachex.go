// Package cachex talks to Redis-compatible caches (Redis, Valkey, KeyDB,
// Dragonfly) and memcached, and classifies their commands by risk. Neither
// has read-only transactions, so the classifier is the safety layer: without
// --write only commands known to be reads are sent.
package cachex

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// go-redis logs a failed dial to stderr itself, which breaks the JSON an
// agent reads with 2>&1; komando reports the error in its own envelope.
func init() { redis.SetLogger(quietLog{}) }

type quietLog struct{}

func (quietLog) Printf(context.Context, string, ...any) {}

// DialFunc opens a TCP connection, possibly through an SSH host.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Open connects to a redis conn and checks it answers: one server, a
// Redis Cluster (any node leads to the others) or the master that the
// Sentinels name.
func Open(ctx context.Context, t driver.Target, password string, dial DialFunc, timeout time.Duration) (redis.UniversalClient, error) {
	db, _ := strconv.Atoi(t.Database)
	var tc *tls.Config
	if t.Secure {
		pool, err := t.RootCAs()
		if err != nil {
			return nil, err
		}
		tc = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool} // nil pool: this computer's CAs
	}
	dialer := redisDialer(dial, tc, timeout)
	var c redis.UniversalClient
	switch {
	case t.Cluster:
		c = redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{t.Address}, Username: t.User, Password: password,
			Dialer: dialer, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout,
			PoolSize: 1, MaxRetries: -1, DialerRetries: 1, MaxRedirects: 3, DisableIdentity: true})
	case t.Sentinel != "":
		fo := &redis.FailoverOptions{MasterName: t.Sentinel, SentinelAddrs: append([]string{t.Address}, t.Sentinels...),
			Username: t.User, Password: password, DB: db, Dialer: dialer, DialTimeout: timeout, ReadTimeout: timeout,
			WriteTimeout: timeout, PoolSize: 1, MaxRetries: -1, DialerRetries: 1, DisableIdentity: true}
		if t.SentinelAuth {
			fo.SentinelUsername, fo.SentinelPassword = t.User, password
		}
		c = redis.NewFailoverClient(fo)
	default:
		c = redis.NewClient(&redis.Options{Addr: t.Address, Username: t.User, Password: password, DB: db,
			Dialer: dialer, DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout,
			PoolSize: 1, MaxRetries: -1, DialerRetries: 1, DisableIdentity: true})
	}
	if err := c.Ping(ctx).Err(); err != nil {
		c.Close()
		return nil, connectErr(t, err)
	}
	return c, nil
}

// redisDialer opens each connection (to a server, a Cluster node or a
// Sentinel) on its way (direct or --via) and adds TLS itself: go-redis
// leaves TLS out when it is given a dialer, and a Cluster's nodes each
// have their own name to check.
func redisDialer(dial DialFunc, tc *tls.Config, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil || tc == nil {
			return c, err
		}
		cfg := tc.Clone()
		cfg.ServerName, _, _ = net.SplitHostPort(addr)
		tlsc := tls.Client(c, cfg)
		if err := tlsc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return tlsc, nil
	}
}

// rules are the named command checks, listed by `komando policy`.
var rules = []driver.Rule{
	{ID: "redis-flush", Reason: "deletes every key (FLUSHALL, FLUSHDB, SWAPDB)"},
	{ID: "redis-blocking", Reason: "blocks the server on large data sets (KEYS, SAVE, DEBUG); use `cache keys` for SCAN"},
	{ID: "redis-server-config", Reason: "changes server, replication or cluster configuration"},
	{ID: "redis-kill", Reason: "kills clients or shuts the server down"},
	{ID: "redis-acl", Reason: "changes users or permissions"},
	{ID: "redis-scripts", Reason: "deletes or replaces stored scripts or functions"},
	{ID: "redis-script-run", Reason: "runs a server-side script komando cannot inspect, which can block the server (EVAL, EVALSHA, FCALL and their _RO forms, TFCALL, RG.PYEXECUTE)"},
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
ZRANDMEMBER ZINTER ZUNION ZDIFF ZINTERCARD XRANGE XREVRANGE XREAD XLEN XPENDING BITCOUNT BITPOS GETBIT BITFIELD_RO
PFCOUNT GEOPOS GEODIST GEOHASH GEOSEARCH GEORADIUS_RO GEORADIUSBYMEMBER_RO INFO DBSIZE PING ECHO TIME LASTSAVE
ROLE RANDOMKEY TOUCH LCS SORT_RO DUMP COMMAND
JSON.GET JSON.MGET JSON.TYPE JSON.STRLEN JSON.ARRLEN JSON.ARRINDEX JSON.OBJKEYS JSON.OBJLEN JSON.RESP
FT.SEARCH FT.AGGREGATE FT.INFO FT._LIST FT.EXPLAIN FT.EXPLAINCLI FT.PROFILE FT.TAGVALS FT.SPELLCHECK
FT.DICTDUMP FT.SYNDUMP TS.GET TS.MGET TS.RANGE TS.REVRANGE TS.MRANGE TS.MREVRANGE TS.INFO TS.QUERYINDEX
BF.EXISTS BF.MEXISTS BF.INFO BF.CARD CF.EXISTS CF.MEXISTS CF.COUNT CF.INFO CMS.QUERY CMS.INFO TOPK.QUERY
TOPK.LIST TOPK.INFO TOPK.COUNT TDIGEST.INFO TDIGEST.MIN TDIGEST.MAX TDIGEST.QUANTILE TDIGEST.CDF
TDIGEST.RANK TDIGEST.REVRANK TDIGEST.BYRANK TDIGEST.BYREVRANK TDIGEST.TRIMMED_MEAN`)

// read-only subcommands of otherwise mixed commands
var readSub = map[string]map[string]bool{
	"CONFIG":    set("GET HELP"),
	"CLIENT":    set("LIST INFO GETNAME ID HELP TRACKINGINFO"),
	"MEMORY":    set("USAGE STATS DOCTOR HELP MALLOC-STATS"),
	"OBJECT":    set("ENCODING FREQ IDLETIME REFCOUNT HELP"),
	"SLOWLOG":   set("GET LEN HELP"),
	"LATENCY":   set("LATEST HISTORY DOCTOR GRAPH HELP HISTOGRAM"),
	"CLUSTER":   set("INFO NODES SLOTS SHARDS MYID MYSHARDID KEYSLOT COUNTKEYSINSLOT GETKEYSINSLOT REPLICAS SLAVES LINKS COUNT-FAILURE-REPORTS HELP"),
	"SENTINEL":  set("MASTERS MASTER PRIMARIES PRIMARY REPLICAS SLAVES SENTINELS GET-MASTER-ADDR-BY-NAME GET-PRIMARY-ADDR-BY-NAME CKQUORUM INFO-CACHE MYID HELP"),
	"XINFO":     set("STREAM GROUPS CONSUMERS HELP"),
	"ACL":       set("LIST USERS WHOAMI GETUSER CAT LOG HELP"),
	"SCRIPT":    set("EXISTS HELP"),
	"FUNCTION":  set("LIST DUMP STATS HELP"),
	"PUBSUB":    set("CHANNELS NUMSUB NUMPAT SHARDCHANNELS SHARDNUMSUB HELP"),
	"MODULE":    set("LIST HELP"),
	"TFUNCTION": set("LIST"),
}

var destructive = map[string]string{
	"FLUSHALL": "redis-flush", "FLUSHDB": "redis-flush", "SWAPDB": "redis-flush",
	"KEYS": "redis-blocking", "SAVE": "redis-blocking", "DEBUG": "redis-blocking",
	"SHUTDOWN": "redis-kill", "REPLICAOF": "redis-server-config", "SLAVEOF": "redis-server-config",
	"FAILOVER": "redis-server-config", "MIGRATE": "redis-flush",
	// a read-only script cannot write, but it can loop: Redis then answers
	// BUSY to every client until someone sends SCRIPT KILL
	"EVAL": "redis-script-run", "EVALSHA": "redis-script-run", "FCALL": "redis-script-run",
	"EVAL_RO": "redis-script-run", "EVALSHA_RO": "redis-script-run", "FCALL_RO": "redis-script-run",
	// module code: Redis Stack Triggers and Functions (JavaScript) and
	// RedisGears (Python, which can do anything the server can)
	"TFCALL": "redis-script-run", "TFCALLASYNC": "redis-script-run",
	"RG.PYEXECUTE": "redis-script-run", "RG.TRIGGER": "redis-script-run", "RG.TRIGGERONKEY": "redis-script-run",
	"RG.UNREGISTER": "redis-scripts",
}

var destructiveSub = map[string]map[string]string{
	"CONFIG": {"SET": "redis-server-config", "REWRITE": "redis-server-config", "RESETSTAT": "redis-server-config"},
	"CLIENT": {"KILL": "redis-kill", "PAUSE": "redis-kill", "NO-EVICT": "redis-server-config"},
	"CLUSTER": {"RESET": "redis-server-config", "FAILOVER": "redis-server-config", "FORGET": "redis-server-config", "DELSLOTS": "redis-server-config",
		"SETSLOT": "redis-server-config", "DELSLOTSRANGE": "redis-server-config", "ADDSLOTS": "redis-server-config", "ADDSLOTSRANGE": "redis-server-config",
		"FLUSHSLOTS": "redis-server-config", "MEET": "redis-server-config", "BUMPEPOCH": "redis-server-config", "SET-CONFIG-EPOCH": "redis-server-config",
		// a node made a replica drops its own data and copies its new master's
		"REPLICATE": "redis-flush"},
	// Sentinel: which master it watches and when it fails over
	"SENTINEL": {"SET": "redis-server-config", "REMOVE": "redis-server-config", "MONITOR": "redis-server-config", "FAILOVER": "redis-server-config",
		"RESET": "redis-server-config", "FLUSHCONFIG": "redis-server-config", "DEBUG": "redis-server-config", "SIMULATE-FAILURE": "redis-kill"},
	"ACL":       {"SETUSER": "redis-acl", "DELUSER": "redis-acl", "LOAD": "redis-acl", "SAVE": "redis-acl"},
	"SCRIPT":    {"FLUSH": "redis-scripts"},
	"FUNCTION":  {"FLUSH": "redis-scripts", "DELETE": "redis-scripts", "RESTORE": "redis-scripts"},
	"TFUNCTION": {"DELETE": "redis-scripts"},
	"MODULE":    {"LOAD": "redis-server-config", "LOADEX": "redis-server-config", "UNLOAD": "redis-server-config"},
}

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

// SplitCommand reads a command given as one argument ("GET foo") the way
// redis-cli reads a line: words split at spaces, "..." with \" \\ \n \r
// \t \xHH escapes, and '...' with \' only. Several arguments are kept.
func SplitCommand(args []string) ([]string, error) {
	if len(args) != 1 || !strings.ContainsAny(args[0], " \t\n\"'") {
		return args, nil
	}
	var words []string
	s := args[0]
	for i := 0; i < len(s); {
		for i < len(s) && strings.ContainsRune(" \t\r\n", rune(s[i])) {
			i++
		}
		if i == len(s) {
			break
		}
		var w strings.Builder
		for i < len(s) && !strings.ContainsRune(" \t\r\n", rune(s[i])) {
			q := s[i]
			if q != '"' && q != '\'' {
				w.WriteByte(q)
				i++
				continue
			}
			i++
			closed := false
			for i < len(s) {
				c := s[i]
				i++
				if c == q {
					closed = true
					break
				}
				if c != '\\' || i == len(s) {
					w.WriteByte(c)
					continue
				}
				e := s[i]
				i++
				switch {
				case q == '\'' && e == '\'':
					w.WriteByte(e)
				case q == '\'':
					w.WriteByte(c)
					w.WriteByte(e)
				case e == 'n':
					w.WriteByte('\n')
				case e == 'r':
					w.WriteByte('\r')
				case e == 't':
					w.WriteByte('\t')
				case e == 'x' && i+2 <= len(s):
					if b, err := strconv.ParseUint(s[i:i+2], 16, 8); err == nil {
						w.WriteByte(byte(b))
						i += 2
						continue
					}
					w.WriteByte(e)
				default:
					w.WriteByte(e)
				}
			}
			if !closed {
				return nil, out.Usage("unbalanced quotes in %q", s)
			}
		}
		words = append(words, w.String())
	}
	if len(words) == 0 {
		return nil, out.Usage("no command given")
	}
	return words, nil
}

// noReply are commands that never answer once: they keep the connection
// and stream to it until it closes.
var noReply = set("MONITOR SUBSCRIBE PSUBSCRIBE SSUBSCRIBE SYNC PSYNC")

// OneReply refuses a command that does not answer with one reply, which
// cache run waits for: MONITOR, SUBSCRIBE and the like, and XREAD or
// XREADGROUP with BLOCK.
func OneReply(args []string) error {
	if len(args) == 0 {
		return nil
	}
	cmd := strings.ToUpper(args[0])
	block := false
	if cmd == "XREAD" || cmd == "XREADGROUP" {
		for _, a := range args[1:] {
			if strings.EqualFold(a, "STREAMS") { // stream names and IDs follow; a stream may be called block
				break
			}
			block = block || strings.EqualFold(a, "BLOCK")
		}
	}
	if !noReply[cmd] && !block {
		return nil
	}
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"cache run sends one command and prints its one reply; drop BLOCK from XREAD, and use redis-cli for MONITOR or SUBSCRIBE",
		"%s waits for data that keeps coming, so cache run would never return", cmd)
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
	if cmd == "DEL" || cmd == "UNLINK" || cmd == "GETDEL" || cmd == "RENAME" || expiresNow(cmd, args) || dropsDocs(cmd, args) {
		// same as `cache rm`: the key (or RENAME's target) is gone afterwards
		return driver.DataDelete()
	}
	if cmd == "ACL" && sub == "LOG" && len(args) > 2 && strings.EqualFold(args[2], "RESET") {
		return driver.Verdict{Risk: driver.RiskWrite}
	}
	if (cmd == "FUNCTION" || cmd == "TFUNCTION") && sub == "LOAD" && replaces(args) {
		// swaps the code behind functions the application already calls;
		// a plain LOAD only adds a library and fails if the name is taken
		return flag("redis-scripts")
	}
	if cmd == "SENTINEL" && sub == "CONFIG" {
		if len(args) > 2 && strings.EqualFold(args[2], "GET") {
			return driver.Verdict{Risk: driver.RiskRead}
		}
		return flag("redis-server-config")
	}
	if id, ok := destructiveSub[cmd][sub]; ok {
		return flag(id)
	}
	if readCmds[cmd] || readSub[cmd][sub] {
		return driver.Verdict{Risk: driver.RiskRead}
	}
	return driver.Verdict{Risk: driver.RiskWrite}
}

// replaces: FUNCTION LOAD or TFUNCTION LOAD with REPLACE among the options,
// which come before the code (the last argument).
func replaces(args []string) bool {
	if len(args) < 4 {
		return false
	}
	for _, a := range args[2 : len(args)-1] {
		if strings.EqualFold(a, "REPLACE") {
			return true
		}
	}
	return false
}

// dropsDocs: FT.DROPINDEX with DD deletes every document the index
// covers, and the old FT.DROP does so unless KEEPDOCS is given.
func dropsDocs(cmd string, args []string) bool {
	has := func(w string) bool {
		return slices.ContainsFunc(args[min(len(args), 2):], func(a string) bool { return strings.EqualFold(a, w) })
	}
	switch cmd {
	case "FT.DROPINDEX":
		return has("DD")
	case "FT.DROP":
		return !has("KEEPDOCS")
	}
	return false
}

// expiresNow reports EXPIRE/PEXPIRE with a time of zero or less, and
// EXPIREAT/PEXPIREAT, or SET/GETEX with EXAT/PXAT, with a time in the
// past: Redis deletes the key at once.
func expiresNow(cmd string, args []string) bool {
	if cmd == "SET" || cmd == "GETEX" {
		first := 2 // GETEX key [options]; SET key value [options]
		if cmd == "SET" {
			first = 3
		}
		for i := first; i+1 < len(args); i++ {
			n, err := strconv.ParseInt(args[i+1], 10, 64)
			switch {
			case err != nil:
			case strings.EqualFold(args[i], "EXAT") && n <= time.Now().Unix(),
				strings.EqualFold(args[i], "PXAT") && n <= time.Now().UnixMilli():
				return true
			}
		}
		return false
	}
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
func Get(ctx context.Context, c redis.UniversalClient, key string, limit int64, maxBytes int) (*Value, error) {
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
func Keys(ctx context.Context, c redis.UniversalClient, pattern string, limit int) (keys []string, more bool, err error) {
	if pattern == "" {
		pattern = "*"
	}
	if cc, ok := c.(*redis.ClusterClient); ok {
		return clusterKeys(ctx, cc, pattern, limit)
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
func Info(ctx context.Context, c redis.UniversalClient, section string) (map[string]map[string]string, error) {
	if cc, ok := c.(*redis.ClusterClient); ok {
		return clusterInfo(ctx, cc, section)
	}
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
func Run(ctx context.Context, c redis.UniversalClient, args []string) (any, error) {
	a := make([]any, len(args))
	for i, s := range args {
		a[i] = s
	}
	v, err := c.Do(ctx, a...).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, scriptTimeout(args, cmdErr(err))
	}
	return reply(v), nil
}

// scriptKill names the command that stops each kind of running script.
var scriptKill = map[string]string{
	"EVAL": "SCRIPT KILL", "EVALSHA": "SCRIPT KILL", "EVAL_RO": "SCRIPT KILL", "EVALSHA_RO": "SCRIPT KILL",
	"FCALL": "FUNCTION KILL", "FCALL_RO": "FUNCTION KILL",
}

// scriptTimeout: komando stopped waiting for a script, but the script may
// still run and block the server, so "raise --timeout" is the wrong advice.
func scriptTimeout(args []string, err error) error {
	var oe *out.Error
	if len(args) == 0 || destructive[strings.ToUpper(args[0])] != "redis-script-run" || !errors.As(err, &oe) || oe.Code != "TIMEOUT" {
		return err
	}
	stop := ""
	if k := scriptKill[strings.ToUpper(args[0])]; k != "" {
		stop = " (" + k + " stops it)"
	}
	oe.Message = "the script did not finish in time"
	oe.Hint = "the script may still be running, and until it ends Redis may answer BUSY to every client: tell the user" +
		stop + "; do not retry with a longer --timeout unless the user says so"
	return oe
}

// passwordHash is a password as ACL LIST and ACL GETUSER show it: an
// unsalted SHA-256, which is cheap to crack for a weak password.
var passwordHash = regexp.MustCompile(`\b[0-9a-f]{64}\b`)

// HideSecrets hides credentials in the reply to args, for output to an AI
// agent: the values of password parameters in CONFIG GET (requirepass,
// masterauth, tls-key-file-pass, ...) and the password hashes in ACL LIST
// and ACL GETUSER. The output masker cannot spot these: requirepass is not
// a name it knows, and over RESP2 CONFIG GET returns names and values as
// separate items of one list.
func HideSecrets(args []string, v any) any {
	w := make([]string, 0, 3)
	for _, a := range args[:min(len(args), 3)] {
		w = append(w, strings.ToUpper(a))
	}
	is := func(words ...string) bool { return len(w) >= len(words) && slices.Equal(w[:len(words)], words) }
	switch {
	case is("CONFIG", "GET"), is("SENTINEL", "CONFIG", "GET"):
		hideParams(v)
	case is("ACL", "LIST"), is("ACL", "GETUSER"):
		return hideHashes(v)
	case is("HGETALL"):
		return pairsToMap(v)
	}
	return v
}

// pairsToMap turns a RESP2 HGETALL reply, a flat [field, value ...] list,
// into the map RESP3 gives, so the output masking sees a field named
// password as a name and hides its value the same way over both.
func pairsToMap(v any) any {
	x, ok := v.([]any)
	if !ok || len(x)%2 != 0 {
		return v
	}
	m := make(map[string]any, len(x)/2)
	for i := 0; i < len(x); i += 2 {
		name, ok := x[i].(string)
		if !ok { // a binary field name: keep the list
			return v
		}
		m[name] = x[i+1]
	}
	return m
}

// hideParams hides password values in a CONFIG GET reply: a map over
// RESP3, a flat [name, value, name, value ...] list over RESP2.
func hideParams(v any) {
	switch x := v.(type) {
	case map[string]any:
		for name, val := range x {
			if secretParam(name, val) {
				x[name] = out.Hidden
			}
		}
	case []any:
		for i := 0; i+1 < len(x); i += 2 {
			if name, ok := x[i].(string); ok && secretParam(name, x[i+1]) {
				x[i+1] = out.Hidden
			}
		}
	}
}

// secretParam: a parameter that holds a password (requirepass, masterauth,
// primaryauth, tls-key-file-pass, sentinel-pass ...) and is set. A switch
// such as tls-auth-clients (yes, no, optional) is not a secret; a password
// parameter is hidden whatever it holds, even "yes".
func secretParam(name string, v any) bool {
	n := strings.ToLower(name)
	if !strings.Contains(n, "pass") && !strings.Contains(n, "auth") {
		return false
	}
	s, ok := v.(string)
	if !ok {
		return v != nil // a binary value comes as {"base64": ...}
	}
	if s == "" {
		return false
	}
	if strings.HasSuffix(n, "pass") || strings.HasSuffix(n, "auth") || strings.HasSuffix(n, "password") {
		return true
	}
	switch strings.ToLower(s) {
	case "yes", "no", "optional", "on", "off", "true", "false":
		return false
	}
	return true
}

// hideHashes replaces every password hash in a reply with [hidden].
func hideHashes(v any) any {
	switch x := v.(type) {
	case string:
		return passwordHash.ReplaceAllString(x, out.Hidden)
	case []any:
		for i, e := range x {
			x[i] = hideHashes(e)
		}
	case map[string]any:
		for k, e := range x {
			x[k] = hideHashes(e)
		}
	}
	return v
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
	case t.Secure && (strings.Contains(msg, "x509:") || strings.Contains(msg, "tls: failed to verify")):
		return out.Errf(out.ExitConnect, "CACHE_CONNECT", "the server's certificate could not be checked against this computer's CAs: give the CA that signed it with ?ca=secret:NAME (`komando secret set NAME < ca.pem`), or reach the server --via an SSH server with the plain scheme (redis://, memcached://) instead (`komando conn edit NAME --via HOST --url ...`)",
			"cannot connect to %s: %s", t.Address, msg)
	case t.Secure && strings.Contains(msg, "first record does not look like a TLS handshake"):
		return out.Errf(out.ExitConnect, "CACHE_CONNECT", "the server does not speak TLS on this port: check the port, or reach it --via an SSH server with the plain scheme (redis://, memcached://)",
			"cannot connect to %s: %s", t.Address, msg)
	}
	return out.Errf(out.ExitConnect, "CACHE_CONNECT", "run `komando conn test NAME` to check reachability", "cannot connect to %s: %s", t.Address, msg)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
