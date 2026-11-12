package cli

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Cache commands follow the same rule as db: named actions (set, del) do
// what they say, behind the usual seatbelts; the raw `cache run` is
// read-only unless --write. Redis has no read-only mode, so without
// --write only commands known to be reads are sent.

func cacheCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "cache",
		Aliases: []string{"redis"},
		Short:   "Caches (Redis, Valkey, memcached): read and change keys",
		Long: `Read and change keys in Redis, Valkey or memcached. Add a cache with
` + "`komando cache add`" + `.

get, keys and info only read. set changes data (a protected cache asks
first); rm deletes keys, so it also needs --allow-dangerous. ` + "`cache run`" + `
sends any command, but only reads unless --write; commands that flush,
block, run scripts or reconfigure the server also need --allow-dangerous.`,
		Example: `  komando cache add prod-redis redis://default@10.0.0.7:6379/0 --via web1 --ask-password
  komando cache info prod-redis
  komando cache keys prod-redis 'session:*'
  komando cache get prod-redis session:42
  komando cache set prod-redis maintenance on --ttl 30m --dry-run`,
	}
	c.AddCommand(connAddCmdFor("cache"), cacheGetCmd(), cacheKeysCmd(), cacheInfoCmd(), cacheSetCmd(), cacheRmCmd(), cacheRunCmd())
	return c
}

type cacheFn func(st *store.State, c *store.Conn, rc cachex.Store) (any, error)

// withCache opens the conn's client, runs fn, and audits the action.
func withCache(ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn cacheFn) error {
	return withCachePreview(ctx, name, connExpr, v, rec, fn, nil)
}

// withCachePreview is withCache with a dry-run preview: for a change,
// --dry-run runs preview (which only reads) instead of fn.
func withCachePreview(ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn, preview cacheFn) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "cache")
	if err != nil {
		return err
	}
	if rec == nil {
		rec = map[string]any{}
	}
	rec["conns"], rec["risk"] = []string{c.Name}, v.Risk.String()
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(st, name, nil, "", false, rec)
		return err
	}
	if v.Risk > driver.RiskRead {
		if err := guardConns(st, []*store.Conn{c}, v); err != nil {
			return fail(err)
		}
		if g.dryRun {
			if preview == nil {
				audit(st, name, nil, "", true, rec)
				out.P.Print(name, map[string]any{"conn": c.Name, "risk": v.Risk.String(), "dry_run": true, "note": "nothing sent: redis cannot roll back"}, nil)
				return nil
			}
			fn = preview
		}
	}
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	timeout := dbTimeout()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rc, err := cachex.OpenStore(cctx, a.Target, a.Password, a.Dial, timeout)
	if err != nil {
		return fail(err)
	}
	defer rc.Close()
	data, err := fn(st, c, rc)
	if err != nil {
		return fail(err)
	}
	audit(st, name, nil, "", true, rec)
	out.P.Print(name, data, nil)
	return nil
}

// connKind is the conn's kind name (redis, memcached, ...), or "".
func connKind(c *store.Conn) string {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return ""
	}
	return t.Kind.Name
}

// cacheKind is the kind of the cache conn expr names, before connecting
// (to check a section or rate a command); "" when it is not known yet.
func cacheKind(expr string) string {
	st, err := loadState()
	if err != nil {
		return ""
	}
	c, err := singleConn(st, expr, "cache")
	if err != nil {
		return ""
	}
	return connKind(c)
}

// cacheIsCluster: the cache conn expr names is a Redis Cluster (?cluster=1).
func cacheIsCluster(expr string) bool {
	st, err := loadState()
	if err != nil {
		return false
	}
	c, err := singleConn(st, expr, "cache")
	if err != nil {
		return false
	}
	t, err := driver.Parse(c.URL)
	return err == nil && t.Cluster
}

func cacheGetCmd() *cobra.Command {
	var limit int
	c := &cobra.Command{
		Use:   "get CONN KEY",
		Short: "Show a key: its type, time to live and value (any type)",
		Example: `  komando cache get prod-redis session:42
  komando cache get prod-redis leaderboard --limit 10`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 {
				return out.Usage("--limit is the most items to show: 1 or more")
			}
			return withCache(cmd.Context(), "cache.get", args[0], driver.Verdict{}, map[string]any{"key": args[1]},
				func(st *store.State, _ *store.Conn, rc cachex.Store) (any, error) {
					return rc.Get(cmd.Context(), args[1], int64(limit), maxOutput(st))
				})
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 100, "the most items to show of a hash, list, set or sorted set")
	return c
}

type keyList struct {
	Conn    string   `json:"conn"`
	Pattern string   `json:"pattern"`
	Keys    []string `json:"keys"`
	Count   int      `json:"count"`
	More    bool     `json:"more"` // more keys match; narrow the pattern or raise --limit
}

func (l keyList) Text() string {
	if len(l.Keys) == 0 {
		if l.Pattern == "" || l.Pattern == "*" {
			return noneYet("cache keys", "")
		}
		return noneMatch("cache keys", cachex.Quote(l.Pattern))
	}
	var sb strings.Builder
	for _, k := range l.Keys {
		sb.WriteString(cachex.Quote(k) + "\n")
	}
	if l.More {
		fmt.Fprintf(&sb, "(first %d keys; more match: narrow the pattern or raise --limit)\n", l.Count)
	}
	return sb.String()
}

func cacheKeysCmd() *cobra.Command {
	var limit int
	c := &cobra.Command{
		Use:     "keys CONN [PATTERN]",
		Aliases: []string{"list", "ls"},
		Short:   "List keys matching a pattern (uses SCAN, so a big cache is not blocked)",
		Example: `  komando cache keys prod-redis 'session:*'
  komando cache keys prod-redis --limit 1000`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 {
				return out.Usage("--limit is the most keys to return: 1 or more")
			}
			pattern := "*"
			if len(args) == 2 {
				pattern = args[1]
			}
			return withCache(cmd.Context(), "cache.keys", args[0], driver.Verdict{}, map[string]any{"pattern": pattern},
				func(_ *store.State, c *store.Conn, rc cachex.Store) (any, error) {
					keys, more, err := rc.Keys(cmd.Context(), pattern, limit)
					if err != nil {
						return nil, err
					}
					sort.Strings(keys)
					if more {
						out.P.CutNoted()
					}
					return keyList{Conn: c.Name, Pattern: pattern, Keys: keys, Count: len(keys), More: more}, nil
				})
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 100, "the most keys to return")
	return c
}

func cacheInfoCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:   "info CONN [SECTION]",
		Short: "Server summary: version, role, memory, clients, keys, hit rate",
		Long: `Without arguments, a short summary: version, role, uptime, memory use and
limit, eviction policy, clients, keys per database and the hit rate. A
SECTION (server, clients, memory, persistence, stats, replication, cpu,
commandstats, keyspace, ...) or --all shows the raw INFO fields.`,
		Example: `  komando cache info prod-redis
  komando cache info prod-redis memory
  komando cache info prod-redis --all`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			section := ""
			if len(args) == 2 {
				section = strings.ToLower(args[1])
				if secs := cachex.SectionsFor(cacheKind(args[0])); !slices.Contains(secs, section) {
					return out.Usage("unknown INFO section %q; pick one of: %s", args[1], strings.Join(secs, ", "))
				}
				if all {
					return out.Usage("give a SECTION or --all, not both")
				}
			}
			return withCache(cmd.Context(), "cache.info", args[0], driver.Verdict{}, nil,
				func(_ *store.State, c *store.Conn, rc cachex.Store) (any, error) {
					info, err := rc.Info(cmd.Context(), section)
					if err != nil {
						return nil, err
					}
					if section == "" && !all {
						return cacheSummary{Conn: c.Name, Summary: cachex.SummarizeFor(connKind(c), info)}, nil
					}
					if len(info) == 0 {
						return nil, out.Errf(out.ExitNotFound, "NOT_FOUND", "this server has no such section; try `komando cache info CONN --all`", "INFO %s returned nothing", section).About("cache_info_section")
					}
					return cacheInfo{Conn: c.Name, Info: info}, nil
				})
		},
	}
	c.Flags().BoolVarP(&all, "all", "a", false, "every field of the default INFO sections")
	return c
}

type cacheSummary struct {
	Conn    string         `json:"conn"`
	Summary cachex.Summary `json:"summary"`
}

func (d cacheSummary) Text() string {
	s := d.Summary
	var rows [][]string
	add := func(k, v string) { rows = append(rows, []string{k + ":", v}) }
	version := s.Version
	if s.Mode != "" {
		version += " (" + s.Mode + ")"
	}
	add("version", version)
	add("role", s.Role)
	add("uptime", humanAge(time.Duration(s.UptimeSeconds)*time.Second))
	mem := humanBytes(s.UsedMemory) + " used, no limit"
	if s.MaxMemory > 0 {
		mem = humanBytes(s.UsedMemory) + " used of " + humanBytes(s.MaxMemory)
	}
	if s.EvictionPolicy != "" {
		mem += " (eviction: " + s.EvictionPolicy + ")"
	}
	add("memory", mem)
	add("clients", fmt.Sprint(s.Clients))
	if len(s.Keys) == 0 {
		add("keys", "0")
	}
	for _, db := range sortedKeys(s.Keys) {
		add("keys "+db, fmt.Sprintf("%d (%d with a ttl)", s.Keys[db], s.Expires[db]))
	}
	if s.HitRate != nil {
		add("hit rate", fmt.Sprintf("%.1f%% (%d hits, %d misses)", *s.HitRate*100, s.Hits, s.Misses))
	} else {
		add("hit rate", "- (no reads yet)")
	}
	tab := layoutTable([]string{"", ""}, rows)
	return tab[strings.Index(tab, "\n")+1:] + "(all fields: --all, or a section such as memory or stats)\n"
}

type cacheInfo struct {
	Conn string                       `json:"conn"`
	Info map[string]map[string]string `json:"info"`
}

// Text prints the sections the way INFO does.
func (d cacheInfo) Text() string {
	var b strings.Builder
	for i, sec := range sortedKeys(d.Info) {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "# %s\n", sec)
		for _, k := range sortedKeys(d.Info[sec]) {
			fmt.Fprintf(&b, "%s:%s\n", k, d.Info[sec][k])
		}
	}
	return b.String()
}

func cacheSetCmd() *cobra.Command {
	var ttlFlag string
	c := &cobra.Command{
		Use:   "set CONN KEY VALUE",
		Short: "Set a string key, replacing any old value",
		Example: `  komando cache set prod-redis feature:dark-mode on
  komando cache set prod-redis maintenance true --ttl 30m
  komando cache set prod-redis report:weekly done --ttl 7d`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			ttl, err := parseTTL(ttlFlag)
			if err != nil {
				return err
			}
			if err := refuseHiddenWrite(args[1], args[2]); err != nil {
				return err
			}
			result := func(c *store.Conn) cacheSet {
				res := cacheSet{Conn: c.Name, Key: args[1]}
				if ttl > 0 {
					secs := int64(ttl / time.Second)
					res.TTL = &secs
				}
				return res
			}
			return withCachePreview(cmd.Context(), "cache.set", args[0], driver.Verdict{Risk: driver.RiskWrite}, map[string]any{"key": args[1]},
				func(_ *store.State, c *store.Conn, rc cachex.Store) (any, error) {
					if err := rc.Set(cmd.Context(), args[1], args[2], ttl); err != nil {
						return nil, err
					}
					return result(c), nil
				},
				func(_ *store.State, c *store.Conn, rc cachex.Store) (any, error) {
					replaces, err := rc.Exists(cmd.Context(), args[1])
					if err != nil {
						return nil, err
					}
					res := result(c)
					res.Replaces, res.DryRun = &replaces, true
					return res, nil
				})
		},
	}
	spanText(c.Flags(), &ttlFlag, "ttl", "", false, "expire the key after this long (like 30m, 24h, 7d); 0 or left out: never")
	return c
}

// parseTTL reads --ttl: empty or 0 means no expiry; negative is refused.
func parseTTL(s string) (time.Duration, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	return parseAge(s, "--ttl")
}

type cacheSet struct {
	Conn     string `json:"conn"`
	Key      string `json:"key"`
	TTL      *int64 `json:"ttl_seconds"` // null = no expiry, as in `cache get`
	Replaces *bool  `json:"replaces,omitempty"`
	DryRun   bool   `json:"dry_run,omitempty"`
}

func (s cacheSet) Text() string {
	exp := "no expiry"
	if s.TTL != nil {
		exp = "expires in " + humanAge(time.Duration(*s.TTL)*time.Second)
	}
	if s.DryRun {
		return fmt.Sprintf("would set %s (%s; replaces existing: %s)\n", cachex.Quote(s.Key), exp, yesNo(s.Replaces != nil && *s.Replaces))
	}
	return fmt.Sprintf("set %s (%s)\n", cachex.Quote(s.Key), exp)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func cacheRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm CONN KEY...",
		Short: "Delete keys by exact name, never by pattern",
		Example: `  komando cache rm prod-redis session:42 session:43 --dry-run
  komando cache rm prod-redis session:42 session:43 --allow-dangerous`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keys := args[1:]
			askTypes(keys, "keys in "+args[0])
			return withCachePreview(cmd.Context(), "cache.rm", args[0], driver.DataDelete(), map[string]any{"keys": keys},
				func(_ *store.State, c *store.Conn, rc cachex.Store) (any, error) {
					n, err := rc.Del(cmd.Context(), keys...)
					if err != nil {
						return nil, err
					}
					return cacheRmDone{Conn: c.Name, Deleted: n, Keys: keys}, nil
				},
				func(_ *store.State, c *store.Conn, rc cachex.Store) (any, error) {
					p := cacheRmPreview{Conn: c.Name, WouldDelete: []string{}, Missing: []string{}, DryRun: true}
					for _, k := range keys {
						ok, err := rc.Exists(cmd.Context(), k)
						if err != nil {
							return nil, err
						}
						if ok {
							p.WouldDelete = append(p.WouldDelete, k)
						} else {
							p.Missing = append(p.Missing, k)
						}
					}
					return p, nil
				})
		},
	}
}

type cacheRmDone struct {
	Conn    string   `json:"conn"`
	Deleted int64    `json:"deleted"`
	Keys    []string `json:"keys"`
}

func (d cacheRmDone) Text() string {
	if int(d.Deleted) == len(d.Keys) {
		return fmt.Sprintf("deleted %d key%s\n", d.Deleted, plural(int(d.Deleted)))
	}
	return fmt.Sprintf("deleted %d of %d keys (the others did not exist)\n", d.Deleted, len(d.Keys))
}

type cacheRmPreview struct {
	Conn        string   `json:"conn"`
	WouldDelete []string `json:"would_delete"`
	Missing     []string `json:"missing"`
	DryRun      bool     `json:"dry_run"`
}

func (p cacheRmPreview) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "would delete %d key%s:\n", len(p.WouldDelete), plural(len(p.WouldDelete)))
	for _, k := range p.WouldDelete {
		b.WriteString("  " + cachex.Quote(k) + "\n")
	}
	for _, k := range p.Missing {
		b.WriteString("  " + cachex.Quote(k) + " (does not exist)\n")
	}
	return b.String()
}

func cacheRunCmd() *cobra.Command {
	var write bool
	c := &cobra.Command{
		Use:   "run CONN -- COMMAND...",
		Short: "Send any Redis or memcached command (read only by default)",
		Example: `  komando cache run prod-redis -- HGETALL user:42
  komando cache run prod-redis -- ZREVRANGE leaderboard 0 9 WITHSCORES
  komando cache run prod-redis --write -- EXPIRE session:42 3600
  komando cache run prod-redis -- "GET feature:dark-mode"   # one quoted line works too`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			command, err := cachex.SplitCommand(args[1:])
			if err != nil {
				return err
			}
			kind := cacheKind(args[0])
			if kind == "memcached" {
				if command, err = cachex.MemcacheWords(command); err != nil {
					return err
				}
			} else {
				if err := cachex.OneReply(command); err != nil {
					return err
				}
				if cacheIsCluster(args[0]) {
					if err := cachex.ClusterWideProblem(command); err != nil {
						return err
					}
				}
			}
			v := cachex.ClassifyFor(kind, command)
			rec := map[string]any{"command": strings.ToUpper(command[0])} // arguments may be personal data
			if v.Risk > driver.RiskRead && !write {
				st, _ := loadState()
				e := out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG",
					"this command may change data (or is not known to be a read); run it again with --write",
					"%s needs --write", strings.ToUpper(command[0]))
				if len(v.RuleIDs) > 0 {
					e.Message += " and --allow-dangerous: " + strings.Join(v.Reasons, "; ")
					e.Hint = runHint(strings.ToUpper(command[0]), v)
				}
				rec["error"], rec["conns"] = e.Code, []string{args[0]}
				audit(st, "cache.run", nil, "", false, rec)
				return e
			}
			if write {
				if err := refuseHiddenWrite(command...); err != nil {
					return err
				}
			}
			return withCache(cmd.Context(), "cache.run", args[0], v, rec,
				func(_ *store.State, c *store.Conn, rc cachex.Store) (any, error) {
					res, err := rc.Run(cmd.Context(), command)
					if err != nil {
						return nil, err
					}
					if out.P.Mask {
						// CONFIG GET requirepass, ACL LIST ...: reads that show
						// passwords the output masking cannot recognize
						res = cachex.HideSecrets(command, res)
					}
					return cacheReply{Conn: c.Name, Risk: v.Risk.String(), Reply: res}, nil
				})
		},
	}
	c.Flags().BoolVar(&write, "write", false, "allow commands that change data")
	return c
}

// runHint says what to do about a flagged command, from the rule it hit.
func runHint(cmd string, v driver.Verdict) string {
	switch {
	case cmd == "KEYS":
		return "list keys with `komando cache keys CONN 'pattern*'` (uses SCAN, safe on big caches) instead of KEYS"
	case slices.Contains(v.RuleIDs, "data-delete"):
		return "to delete keys, confirm with the user first and use `komando cache rm CONN KEY... --allow-dangerous` (try --dry-run first)"
	}
	return "only if that is intended: confirm with the user first, then run it again with --write --allow-dangerous"
}

type cacheReply struct {
	Conn  string `json:"conn"`
	Risk  string `json:"risk"`
	Reply any    `json:"reply"`
}

func (r cacheReply) Text() string { return cachex.ReplyText(r.Reply) }
