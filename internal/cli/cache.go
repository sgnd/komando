package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/redis/go-redis/v9"
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
		Short:   "Read and change Redis/Valkey caches safely",
		Long: `Work with a redis conn (see ` + "`komando conn`" + `). get, keys and info only read.
set changes data (protected conns need --yes); rm deletes keys, so it also
needs --allow-dangerous. ` + "`cache run`" + ` sends any command, but only reads unless
--write; commands that flush, block, run scripts or reconfigure the server
also need --allow-dangerous.`,
	}
	c.AddCommand(cacheGetCmd(), cacheKeysCmd(), cacheInfoCmd(), cacheSetCmd(), cacheRmCmd(), cacheRunCmd())
	return c
}

// withCache opens the conn's client, runs fn, and audits the action.
func withCache(ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn func(st *store.State, c *store.Conn, rc *redis.Client) (any, error)) error {
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
			audit(st, name, nil, "", true, rec)
			out.P.Print(name, map[string]any{"conn": c.Name, "risk": v.Risk.String(), "dry_run": true, "note": "nothing sent: redis cannot roll back"}, nil)
			return nil
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
	rc, err := cachex.Open(cctx, a.Target, a.Password, a.Dial, timeout)
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

func cacheGetCmd() *cobra.Command {
	var limit int64
	c := &cobra.Command{
		Use:   "get CONN KEY",
		Short: "Show a key: its type, time to live and value (any type)",
		Example: `  komando cache get cache session:42
  komando cache get cache leaderboard --limit 10`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withCache(cmd.Context(), "cache.get", args[0], driver.Verdict{}, map[string]any{"key": args[1]},
				func(st *store.State, _ *store.Conn, rc *redis.Client) (any, error) {
					return cachex.Get(cmd.Context(), rc, args[1], limit, maxOutput(st))
				})
		},
	}
	c.Flags().Int64VarP(&limit, "limit", "n", 100, "max items shown for hashes, lists, sets and sorted sets")
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
	s := strings.Join(l.Keys, "\n")
	if s != "" {
		s += "\n"
	}
	if l.More {
		s += fmt.Sprintf("(first %d keys; more match: narrow the pattern or raise --limit)\n", l.Count)
	}
	return s
}

func cacheKeysCmd() *cobra.Command {
	var limit int
	c := &cobra.Command{
		Use:     "keys CONN [PATTERN]",
		Aliases: []string{"ls"},
		Short:   "List keys matching a pattern (uses SCAN, safe on big caches)",
		Example: `  komando cache keys cache 'session:*'
  komando cache keys cache --limit 1000`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pattern := "*"
			if len(args) == 2 {
				pattern = args[1]
			}
			return withCache(cmd.Context(), "cache.keys", args[0], driver.Verdict{}, map[string]any{"pattern": pattern},
				func(_ *store.State, c *store.Conn, rc *redis.Client) (any, error) {
					keys, more, err := cachex.Keys(cmd.Context(), rc, pattern, limit)
					if err != nil {
						return nil, err
					}
					sort.Strings(keys)
					return keyList{Conn: c.Name, Pattern: pattern, Keys: keys, Count: len(keys), More: more}, nil
				})
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 100, "max keys returned")
	return c
}

func cacheInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info CONN [SECTION]",
		Short: "Server facts: version, memory, clients, keys per database",
		Example: `  komando cache info cache
  komando cache info cache memory`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			section := ""
			if len(args) == 2 {
				section = args[1]
			}
			return withCache(cmd.Context(), "cache.info", args[0], driver.Verdict{}, nil,
				func(_ *store.State, c *store.Conn, rc *redis.Client) (any, error) {
					info, err := cachex.Info(cmd.Context(), rc, section)
					if err != nil {
						return nil, err
					}
					return map[string]any{"conn": c.Name, "info": info}, nil
				})
		},
	}
}

func cacheSetCmd() *cobra.Command {
	var ttl time.Duration
	c := &cobra.Command{
		Use:   "set CONN KEY VALUE",
		Short: "Set a string key (replaces any old value); --ttl to expire it",
		Example: `  komando cache set cache feature:dark-mode on
  komando cache set cache maintenance true --ttl 30m`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withCache(cmd.Context(), "cache.set", args[0], driver.Verdict{Risk: driver.RiskWrite}, map[string]any{"key": args[1]},
				func(_ *store.State, c *store.Conn, rc *redis.Client) (any, error) {
					if err := rc.Set(cmd.Context(), args[1], args[2], ttl).Err(); err != nil {
						return nil, cachex.CmdErr(err)
					}
					return map[string]any{"conn": c.Name, "key": args[1], "ttl_seconds": int64(ttl / time.Second)}, nil
				})
		},
	}
	c.Flags().DurationVar(&ttl, "ttl", 0, "expire the key after this long (e.g. 30m, 24h); 0 = never")
	return c
}

func cacheRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm CONN KEY...",
		Short:   "Delete keys by exact name (no patterns; needs --allow-dangerous)",
		Example: `  komando cache rm cache session:42 session:43 --allow-dangerous`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keys := args[1:]
			return withCache(cmd.Context(), "cache.rm", args[0], driver.DataDelete(), map[string]any{"keys": keys},
				func(_ *store.State, c *store.Conn, rc *redis.Client) (any, error) {
					n, err := rc.Del(cmd.Context(), keys...).Result()
					if err != nil {
						return nil, cachex.CmdErr(err)
					}
					return map[string]any{"conn": c.Name, "deleted": n, "keys": keys}, nil
				})
		},
	}
}

func cacheRunCmd() *cobra.Command {
	var write bool
	c := &cobra.Command{
		Use:   "run CONN -- COMMAND [ARG...]",
		Short: "Send any Redis command; read-only unless --write",
		Example: `  komando cache run cache -- HGETALL user:42
  komando cache run cache -- ZREVRANGE leaderboard 0 9 WITHSCORES
  komando cache run cache --write -- EXPIRE session:42 3600`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := args[1:]
			v := cachex.Classify(command)
			rec := map[string]any{"command": strings.ToUpper(command[0])} // arguments may be personal data
			if v.Risk > driver.RiskRead && !write {
				st, _ := loadState()
				e := out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG",
					"this command may change data (or is not known to be a read); re-run with --write",
					"%s needs --write", strings.ToUpper(command[0]))
				if len(v.RuleIDs) > 0 {
					e.Message += " and --allow-dangerous: " + strings.Join(v.Reasons, "; ")
					e.Hint = "confirm with the user first; for listing keys use `komando cache keys` instead of KEYS"
				}
				rec["error"], rec["conns"] = e.Code, []string{args[0]}
				audit(st, "cache.run", nil, "", false, rec)
				return e
			}
			return withCache(cmd.Context(), "cache.run", args[0], v, rec,
				func(_ *store.State, c *store.Conn, rc *redis.Client) (any, error) {
					res, err := cachex.Run(cmd.Context(), rc, command)
					if err != nil {
						return nil, err
					}
					return cacheReply{Conn: c.Name, Risk: v.Risk.String(), Reply: res}, nil
				})
		},
	}
	c.Flags().BoolVar(&write, "write", false, "allow commands that change data")
	return c
}

type cacheReply struct {
	Conn  string `json:"conn"`
	Risk  string `json:"risk"`
	Reply any    `json:"reply"`
}

func (r cacheReply) Text() string {
	switch x := r.Reply.(type) {
	case nil:
		return "(nil)\n"
	case []any:
		var sb strings.Builder
		tw := tabwriter.NewWriter(&sb, 0, 2, 1, ' ', 0)
		for i, e := range x {
			fmt.Fprintf(tw, "%d)\t%v\n", i+1, cellText(e, true))
		}
		tw.Flush()
		return sb.String()
	}
	return fmt.Sprintln(cellText(r.Reply, true))
}
