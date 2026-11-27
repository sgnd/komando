package cli

import (
	"context"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// `cache redis raw` is read-only unless --write. Redis has no read-only
// mode, so without --write only commands known to be reads are sent.

func cacheCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "cache",
		Aliases: []string{"redis"},
		Short:   "Caches (Redis, Valkey, memcached): save them, run commands",
		Long: `Save a cache with ` + "`komando cache redis add`" + `, then run its native commands with
` + "`cache redis raw`" + `. raw only reads unless --write (a protected cache asks first);
commands that flush, block, run scripts, delete keys or reconfigure the server
also need --allow-dangerous.`,
		Example: `  komando cache redis add prod-redis redis://default@10.0.0.7:6379/0 --via web1 --ask-password
  komando cache redis raw prod-redis GET session:42
  komando cache redis raw prod-redis SET maintenance on --write`,
	}
}

type cacheFn func(st *store.State, c *store.Conn, rc cachex.Store) (any, error)

// withCache opens the conn's client, runs fn, and audits the action.
func withCache(cl *call, ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn cacheFn) error {
	return withCachePreview(cl, ctx, name, connExpr, v, rec, fn, nil)
}

// withCachePreview is withCache with a dry-run preview: for a change,
// --dry-run runs preview (which only reads) instead of fn.
func withCachePreview(cl *call, ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn, preview cacheFn) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(cl, st, connExpr, "cache")
	if err != nil {
		return err
	}
	if rec == nil {
		rec = map[string]any{}
	}
	rec["conns"], rec["risk"] = []string{c.Name}, v.Risk.String()
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(cl, st, name, nil, "", false, rec)
		return err
	}
	if v.Risk > driver.RiskRead {
		if err := GuardConns(cl, st, []*store.Conn{c}, v); err != nil {
			return fail(err)
		}
		if cl.dryRun() {
			if preview == nil {
				audit(cl, st, name, nil, "", true, rec)
				cl.out.Print(name, map[string]any{"conn": c.Name, "risk": v.Risk.String(), "dry_run": true, "note": "nothing sent: redis cannot roll back"}, nil)
				return nil
			}
			fn = preview
		}
	}
	a, err := openAccess(cl, ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	timeout := dbTimeout(cl)
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
	audit(cl, st, name, nil, "", true, rec)
	cl.out.Print(name, data, nil)
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
func cacheKind(cl *call, expr string) string {
	st, err := loadState()
	if err != nil {
		return ""
	}
	c, err := singleConn(cl, st, expr, "cache")
	if err != nil {
		return ""
	}
	return connKind(c)
}

// cacheIsCluster: the cache conn expr names is a Redis Cluster (?cluster=1).
func cacheIsCluster(cl *call, expr string) bool {
	st, err := loadState()
	if err != nil {
		return false
	}
	c, err := singleConn(cl, st, expr, "cache")
	if err != nil {
		return false
	}
	t, err := driver.Parse(c.URL)
	return err == nil && t.Cluster
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func cacheRunCmd() *cobra.Command {
	var write bool
	c := &cobra.Command{
		Use:   "run CONN -- COMMAND...",
		Short: "Send any Redis or memcached command (read only by default)",
		Example: `  komando cache redis raw prod-redis -- HGETALL user:42
  komando cache redis raw prod-redis -- ZREVRANGE leaderboard 0 9 WITHSCORES
  komando cache redis raw prod-redis --write -- EXPIRE session:42 3600
  komando cache redis raw prod-redis -- "GET feature:dark-mode"   # one quoted line works too`,
		Args: cobra.MinimumNArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			command, err := cachex.SplitCommand(args[1:])
			if err != nil {
				return err
			}
			kind := cacheKind(cl, args[0])
			if kind == "memcached" {
				if command, err = cachex.MemcacheWords(command); err != nil {
					return err
				}
			} else {
				if err := cachex.OneReply(command); err != nil {
					return err
				}
				if cacheIsCluster(cl, args[0]) {
					if err := cachex.ClusterWideProblem(command); err != nil {
						return err
					}
				}
			}
			v := cachex.ClassifyFor(kind, command)
			rec := map[string]any{"cache_command": strings.ToUpper(command[0])} // arguments may be personal data
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
				audit(cl, st, "cache.run", nil, "", false, rec)
				return e
			}
			if write {
				if err := refuseHiddenWrite(command...); err != nil {
					return err
				}
			}
			return withCache(cl, cmd.Context(), "cache.run", args[0], v, rec,
				func(_ *store.State, c *store.Conn, rc cachex.Store) (any, error) {
					res, err := rc.Run(cmd.Context(), command)
					if err != nil {
						return nil, err
					}
					if cl.out.Mask {
						// CONFIG GET requirepass, ACL LIST ...: reads that show
						// passwords the output masking cannot recognize
						res = cachex.HideSecrets(command, res)
					}
					return cacheReply{Conn: c.Name, Risk: v.Risk.String(), Reply: res}, nil
				})
		}),
	}
	c.Flags().BoolVar(&write, "write", false, "allow commands that change data")
	return c
}

// runHint says what to do about a flagged command, from the rule it hit.
func runHint(cmd string, v driver.Verdict) string {
	switch {
	case cmd == "KEYS":
		return "list keys with SCAN instead of KEYS (safe on big caches): `komando cache redis raw NAME -- SCAN 0 MATCH 'pattern*'`"
	case slices.Contains(v.RuleIDs, "data-delete"):
		return "to delete keys, confirm with the user first, then run it again with --write --allow-dangerous (try --dry-run first)"
	}
	return "only if that is intended: confirm with the user first, then run it again with --write --allow-dangerous"
}

type cacheReply struct {
	Conn  string `json:"conn"`
	Risk  string `json:"risk"`
	Reply any    `json:"reply"`
}

func (r cacheReply) Text() string { return cachex.ReplyText(r.Reply) }

// The cache type of the table: komando cache redis|memcached VERB. The
// inventory verbs are the shared ones (inventoryHandlers); raw is today's
// `cache run`; its entry in personalCmds and the ssh-gate list moved with it (moveType).

func init() {
	inventoryHandlers("cache", "redis", "memcached")
	for _, p := range []string{"redis", "memcached"} {
		leafBodies[capability.Key{Type: "cache", Provider: p, Verb: "raw"}] = cacheRunCmd
		handlers[capability.Key{Type: "cache", Provider: p, Verb: "raw"}] = func(cl *call, ctx context.Context, in leafInput) error {
			return runBody(cl, ctx, cacheRunCmd(), in, nil)
		}
	}
	moveType("cache")
	groupShorts["cache redis"] = "Redis caches: save them, and send them a command"
	groupShorts["cache memcached"] = "Memcached caches: save them, and send them a command"
}
