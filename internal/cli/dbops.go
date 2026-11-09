package cli

import (
	"context"
	"database/sql"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// readDB opens a db conn read-only, runs fn and prints its answer.
func readDB(ctx context.Context, name, connExpr string, fn func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "db")
	if err != nil {
		return err
	}
	db, closeDB, err := openDB(ctx, st, c, true)
	if err != nil {
		return err
	}
	defer closeDB()
	res, err := fn(ctx, c, db)
	if err != nil {
		return err
	}
	out.P.Print(name, res, nil)
	return nil
}

func dbInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "info CONN",
		Short:   "Version, uptime, size, connections, and whether it is a primary or a replica",
		Example: "  komando db info prod-db",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if st, c, ok := mongoConn(args[0]); ok {
				return runMongoInfo(cmd.Context(), st, c)
			}
			return readDB(cmd.Context(), "db.info", args[0], func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error) {
				res, err := dbx.Info(ctx, db, c.Kind, connTimeout(c))
				if err != nil {
					return nil, err
				}
				res["conn"], res["kind"] = c.Name, c.Kind
				return dbInfoData(res), nil
			})
		},
	}
}

func dbActivityCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:   "activity CONN",
		Short: "Sessions running something now: pid, user, how long, what",
		Example: `  komando db activity prod-db
  komando db activity prod-db --all`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return readDB(cmd.Context(), "db.activity", args[0], func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error) {
				rows, err := dbx.Activity(ctx, db, c.Kind, all, connTimeout(c))
				if err != nil {
					return nil, err
				}
				return activityData{Conn: c.Name, Count: len(rows), Sessions: rows}, nil
			})
		},
	}
	c.Flags().BoolVar(&all, "all", false, "include idle sessions")
	return c
}

func dbLocksCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "locks CONN",
		Short:   "Sessions waiting for a lock, and the session that holds it",
		Example: "  komando db locks prod-db",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return readDB(cmd.Context(), "db.locks", args[0], func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error) {
				rows, err := dbx.Locks(ctx, db, c.Kind, connTimeout(c))
				if err != nil {
					return nil, err
				}
				return locksData{Conn: c.Name, Count: len(rows), Waits: rows}, nil
			})
		},
	}
}

func dbSizesCmd() *cobra.Command {
	var limit int
	c := &cobra.Command{
		Use:     "sizes CONN",
		Short:   "Databases, and the biggest tables and indexes",
		Example: "  komando db sizes prod-db -n 10",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return readDB(cmd.Context(), "db.sizes", args[0], func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error) {
				res, err := dbx.Sizes(ctx, db, c.Kind, limit, connTimeout(c))
				if err != nil {
					return nil, err
				}
				res["conn"], res["kind"] = c.Name, c.Kind
				return sizesData(res), nil
			})
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 20, "how many tables and indexes")
	return c
}

func dbKillCmd() *cobra.Command {
	var session bool
	c := &cobra.Command{
		Use:   "kill CONN PID",
		Short: "Stop a session's running query (--session ends the connection)",
		Long: `Find the PID with ` + "`komando db activity`" + ` or ` + "`komando db locks`" + `. Without --session
only the running query stops (its transaction rolls back) and the client
stays connected. --dry-run shows the session it would stop. SQL Server can
only end a session (KILL), so there it needs --session. On Oracle the PID
is the SID that db activity shows.`,
		Example: `  komando db kill prod-db 4821 --dry-run
  komando db kill prod-db 4821
  komando db kill prod-db 4821 --session --allow-dangerous`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pid, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil || pid <= 0 {
				return out.Usage("PID must be a session number from `komando db activity`")
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			c, err := singleConn(st, args[0], "db")
			if err != nil {
				return err
			}
			if c.Kind == "sqlserver" && !session {
				return dbx.KillNeedsSession()
			}
			v := driver.Verdict{Risk: driver.RiskWrite, RuleIDs: []string{"db-kill"}, Reasons: []string{"stops the running query of session " + args[1]}}
			if session {
				v = driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"db-kill-session"}, Reasons: []string{"ends session " + args[1] + " (its client loses the connection)"}}
			}
			if !g.dryRun {
				if err := guardConns(st, []*store.Conn{c}, v); err != nil {
					return err
				}
			}
			db, closeDB, err := openDB(cmd.Context(), st, c, false)
			if err != nil {
				return err
			}
			defer closeDB()
			s, err := dbx.Session(cmd.Context(), db, c.Kind, pid)
			if err != nil {
				return err
			}
			action := map[bool]string{true: "end session", false: "cancel query"}[session]
			if g.dryRun {
				out.P.Print("db.kill", map[string]any{"conn": c.Name, "would": action, "session": s, "dry_run": true}, nil)
				return nil
			}
			err = dbx.Kill(cmd.Context(), db, c.Kind, pid, session)
			audit(st, "db.kill", nil, "", err == nil, map[string]any{"conns": []string{c.Name}, "pid": pid, "action": action})
			if err != nil {
				return err
			}
			out.P.Print("db.kill", map[string]any{"conn": c.Name, "done": action, "session": s}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&session, "session", false, "end the whole connection, not just its query")
	return c
}
