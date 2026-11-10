package cli

import (
	"context"
	"database/sql"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `db user` and `db grant`: accounts and what they may do, with passwords
// from a secret reference (never typed on the command line, never shown).

func dbUserCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "user",
		Short: "Database users: list, add, change the password, remove",
		Long: `Passwords come from a secret reference (--password-ref secret:NAME, vault:...,
aws-sm:...), so they are never typed on a command line or shown. PostgreSQL
gets a SCRAM-SHA-256 verifier komando computes, so the password itself never
reaches the server or its logs. Adding a user or changing a password is a
change (protected conns need --yes); removing one needs --allow-dangerous.`,
	}
	c.AddCommand(dbUserLsCmd(), dbUserChangeCmd("add"), dbUserChangeCmd("passwd"), dbUserChangeCmd("rm"))
	return c
}

func dbUserLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls CONN",
		Short:   "List users and roles (login, superuser, member of ...; MySQL: host, locked)",
		Example: "  komando db user ls prod-db",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return readDB(cmd.Context(), "db.user.ls", args[0], func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error) {
				rows, err := dbx.Users(ctx, db, c.Kind, connTimeout(c))
				if err != nil {
					return nil, err
				}
				if rows == nil {
					rows = []map[string]any{}
				}
				return map[string]any{"conn": c.Name, "count": len(rows), "users": rows}, nil
			})
		},
	}
}

func dbUserChangeCmd(action string) *cobra.Command {
	var ref, host string
	var noLogin bool
	parts := map[string][3]string{
		"add":    {"add CONN NAME --password-ref REF", "Create a user with a password from a secret reference", "  komando db user add prod-db app_ro --password-ref secret:app-ro-pass"},
		"passwd": {"passwd CONN NAME --password-ref REF", "Set a user's password from a secret reference (rotation)", "  komando db user passwd prod-db app_ro --password-ref secret:app-ro-pass-2"},
		"rm":     {"rm CONN NAME", "Remove a user (needs --allow-dangerous)", "  komando db user rm prod-db old_app --allow-dangerous"},
	}[action]
	c := &cobra.Command{
		Use:     parts[0],
		Short:   parts[1],
		Example: parts[2],
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			u := dbx.UserSpec{Name: args[1], Host: host, NoLogin: noLogin}
			switch {
			case action == "rm" && ref != "":
				return out.Usage("rm takes no --password-ref")
			case action == "passwd" && ref == "", action == "add" && ref == "" && !noLogin:
				return out.Usage("give the password as a reference: --password-ref secret:NAME (set it with `komando secret set NAME`)")
			case ref != "" && !vault.ValidRef(ref):
				return out.Usage("--password-ref: %s", vault.RefHelp())
			}
			v := driver.Verdict{Risk: driver.RiskWrite, RuleIDs: []string{"db-user"}, Reasons: []string{"db user " + action + " " + args[1]}}
			if action == "rm" {
				v = driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"db-user-rm"}, Reasons: []string{"removes the user " + args[1]}}
			}
			return changeDB(cmd.Context(), "db.user."+action, args[0], v, map[string]any{"user": args[1]},
				func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error) {
					if ref != "" {
						// the password goes to the conn's server, which could be the agent's own
						if err := guardSecretUse([]string{ref}, connPlace(c).dest+" as the password of database user "+args[1]+" (conn "+c.Name+")"); err != nil {
							return nil, err
						}
						pw, err := vault.Resolve(ref)
						if err != nil {
							return nil, out.Errf(out.ExitNotFound, "SECRET_NOT_FOUND", "set it with `komando secret set NAME`", "--password-ref: %v", err)
						}
						if pw == "" {
							return nil, out.Usage("the password in %s is empty", ref)
						}
						u.Password = pw
					}
					shown, err := dbx.UserChange(ctx, db, c.Kind, action, u, g.dryRun)
					res := map[string]any{"conn": c.Name, "user": args[1], "sql": shown}
					if g.dryRun {
						res["dry_run"] = true
					} else if err == nil {
						res["done"] = action
					}
					return res, err
				})
		},
	}
	if action != "rm" {
		c.Flags().StringVar(&ref, "password-ref", "", "the password: secret:NAME | vault:PATH#FIELD | aws-sm:NAME | ...")
	}
	c.Flags().StringVar(&host, "from", "", "MySQL: where the user may connect from (the account host; default %, anywhere)")
	if action == "add" {
		c.Flags().BoolVar(&noLogin, "no-login", false, "PostgreSQL: a role that cannot log in (a group to grant to users)")
	}
	return c
}

// changeDB is readDB for a change: the safety check first, then fn on a
// writable connection, then the audit (no password in it).
func changeDB(ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "db")
	if err != nil {
		return err
	}
	if c.Kind == "snowflake" { // users and grants are read-only here
		return dbx.SFNoUserChange(strings.ReplaceAll(name, ".", " "))
	}
	if err := guardConns(st, []*store.Conn{c}, v); err != nil && !g.dryRun {
		audit(st, name, nil, "", false, map[string]any{"conns": []string{c.Name}, "blocked": toErr(err).Code})
		return err
	}
	db, closeDB, err := openDB(ctx, st, c, g.dryRun)
	if err != nil {
		return err
	}
	defer closeDB()
	res, err := fn(ctx, c, db)
	if !g.dryRun {
		r := map[string]any{"conns": []string{c.Name}, "risk": v.Risk.String()}
		for k, x := range rec {
			r[k] = x
		}
		if m, ok := res.(map[string]any); ok && m["sql"] != nil {
			r["sql"] = m["sql"] // the shown form: the password is hidden
		}
		audit(st, name, nil, "", err == nil, r)
	}
	if err != nil {
		return err
	}
	out.P.Print(name, res, nil)
	return nil
}

func dbGrantCmd(revoke bool) *cobra.Command {
	var privs, on, role, host string
	verb := "grant"
	if revoke {
		verb = "revoke"
	}
	c := &cobra.Command{
		Use:   verb + " CONN USER (--privileges P,... --on OBJECT | --role ROLE)",
		Short: map[bool]string{false: "Give a user privileges on a database, schema or table (or a role)", true: "Take privileges (or a role) away from a user"}[revoke],
		Long: `OBJECT for PostgreSQL: database:NAME, schema:NAME, table:[SCHEMA.]TABLE or
all-tables:SCHEMA; --role ROLE makes the user a member of ROLE. For MySQL:
DB.* , DB.TABLE or *.* (with --from for the account host). For ClickHouse:
DB.*, DB.TABLE or *.*, or database:DB, table:DB.TABLE. Snowflake: not
available (db grants reads them). --dry-run shows
the statement.`,
		Example: `  komando db ` + verb + ` prod-db app_ro --privileges SELECT --on all-tables:public
  komando db ` + verb + ` prod-db app_ro --role readers
  komando db ` + verb + ` shop-db app --privileges SELECT,INSERT,UPDATE --on 'shop.*'`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			gr := dbx.Grant{User: args[1], Host: host, On: on, Role: role, Revoke: revoke}
			if privs != "" {
				gr.Privs = strings.Split(privs, ",")
			}
			if (role == "") == (privs == "") {
				return out.Usage("give --privileges with --on, or --role")
			}
			if privs != "" && on == "" {
				return out.Usage("--privileges needs --on OBJECT")
			}
			v := driver.Verdict{Risk: driver.RiskWrite, RuleIDs: []string{"db-grant"}, Reasons: []string{"db " + verb + " for " + args[1]}}
			return changeDB(cmd.Context(), "db."+verb, args[0], v, map[string]any{"user": args[1]},
				func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error) {
					stmt, err := dbx.GrantSQL(ctx, db, c.Kind, gr)
					if err != nil {
						return nil, err
					}
					res := map[string]any{"conn": c.Name, "user": args[1], "sql": stmt}
					if g.dryRun {
						res["dry_run"] = true
						return res, nil
					}
					if _, err := db.ExecContext(ctx, stmt); err != nil {
						return res, dbExecErr(err)
					}
					res["done"] = verb
					return res, nil
				})
		},
	}
	c.Flags().StringVar(&privs, "privileges", "", "comma-separated: SELECT,INSERT,UPDATE,DELETE,... or ALL")
	c.Flags().StringVar(&on, "on", "", "what the privileges are on (see above)")
	c.Flags().StringVar(&role, "role", "", "PostgreSQL: make the user a member of this role")
	c.Flags().StringVar(&host, "from", "", "MySQL: where the user connects from (the account host; default %)")
	return c
}

func dbGrantsCmd() *cobra.Command {
	var host string
	c := &cobra.Command{
		Use:     "grants CONN USER",
		Short:   "What a user may do: privileges on tables and databases, and its roles",
		Example: "  komando db grants prod-db app_ro",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return readDB(cmd.Context(), "db.grants", args[0], func(ctx context.Context, c *store.Conn, db *sql.DB) (any, error) {
				rows, err := dbx.Grants(ctx, db, c.Kind, args[1], host, connTimeout(c))
				if err != nil {
					return nil, err
				}
				if rows == nil {
					rows = []map[string]any{}
				}
				return map[string]any{"conn": c.Name, "user": args[1], "grants": rows}, nil
			})
		},
	}
	c.Flags().StringVar(&host, "from", "", "MySQL: where the user connects from (the account host; default %)")
	return c
}

func dbExecErr(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "does not exist") || strings.Contains(msg, "1146") || strings.Contains(msg, "1133") {
		return out.Errf(out.ExitNotFound, "DB_NOT_FOUND", "check the user and the object names", "%s", msg)
	}
	if strings.Contains(msg, "permission denied") || strings.Contains(msg, "1044") || strings.Contains(msg, "1142") || strings.Contains(msg, "Access denied") {
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "the conn's user may only grant what it has itself (WITH GRANT OPTION)", "%s", msg)
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "read the message; the statement is in data.sql", "%s", msg)
}
