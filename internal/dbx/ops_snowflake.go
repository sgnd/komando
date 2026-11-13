package dbx

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// Snowflake's views for db info, activity, sizes and kill. A running
// query has a query ID (text) and a session number; db activity shows a
// pid komando makes from the query ID (53 bits of its FNV-1a hash), which
// db kill takes. Running queries come from the current database's
// INFORMATION_SCHEMA.QUERY_HISTORY: those of the conn's user, and of the
// warehouses its role may monitor.

func snowflakeInfo(ctx context.Context, db *sql.DB) (map[string]any, error) {
	res, err := oneRow(ctx, db, `
SELECT CURRENT_VERSION() AS "version", CURRENT_ACCOUNT() AS "account", CURRENT_REGION() AS "region",
       CURRENT_USER() AS "user", CURRENT_ROLE() AS "role", CURRENT_WAREHOUSE() AS "warehouse",
       CURRENT_DATABASE() AS "database", CURRENT_SCHEMA() AS "schema"`)
	if err != nil {
		return nil, err
	}
	// needs a warehouse and a database; without them the rest stays out
	if r, err := oneRow(ctx, db, `
SELECT SUM(bytes) AS "size_bytes", COUNT(*) AS "tables" FROM INFORMATION_SCHEMA.TABLES WHERE table_type = 'BASE TABLE'`); err == nil {
		for k, v := range r {
			res[k] = v
		}
	}
	return res, nil
}

const sfRunning = `
SELECT query_id AS "query_id", session_id AS "session_id", user_name AS "user", role_name AS "role",
       warehouse_name AS "warehouse", database_name AS "database", query_tag AS "app", execution_status AS "state",
       DATEDIFF('second', start_time, CURRENT_TIMESTAMP()) AS "running_seconds", LEFT(query_text, 500) AS "query"
FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY(RESULT_LIMIT => 10000))
WHERE execution_status IN ('RUNNING', 'QUEUED', 'BLOCKED', 'RESUMING_WAREHOUSE') AND session_id <> CURRENT_SESSION()
ORDER BY start_time`

func snowflakeActivity(ctx context.Context, db *sql.DB) ([]map[string]any, error) {
	rows, err := rowsOf(ctx, db, sfRunning)
	for _, r := range rows {
		r["pid"] = sfPID(fmt.Sprint(r["query_id"]))
	}
	return rows, err
}

// sfPID is a query's number for db activity and db kill.
func sfPID(queryID string) int64 {
	h := fnv.New64a()
	h.Write([]byte(queryID))
	return int64(h.Sum64() & (1<<53 - 1))
}

func snowflakeSizes(ctx context.Context, db *sql.DB, limit int, res map[string]any) error {
	var err error
	if res["databases"], err = rowsOf(ctx, db, `
SELECT CURRENT_DATABASE() AS "name", SUM(bytes) AS "bytes" FROM INFORMATION_SCHEMA.TABLES WHERE table_type = 'BASE TABLE'`); err != nil {
		return err
	}
	res["tables"], err = rowsOf(ctx, db, fmt.Sprintf(`
SELECT table_schema AS "schema", table_name AS "name", bytes AS "total_bytes", row_count AS "rows"
FROM INFORMATION_SCHEMA.TABLES WHERE table_type = 'BASE TABLE'
ORDER BY bytes DESC NULLS LAST LIMIT %d`, max(limit, 1)))
	return err
}

var sfQueryID = regexp.MustCompile(`^[0-9a-fA-F-]{20,64}$`)

// snowflakeKill cancels the running query db activity showed as pid, or
// with session ends its session (SYSTEM$ABORT_SESSION).
func snowflakeKill(ctx context.Context, db *sql.DB, pid int64, session bool) error {
	rows, err := snowflakeActivity(ctx, db)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r["pid"] != pid {
			continue
		}
		if session {
			_, err = db.ExecContext(ctx, "SELECT SYSTEM$ABORT_SESSION(?)", r["session_id"])
			return err
		}
		id := fmt.Sprint(r["query_id"])
		if !sfQueryID.MatchString(id) {
			return fmt.Errorf("unexpected query ID %q", id)
		}
		_, err = db.ExecContext(ctx, "SELECT SYSTEM$CANCEL_QUERY(?)", id)
		return err
	}
	return out.Errf(out.ExitNotFound, "SESSION_NOT_FOUND", "list running queries with `komando db activity CONN`", "no running query %d", pid)
}

// sfNoLocks is db locks on Snowflake.
func sfNoLocks() error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"`komando db activity CONN` shows queries with state BLOCKED; SHOW LOCKS IN ACCOUNT (with --write, as an account admin) lists the locks",
		"db locks is not available for snowflake")
}

// SFNoUserChange is db user add/passwd/rm and db grant/revoke on
// Snowflake: this version reads users and grants only.
func SFNoUserChange(what string) error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"run the statement yourself with `komando db query CONN --write` (CREATE USER, GRANT ROLE ...: it needs --allow-dangerous, so ask the user first); `db user list` and `db user show` work",
		"%s is not available for snowflake", what)
}

func snowflakeUsers(ctx context.Context, db *sql.DB) ([]map[string]any, error) {
	users, err := rowsOf(ctx, db, "SHOW USERS")
	if err != nil {
		return nil, snowflakeErr(err)
	}
	res := []map[string]any{}
	for _, u := range users {
		m := map[string]any{"type": "user"}
		for _, k := range []string{"name", "login_name", "disabled", "default_role", "has_password", "has_rsa_public_key", "last_success_login"} {
			if v, ok := u[k]; ok {
				m[k] = v
			}
		}
		if v, ok := u["type"]; ok {
			m["user_type"] = v // PERSON, SERVICE, LEGACY_SERVICE
		}
		res = append(res, m)
	}
	roles, err := rowsOf(ctx, db, "SHOW ROLES")
	if err != nil {
		return nil, snowflakeErr(err)
	}
	for _, r := range roles {
		res = append(res, map[string]any{"name": r["name"], "type": "role"})
	}
	return res, nil
}

// snowflakeGrants lists what a user may do: its roles, and what each of
// them was granted (one level, not the roles those roles inherit). NAME
// may be a role, too.
func snowflakeGrants(ctx context.Context, db *sql.DB, name string) ([]map[string]any, error) {
	if !validObj.MatchString(name) {
		return nil, out.Usage("user or role name %q: letters, digits, _ and $", name)
	}
	res := []map[string]any{}
	var roles []string
	members, err := rowsOf(ctx, db, "SHOW GRANTS TO USER "+name)
	if err == nil {
		for _, m := range members {
			role := fmt.Sprint(m["role"])
			roles = append(roles, role)
			res = append(res, map[string]any{"on_type": "role", "object": role, "privileges": "MEMBER"})
		}
	} else {
		roles = []string{name} // not a user: perhaps a role
	}
	for _, role := range roles {
		quoted := role
		if role != name {
			quoted = `"` + strings.ReplaceAll(role, `"`, `""`) + `"`
		}
		grants, gerr := rowsOf(ctx, db, "SHOW GRANTS TO ROLE "+quoted)
		if gerr != nil {
			if role == name {
				return nil, out.Errf(out.ExitNotFound, "DB_USER_NOT_FOUND", "list users and roles with `komando db user list CONN` (the conn's role needs to see them)",
					"user or role %s does not exist, or the conn's role may not see it", name)
			}
			return nil, snowflakeErr(gerr)
		}
		res = append(res, sfGroupGrants(role, grants)...)
	}
	return res, nil
}

// sfGroupGrants turns SHOW GRANTS TO ROLE rows into one row per object.
func sfGroupGrants(role string, grants []map[string]any) []map[string]any {
	var res []map[string]any
	at := map[string]int{}
	for _, g := range grants {
		on, obj, priv := strings.ToLower(fmt.Sprint(g["granted_on"])), fmt.Sprint(g["name"]), fmt.Sprint(g["privilege"])
		if g["grant_option"] == true || g["grant_option"] == "true" {
			priv += " (with grant option)"
		}
		key := on + "\x00" + obj
		if i, ok := at[key]; ok {
			res[i]["privileges"] = res[i]["privileges"].(string) + "," + priv
			continue
		}
		at[key] = len(res)
		res = append(res, map[string]any{"on_type": on, "object": obj, "privileges": priv, "via_role": role})
	}
	return res
}
