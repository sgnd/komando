package dbx

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// ClickHouse's SQL users and roles (access management on: the conn's user
// needs access_management, or the CREATE USER and GRANT rights). komando
// sends a salted SHA-256 hash it computes itself (IDENTIFIED WITH
// sha256_hash ... SALT), so the password never reaches the server or its
// query log. Users from users.xml cannot be changed with SQL.

func chid(s string) string { return "`" + strings.ReplaceAll(s, "`", "\\`") + "`" }

func chlit(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

// chPassword is the IDENTIFIED clause for password: SHA-256 of the
// password and a random salt, as ClickHouse checks it.
func chPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	s := hex.EncodeToString(salt)
	sum := sha256.Sum256([]byte(password + s))
	return "identified with sha256_hash by " + chlit(hex.EncodeToString(sum[:])) + " salt " + chlit(s)
}

const chHiddenPassword = "identified with sha256_hash by '[hidden]' salt '[hidden]'"

func clickhouseUsers(ctx context.Context, db *sql.DB) ([]map[string]any, error) {
	rows, err := rowsOf(ctx, db, `
SELECT name, type, auth, storage, member_of FROM (
  SELECT u.name AS name, 'user' AS type, toString(u.auth_type) AS auth, u.storage AS storage, g.roles AS member_of
  FROM system.users AS u
  LEFT JOIN (SELECT user_name, arrayStringConcat(arraySort(groupArray(granted_role_name)), ',') AS roles
             FROM system.role_grants WHERE user_name IS NOT NULL GROUP BY user_name) AS g ON g.user_name = u.name
  UNION ALL
  SELECT name, 'role', '', storage, '' FROM system.roles)
ORDER BY name`)
	if err != nil {
		return nil, clickhouseErr(err)
	}
	return rows, nil
}

// clickhouseUserSQL is userSQL for ClickHouse. rm drops a role when the
// name is one.
func clickhouseUserSQL(ctx context.Context, db *sql.DB, action string, u UserSpec) (stmt, shown string, err error) {
	if u.Host != "" {
		return "", "", out.Usage("--from is for MySQL; a ClickHouse user lists the hosts it may connect from itself (HOST ...)")
	}
	id := chid(u.Name)
	switch action {
	case "add":
		if u.NoLogin {
			s := "create role " + id
			return s, s, nil
		}
		return "create user " + id + " " + chPassword(u.Password), "create user " + id + " " + chHiddenPassword, nil
	case "passwd":
		return "alter user " + id + " " + chPassword(u.Password), "alter user " + id + " " + chHiddenPassword, nil
	case "rm":
		what := "user "
		var n int64
		if db != nil && db.QueryRowContext(ctx, "SELECT count() FROM system.roles WHERE name = {p1:String}", u.Name).Scan(&n) == nil && n > 0 {
			what = "role "
		}
		s := "drop " + what + id
		return s, s, nil
	}
	return "", "", out.Usage("unknown user action %q", action)
}

// chUserErr is userErr for ClickHouse's error codes.
func chUserErr(n int, msg, name string) error {
	switch n {
	case 493: // ACCESS_ENTITY_ALREADY_EXISTS
		return out.Errf(out.ExitConflict, "DB_USER_EXISTS", "change its password with `komando db user passwd CONN "+name+" --password-ref secret:NAME`", "user %s already exists", name)
	case 192, 511: // UNKNOWN_USER, UNKNOWN_ROLE
		return out.Errf(out.ExitNotFound, "DB_USER_NOT_FOUND", "list users with `komando db user ls CONN`", "%s", msg)
	case 497:
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "the conn's user needs the right to manage users (ClickHouse: access_management, or CREATE USER, ALTER USER, DROP USER and GRANT with grant option)", "%s", msg)
	case 495: // ACCESS_STORAGE_READONLY
		return out.Errf(out.ExitRemote, "DB_ERROR", "this user is defined in the server's users.xml, which SQL cannot change: edit that file on the server", "%s", msg)
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "read the message; the statement is in data.sql (password hidden)", "%s", msg)
}

// chPrivs are the privileges db grant takes on ClickHouse.
var chPrivs = map[string]bool{"SELECT": true, "INSERT": true, "ALTER": true, "CREATE": true, "DROP": true, "TRUNCATE": true,
	"OPTIMIZE": true, "SHOW": true, "KILL QUERY": true, "ALTER UPDATE": true, "ALTER DELETE": true, "CREATE TABLE": true,
	"CREATE VIEW": true, "CREATE DATABASE": true, "CREATE DICTIONARY": true, "DROP TABLE": true, "DROP VIEW": true,
	"DROP DATABASE": true, "SHOW TABLES": true, "SHOW COLUMNS": true, "SHOW DATABASES": true, "DICTGET": true, "ALL": true}

// clickhouseGrantSQL is GrantSQL for ClickHouse. OBJECT is DB.*, DB.TABLE
// or *.* as in MySQL, or database:DB, table:DB.TABLE, all-tables:DB.
func clickhouseGrantSQL(_ context.Context, _ *sql.DB, g Grant) (string, error) {
	if g.Host != "" {
		return "", out.Usage("--from is for MySQL; a ClickHouse user lists the hosts it may connect from itself (HOST ...)")
	}
	verb, prep := "grant ", " to "
	if g.Revoke {
		verb, prep = "revoke ", " from "
	}
	if g.Role != "" {
		if err := checkRole(g.Role); err != nil {
			return "", err
		}
		return verb + chid(g.Role) + prep + chid(g.User), nil
	}
	if len(g.Privs) == 0 {
		return "", out.Usage("name the privileges (--privileges SELECT,INSERT) or a --role")
	}
	privs := make([]string, 0, len(g.Privs))
	for _, p := range g.Privs {
		p = strings.ToUpper(strings.Join(strings.Fields(p), " "))
		if !chPrivs[p] {
			return "", out.Usage("unknown privilege %q (ClickHouse: SELECT, INSERT, ALTER, CREATE, DROP, TRUNCATE, OPTIMIZE, SHOW, KILL QUERY, ...)", p)
		}
		if p == "DICTGET" {
			p = "dictGet"
		}
		privs = append(privs, p)
	}
	on, err := chGrantObject(g.On)
	if err != nil {
		return "", err
	}
	return verb + strings.Join(privs, ", ") + " on " + on + prep + chid(g.User), nil
}

// chGrantObject turns --on into ClickHouse's DB.TABLE form.
func chGrantObject(on string) (string, error) {
	typ, name, found := strings.Cut(on, ":")
	switch {
	case !found:
		name = on
	case typ == "database" || typ == "all-tables":
		name += ".*"
	case typ == "table":
	default:
		return "", out.Usage("--on takes DB.*, DB.TABLE, *.*, database:DB or table:DB.TABLE")
	}
	dbName, table, ok := strings.Cut(name, ".")
	if !ok {
		return "", out.Usage("--on takes DB.*, DB.TABLE, *.*, database:DB or table:DB.TABLE")
	}
	q := func(s string) (string, error) {
		if s == "*" {
			return "*", nil
		}
		if !validObj.MatchString(s) {
			return "", out.Usage("object name %q: letters, digits, _ and $", s)
		}
		return chid(s), nil
	}
	d, err := q(dbName)
	if err != nil {
		return "", err
	}
	if d == "*" && table != "*" {
		return "", out.Usage("--on *.%s names no database; use DB.%s", table, table)
	}
	t, err := q(table)
	if err != nil {
		return "", err
	}
	return d + "." + t, nil
}

// clickhouseGrants lists the privileges of a user (or role) by object,
// and its roles.
func clickhouseGrants(ctx context.Context, db *sql.DB, user string) ([]map[string]any, error) {
	rows, err := rowsOf(ctx, db, `
SELECT on_type, object, privileges FROM (
  SELECT multiIf(database IS NULL, 'server', table IS NULL, 'database', 'table') AS on_type,
         concat(ifNull(database, '*'), '.', ifNull(table, '*'), if(column IS NULL, '', concat('(', assumeNotNull(column), ')'))) AS object,
         arrayStringConcat(arraySort(groupArray(concat(if(is_partial_revoke, 'REVOKE ', ''), toString(access_type),
                                                       if(grant_option, ' (with grant option)', '')))), ',') AS privileges
  FROM system.grants WHERE user_name = {p1:String} OR role_name = {p1:String} GROUP BY on_type, object
  UNION ALL
  SELECT 'role', granted_role_name, 'MEMBER' FROM system.role_grants WHERE user_name = {p1:String} OR role_name = {p1:String})
ORDER BY on_type, object`, user)
	if err != nil {
		return nil, clickhouseErr(err)
	}
	return rows, nil
}
