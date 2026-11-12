package dbx

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// Database users, roles and grants. Passwords come from the vault and never
// reach the output, the audit log or (for PostgreSQL) the server: komando
// sends a SCRAM-SHA-256 verifier it computes itself, like psql's \password.
// MySQL rewrites passwords in its own logs.

// scramVerifier is PostgreSQL's stored form of a password (RFC 5802,
// RFC 7677): SCRAM-SHA-256$iterations:salt$StoredKey:ServerKey.
func scramVerifier(password string, salt []byte, iter int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	clientKey := mac(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	serverKey := mac(salted, "Server Key")
	b := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iter, b(salt), b(stored[:]), b(serverKey)), nil
}

func newScram(password string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	return scramVerifier(password, salt, 4096)
}

// validRole: a user name komando puts in SQL (quoted as well).
var validRole = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.$@-]{0,62}$`)

// validMyHost: the host part of a MySQL account.
var validMyHost = regexp.MustCompile(`^[A-Za-z0-9_.%:/-]{1,255}$`)

func checkRole(name string) error {
	if !validRole.MatchString(name) {
		return out.Usage("user name %q: use letters, digits and _ . $ @ - (up to 63, not starting with a digit)", name)
	}
	return nil
}

// mysqlLit quotes a string for MySQL, with or without NO_BACKSLASH_ESCAPES.
func mysqlLit(s string, backslashEscapes bool) string {
	if backslashEscapes {
		s = strings.ReplaceAll(s, `\`, `\\`)
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func myAccount(name, host string, bs bool) string {
	return mysqlLit(name, bs) + "@" + mysqlLit(host, bs)
}

// backslashEscapes reports whether the MySQL session treats \ as an escape.
func backslashEscapes(ctx context.Context, db *sql.DB) bool {
	var mode string
	if db == nil {
		return true
	}
	if err := db.QueryRowContext(ctx, "select @@sql_mode").Scan(&mode); err != nil {
		return true
	}
	return !strings.Contains(strings.ToUpper(mode), "NO_BACKSLASH_ESCAPES")
}

// Users lists users and roles with their main attributes.
func Users(ctx context.Context, db *sql.DB, kind string, timeout time.Duration) ([]map[string]any, error) {
	ctx, cancel := withTimeout(ctx, timeout)
	defer cancel()
	switch kind {
	case "postgres":
		return rowsOf(ctx, db, `select r.rolname as name, r.rolcanlogin as login, r.rolsuper as superuser, r.rolcreatedb as create_db,
  r.rolcreaterole as create_role, r.rolreplication as replication, r.rolvaliduntil::text as valid_until,
  coalesce((select string_agg(m.rolname, ',' order by m.rolname) from pg_auth_members a join pg_roles m on m.oid = a.roleid where a.member = r.oid), '') as member_of
from pg_roles r where r.rolname !~ '^pg_' order by r.rolname`)
	case "mysql":
		rows, err := rowsOf(ctx, db, `select user as name, host, account_locked = 'Y' as locked, password_expired = 'Y' as password_expired, plugin
from mysql.user order by user, host`)
		if err != nil && strings.Contains(err.Error(), "1054") { // MariaDB: no account_locked in its mysql.user view
			return rowsOf(ctx, db, `select user as name, host, password_expired = 'Y' as password_expired, plugin, is_role = 'Y' as role
from mysql.user order by user, host`)
		}
		return rows, err
	case "sqlserver":
		return mssqlUsers(ctx, db)
	case "oracle":
		return oracleUsers(ctx, db)
	case "clickhouse":
		return clickhouseUsers(ctx, db)
	case "snowflake":
		return snowflakeUsers(ctx, db)
	case "bigquery":
		return nil, BQNoUsers("db user list")
	}
	return nil, NotSupported(kind, "db user")
}

// UserSpec is a user to create or change.
type UserSpec struct {
	Name     string
	Host     string // MySQL account host; "%" when empty
	Password string
	NoLogin  bool // a role that cannot log in (a group)
}

// userSQL is the statement for an action on a user; shown is the same
// with the password replaced, for dry runs and errors.
func userSQL(ctx context.Context, db *sql.DB, kind, action string, u UserSpec) (stmt, shown string, err error) {
	if err := checkRole(u.Name); err != nil {
		return "", "", err
	}
	switch kind {
	case "sqlserver":
		return mssqlUserSQL(action, u)
	case "oracle":
		return oracleUserSQL(action, u)
	case "clickhouse":
		return clickhouseUserSQL(ctx, db, action, u)
	case "snowflake":
		return "", "", SFNoUserChange("db user " + action)
	case "bigquery":
		return "", "", BQNoUsers("db user " + action)
	}
	host := u.Host
	if host == "" {
		host = "%"
	}
	if kind == "mysql" && !validMyHost.MatchString(host) {
		return "", "", out.Usage("host %q: a name, an address, or a pattern with %%", host)
	}
	switch kind {
	case "postgres":
		pw := func() (string, error) {
			if u.Password == "" {
				return "", nil
			}
			v, err := newScram(u.Password)
			return " password " + pqlit(v), err
		}
		switch action {
		case "add":
			login := " login"
			if u.NoLogin {
				login = " nologin"
			}
			p, err := pw()
			return "create role " + pqid(u.Name) + login + p, "create role " + pqid(u.Name) + login + hidden(u.Password), err
		case "passwd":
			p, err := pw()
			return "alter role " + pqid(u.Name) + p, "alter role " + pqid(u.Name) + hidden(u.Password), err
		case "rm":
			s := "drop role " + pqid(u.Name)
			return s, s, nil
		}
	case "mysql":
		bs := backslashEscapes(ctx, db)
		acct := myAccount(u.Name, host, bs)
		switch action {
		case "add":
			return "create user " + acct + " identified by " + mysqlLit(u.Password, bs), "create user " + acct + " identified by '[hidden]'", nil
		case "passwd":
			return "alter user " + acct + " identified by " + mysqlLit(u.Password, bs), "alter user " + acct + " identified by '[hidden]'", nil
		case "rm":
			s := "drop user " + acct
			return s, s, nil
		}
	default:
		return "", "", NotSupported(kind, "db user")
	}
	return "", "", fmt.Errorf("unknown user action %q", action)
}

func hidden(pw string) string {
	if pw == "" {
		return ""
	}
	return " password '[hidden]'"
}

// UserChange runs an action on a user (add, passwd, rm) and returns the
// statement as it may be shown. With dry, nothing runs.
func UserChange(ctx context.Context, db *sql.DB, kind, action string, u UserSpec, dry bool) (string, error) {
	stmt, shown, err := userSQL(ctx, db, kind, action, u)
	if err != nil || dry {
		return shown, err
	}
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return shown, userErr(err, u.Name)
	}
	return shown, nil
}

// userErr names the common failures without echoing the statement.
func userErr(err error, name string) error {
	msg := err.Error()
	if n := oraNumber(err); n != 0 {
		return oraUserErr(n, firstLine(msg), name)
	}
	var ce *chError
	if errors.As(err, &ce) {
		return chUserErr(ce.Code, ce.Msg, name)
	}
	switch {
	case strings.Contains(msg, "already exists"), strings.Contains(msg, "1396") && strings.Contains(strings.ToLower(msg), "create user"):
		return out.Errf(out.ExitConflict, "DB_USER_EXISTS", "change its password with `komando db user passwd CONN "+name+" --password-ref secret:NAME`", "user %s already exists", name)
	case strings.Contains(msg, "does not exist"), strings.Contains(msg, "1396"):
		return out.Errf(out.ExitNotFound, "DB_USER_NOT_FOUND", "list users with `komando db user list CONN`", "user %s does not exist", name)
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "does not have permission"), strings.Contains(msg, "must have CREATEROLE"), strings.Contains(msg, "Access denied"), strings.Contains(msg, "1227"):
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "the conn's user needs the right to manage users (PostgreSQL: CREATEROLE; MySQL: CREATE USER; SQL Server: ALTER ANY LOGIN and ALTER ANY USER)", "%s", firstLine(msg))
	case strings.Contains(msg, "depend on it"), strings.Contains(msg, "owns"):
		return out.Errf(out.ExitConflict, "DB_USER_IN_USE", "move or drop what the user owns first (PostgreSQL: REASSIGN OWNED BY, DROP OWNED BY)", "%s", firstLine(msg))
	case strings.Contains(msg, "is currently logged in"):
		return out.Errf(out.ExitConflict, "DB_USER_IN_USE", "end its sessions first: find them with `komando db activity CONN --all`, then `komando db kill CONN PID --session`", "%s", firstLine(msg))
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "read the message; the statement is in data.sql (password hidden)", "%s", firstLine(msg))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Grant is a GRANT or REVOKE: privileges on one object, or a role.
type Grant struct {
	User   string
	Host   string   // MySQL account host
	Privs  []string // SELECT, INSERT ...; empty with Role
	On     string   // database:NAME, schema:NAME, table:NAME, all-tables:SCHEMA (PostgreSQL); DB.* or DB.TABLE (MySQL)
	Role   string   // grant membership in this role instead
	Revoke bool
}

var pgPrivs = map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "TRUNCATE": true, "REFERENCES": true,
	"TRIGGER": true, "USAGE": true, "CREATE": true, "CONNECT": true, "TEMPORARY": true, "EXECUTE": true, "ALL": true}
var myPrivs = map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "CREATE": true, "DROP": true, "INDEX": true,
	"ALTER": true, "REFERENCES": true, "EXECUTE": true, "SHOW VIEW": true, "CREATE VIEW": true, "TRIGGER": true, "EVENT": true,
	"LOCK TABLES": true, "CREATE TEMPORARY TABLES": true, "ALL": true}

var validObj = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)

// grantSQLFor are the kinds whose grants have a file of their own.
var grantSQLFor = map[string]func(context.Context, *sql.DB, Grant) (string, error){"sqlserver": mssqlGrantSQL, "oracle": oracleGrantSQL, "clickhouse": clickhouseGrantSQL,
	"snowflake": func(context.Context, *sql.DB, Grant) (string, error) {
		return "", SFNoUserChange("db grant and revoke")
	}, "bigquery": func(context.Context, *sql.DB, Grant) (string, error) {
		return "", BQNoUsers("db grant and revoke")
	}}

// GrantSQL builds the statement for g.
func GrantSQL(ctx context.Context, db *sql.DB, kind string, g Grant) (string, error) {
	if err := checkRole(g.User); err != nil {
		return "", err
	}
	if f := grantSQLFor[kind]; f != nil {
		return f(ctx, db, g)
	}
	verb, prep := "grant", " to "
	if g.Revoke {
		verb, prep = "revoke", " from "
	}
	privs := make([]string, 0, len(g.Privs))
	known := map[bool]map[string]bool{false: pgPrivs, true: myPrivs}[kind == "mysql"]
	for _, p := range g.Privs {
		p = strings.ToUpper(strings.TrimSpace(p))
		if !known[p] {
			return "", out.Usage("unknown privilege %q", p)
		}
		privs = append(privs, p)
	}
	switch kind {
	case "postgres":
		if g.Role != "" {
			if err := checkRole(g.Role); err != nil {
				return "", err
			}
			return verb + " " + pqid(g.Role) + prep + pqid(g.User), nil
		}
		if len(privs) == 0 {
			return "", out.Usage("name the privileges (--privileges SELECT,INSERT) or a --role")
		}
		typ, name, _ := strings.Cut(g.On, ":")
		obj := ""
		switch typ {
		case "database":
			obj = "database " + pqid(name)
		case "schema":
			obj = "schema " + pqid(name)
		case "all-tables":
			obj = "all tables in schema " + pqid(name)
		case "table":
			parts := strings.Split(name, ".")
			if len(parts) > 2 {
				return "", out.Usage("--on table:[SCHEMA.]TABLE takes at most one dot, not %q", name)
			}
			q := make([]string, len(parts))
			for i, p := range parts {
				q[i] = pqid(p)
			}
			obj = "table " + strings.Join(q, ".")
		default:
			return "", out.Usage("--on takes database:NAME, schema:NAME, table:[SCHEMA.]TABLE or all-tables:SCHEMA")
		}
		for _, p := range strings.Split(name, ".") {
			if !validObj.MatchString(p) {
				return "", out.Usage("object name %q: letters, digits, _ and $", p)
			}
		}
		return verb + " " + strings.Join(privs, ", ") + " on " + obj + prep + pqid(g.User), nil
	case "mysql":
		if g.Role != "" {
			return "", out.Usage("--role is for PostgreSQL; on MySQL grant privileges with --on DB.* or DB.TABLE")
		}
		if len(privs) == 0 {
			return "", out.Usage("name the privileges (--privileges SELECT,INSERT)")
		}
		dbName, table, ok := strings.Cut(g.On, ".")
		if !ok {
			return "", out.Usage("--on takes DB.* , DB.TABLE or *.*")
		}
		q := func(s string) (string, error) {
			if s == "*" {
				return "*", nil
			}
			if !validObj.MatchString(s) {
				return "", out.Usage("object name %q: letters, digits, _ and $", s)
			}
			return qid(s), nil
		}
		d, err := q(dbName)
		if err != nil {
			return "", err
		}
		tb, err := q(table)
		if err != nil {
			return "", err
		}
		host := g.Host
		if host == "" {
			host = "%"
		}
		if !validMyHost.MatchString(host) {
			return "", out.Usage("host %q: a name, an address, or a pattern with %%", host)
		}
		return verb + " " + strings.Join(privs, ", ") + " on " + d + "." + tb + prep + myAccount(g.User, host, backslashEscapes(ctx, db)), nil
	}
	return "", NotSupported(kind, "db grant")
}

// Grants lists what a user may do.
func Grants(ctx context.Context, db *sql.DB, kind, user, host string, timeout time.Duration) ([]map[string]any, error) {
	if err := checkRole(user); err != nil {
		return nil, err
	}
	ctx, cancel := withTimeout(ctx, timeout)
	defer cancel()
	switch kind {
	case "postgres":
		return rowsOf(ctx, db, `select 'table' as on_type, table_schema || '.' || table_name as object, string_agg(privilege_type, ',' order by privilege_type) as privileges
from information_schema.role_table_grants where grantee = $1 group by table_schema, table_name
union all
select 'database', datname, concat_ws(',', case when has_database_privilege($1, datname, 'CONNECT') then 'CONNECT' end,
  case when has_database_privilege($1, datname, 'CREATE') then 'CREATE' end, case when has_database_privilege($1, datname, 'TEMPORARY') then 'TEMPORARY' end)
from pg_database where not datistemplate and has_database_privilege($1, datname, 'CREATE')
union all
select 'role', m.rolname, 'MEMBER' from pg_auth_members a join pg_roles m on m.oid = a.roleid join pg_roles u on u.oid = a.member where u.rolname = $1
order by 1, 2`, user)
	case "mysql":
		if host == "" {
			host = "%"
		}
		rows, err := db.QueryContext(ctx, "show grants for "+myAccount(user, host, backslashEscapes(ctx, db)))
		if err != nil {
			return nil, userErr(err, user)
		}
		defer rows.Close()
		var res []map[string]any
		for rows.Next() {
			var g string
			if err := rows.Scan(&g); err != nil {
				return nil, err
			}
			res = append(res, map[string]any{"grant": g})
		}
		return res, rows.Err()
	case "sqlserver":
		return mssqlGrants(ctx, db, user)
	case "oracle":
		return oracleGrants(ctx, db, user)
	case "clickhouse":
		return clickhouseGrants(ctx, db, user)
	case "snowflake":
		return snowflakeGrants(ctx, db, user)
	case "bigquery":
		return nil, BQNoUsers("db grants")
	}
	return nil, NotSupported(kind, "db grants")
}
