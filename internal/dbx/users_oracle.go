package dbx

import (
	"context"
	"database/sql"
	"regexp"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// Oracle users are also schemas: db user add creates the user and lets it
// log in (CREATE SESSION), in one PL/SQL block that drops the user again
// if the grant fails. --no-login creates a role instead, a group to grant
// to users. Names are stored in upper case, as Oracle does for names
// without quotes.

var validOraUser = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_$#]{0,127}$`)

func oraid(s string) string { return `"` + strings.ToUpper(s) + `"` }
func oralit(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func checkOraUser(name string) error {
	if !validOraUser.MatchString(name) {
		return out.Usage("Oracle user name %q: a letter, then letters, digits and _ $ # (up to 128)", name)
	}
	return nil
}

func oracleUsers(ctx context.Context, db *sql.DB) ([]map[string]any, error) {
	rows, err := lowerRows(rowsOf(ctx, db, `
SELECT u.username AS name, 'user' AS type, LOWER(u.account_status) AS status, u.default_tablespace, u.profile, u.created,
       (SELECT LISTAGG(r.granted_role, ',') WITHIN GROUP (ORDER BY r.granted_role) FROM dba_role_privs r WHERE r.grantee = u.username) AS member_of
FROM dba_users u WHERE u.oracle_maintained = 'N'
UNION ALL
SELECT r.role, 'role', NULL, NULL, NULL, NULL, NULL FROM dba_roles r WHERE r.oracle_maintained = 'N'
ORDER BY 1`))
	if n := oraNumber(err); n == 942 || n == 1031 { // no DBA_ views: the users anyone may list
		return lowerRows(rowsOf(ctx, db, `SELECT username AS name, 'user' AS type, created FROM all_users WHERE oracle_maintained = 'N' ORDER BY 1`))
	}
	return rows, err
}

// oracleUserSQL is userSQL for Oracle.
func oracleUserSQL(action string, u UserSpec) (stmt, shown string, err error) {
	if u.Host != "" {
		return "", "", out.Usage("--from is for MySQL; Oracle users are not tied to a host")
	}
	if err := checkOraUser(u.Name); err != nil {
		return "", "", err
	}
	id := oraid(u.Name)
	if (action == "add" && !u.NoLogin || action == "passwd") && strings.ContainsAny(u.Password, "\"\x00\n\r") {
		return "", "", out.Usage("an Oracle password cannot hold a double quote or a line break; store another one in the vault")
	}
	pw := func(p string) string { return `identified by "` + p + `"` }
	switch action {
	case "add":
		if u.NoLogin {
			s := "create role " + id
			return s, s, nil
		}
		block := func(p string) string {
			return "begin execute immediate " + oralit("create user "+id+" "+pw(p)) + "; " +
				"begin execute immediate " + oralit("grant create session to "+id) + "; " +
				"exception when others then execute immediate " + oralit("drop user "+id+" cascade") + "; raise; end; end;"
		}
		return block(u.Password), block("[hidden]"), nil
	case "passwd":
		return "alter user " + id + " " + pw(u.Password), "alter user " + id + ` identified by "[hidden]"`, nil
	case "rm":
		s := "declare n number; begin select count(*) into n from all_users where username = " + oralit(strings.ToUpper(u.Name)) + "; " +
			"if n > 0 then execute immediate " + oralit("drop user "+id) + "; else execute immediate " + oralit("drop role "+id) + "; end if; end;"
		return s, s, nil
	}
	return "", "", out.Usage("unknown user action %q", action)
}

// oraUserErr is userErr for Oracle's error numbers.
func oraUserErr(n int, msg, name string) error {
	switch n {
	case 1920:
		return out.Errf(out.ExitConflict, "DB_USER_EXISTS", "change its password with `komando db user passwd`", "user %s already exists", name)
	case 1918, 1919:
		return out.Errf(out.ExitNotFound, "DB_USER_NOT_FOUND", "list users with `komando db user ls CONN`", "user %s does not exist", name)
	case 1940:
		return out.Errf(out.ExitConflict, "DB_USER_IN_USE", "end its sessions first: find them with `komando db activity CONN --all`, then `komando db kill CONN PID --session`", "%s", msg)
	case 1922:
		return out.Errf(out.ExitConflict, "DB_USER_IN_USE", "the user owns tables or other objects: move or drop them first (DROP USER ... CASCADE drops them all, which komando leaves to you)", "%s", msg)
	case 1031:
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "the conn's user needs the right to manage users (Oracle: CREATE USER, ALTER USER, DROP USER and GRANT ANY PRIVILEGE)", "%s", msg)
	case 28003, 28007, 988:
		return out.Errf(out.ExitRemote, "DB_ERROR", "the password does not meet the database's password rules; store another one in the vault", "%s", msg)
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "read the message; the statement is in data.sql (password hidden)", "%s", msg)
}

var oraObjPrivs = map[string]bool{"SELECT": true, "READ": true, "INSERT": true, "UPDATE": true, "DELETE": true, "ALTER": true,
	"INDEX": true, "REFERENCES": true, "EXECUTE": true, "DEBUG": true, "ALL": true}

var oraSysPrivs = map[string]bool{"CREATE SESSION": true, "CREATE TABLE": true, "CREATE VIEW": true, "CREATE SEQUENCE": true,
	"CREATE PROCEDURE": true, "CREATE TRIGGER": true, "CREATE TYPE": true, "CREATE SYNONYM": true, "CREATE MATERIALIZED VIEW": true,
	"CREATE JOB": true, "UNLIMITED TABLESPACE": true, "SELECT ANY TABLE": true, "READ ANY TABLE": true, "INSERT ANY TABLE": true,
	"UPDATE ANY TABLE": true, "DELETE ANY TABLE": true, "EXECUTE ANY PROCEDURE": true, "SELECT ANY DICTIONARY": true}

// oraSchemaPrivs are the Oracle 23ai privileges on a whole schema, by the
// short name db grant takes.
var oraSchemaPrivs = map[string]string{"SELECT": "SELECT ANY TABLE", "READ": "READ ANY TABLE", "INSERT": "INSERT ANY TABLE",
	"UPDATE": "UPDATE ANY TABLE", "DELETE": "DELETE ANY TABLE", "EXECUTE": "EXECUTE ANY PROCEDURE"}

// oracleGrantSQL is GrantSQL for Oracle. OBJECT is database (system
// privileges: CREATE SESSION, SELECT ANY TABLE, ...), table:[SCHEMA.]TABLE
// (object privileges), or schema:NAME / all-tables:NAME (Oracle 23ai
// schema privileges); --role grants a role.
func oracleGrantSQL(ctx context.Context, db *sql.DB, g Grant) (string, error) {
	if g.Host != "" {
		return "", out.Usage("--from is for MySQL; Oracle users are not tied to a host")
	}
	if err := checkOraUser(g.User); err != nil {
		return "", err
	}
	verb, prep := "grant ", " to "
	if g.Revoke {
		verb, prep = "revoke ", " from "
	}
	if g.Role != "" {
		if err := checkOraUser(g.Role); err != nil {
			return "", err
		}
		return verb + oraid(g.Role) + prep + oraid(g.User), nil
	}
	if len(g.Privs) == 0 {
		return "", out.Usage("name the privileges (--privileges SELECT,INSERT) or a --role")
	}
	typ, name, _ := strings.Cut(g.On, ":")
	privs := make([]string, 0, len(g.Privs))
	for _, p := range g.Privs {
		p = strings.ToUpper(strings.Join(strings.Fields(p), " "))
		switch {
		case typ == "database" && oraSysPrivs[p], typ == "table" && oraObjPrivs[p]:
		case (typ == "schema" || typ == "all-tables") && oraSchemaPrivs[p] != "":
			p = oraSchemaPrivs[p]
		case (typ == "schema" || typ == "all-tables") && strings.HasSuffix(p, " ANY TABLE") && oraSysPrivs[p]:
		default:
			return "", out.Usage("unknown privilege %q for --on %s", p, typ)
		}
		privs = append(privs, p)
	}
	on := ""
	switch typ {
	case "database":
		if name != "" {
			var current string
			if db != nil {
				_ = db.QueryRowContext(ctx, "SELECT SYS_CONTEXT('USERENV', 'CON_NAME') FROM dual").Scan(&current)
			}
			if !strings.EqualFold(name, current) {
				return "", out.Usage("on Oracle, --on database means the conn's database (%s); use a conn for %s", current, name)
			}
		}
	case "schema", "all-tables":
		if !validObj.MatchString(name) {
			return "", out.Usage("schema name %q: letters, digits, _ and $", name)
		}
		on = " on schema " + oraid(name)
	case "table":
		parts := strings.Split(name, ".")
		if len(parts) > 2 {
			return "", out.Usage("--on table:SCHEMA.TABLE")
		}
		q := make([]string, len(parts))
		for i, p := range oracleNames(parts) {
			if !validObj.MatchString(p) {
				return "", out.Usage("object name %q: letters, digits, _ and $", p)
			}
			q[i] = `"` + p + `"`
		}
		on = " on " + strings.Join(q, ".")
	default:
		return "", out.Usage("--on takes database, table:[SCHEMA.]TABLE, or schema:NAME (Oracle 23ai)")
	}
	return verb + strings.Join(privs, ", ") + on + prep + oraid(g.User), nil
}

// oracleGrants lists a user's privileges: on tables, on the database
// (system privileges), on schemas (23ai) and the roles it has.
func oracleGrants(ctx context.Context, db *sql.DB, user string) ([]map[string]any, error) {
	user = strings.ToUpper(user)
	rows, err := lowerRows(rowsOf(ctx, db, `
SELECT 'table' AS on_type, owner || '.' || table_name AS object,
       privilege || CASE grantable WHEN 'YES' THEN ' (with grant option)' END AS privilege
FROM dba_tab_privs WHERE grantee = :1
UNION ALL
SELECT 'database', SYS_CONTEXT('USERENV', 'CON_NAME'), privilege || CASE admin_option WHEN 'YES' THEN ' (with admin option)' END
FROM dba_sys_privs WHERE grantee = :2
UNION ALL
SELECT 'role', granted_role, 'MEMBER' FROM dba_role_privs WHERE grantee = :3`, user, user, user))
	if err != nil {
		return nil, catalogErr(err, "db grants")
	}
	if more, err := lowerRows(rowsOf(ctx, db, `SELECT 'schema' AS on_type, schema AS object, privilege FROM dba_schema_privs WHERE grantee = :1`, user)); err == nil {
		rows = append(rows, more...)
	}
	type key struct{ typ, obj string }
	byObj := map[key][]string{}
	for _, r := range rows {
		k := key{str(r["on_type"]), str(r["object"])}
		byObj[k] = append(byObj[k], str(r["privilege"]))
	}
	keys := make([]key, 0, len(byObj))
	for k := range byObj {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].typ != keys[j].typ {
			return keys[i].typ < keys[j].typ
		}
		return keys[i].obj < keys[j].obj
	})
	res := []map[string]any{}
	for _, k := range keys {
		p := byObj[k]
		sort.Strings(p)
		res = append(res, map[string]any{"on_type": k.typ, "object": k.obj, "privileges": strings.Join(p, ",")})
	}
	return res, nil
}
