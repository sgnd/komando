package dbx

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// SQL Server users come in two parts: a login (on the server, with the
// password) and a user (in the conn's database, mapped to the login).
// db user add makes both, rm removes both; --no-login makes a database
// role instead, a group to grant to users. Contained database users
// (Azure SQL Database) are not made by komando.

func msid(s string) string  { return "[" + strings.ReplaceAll(s, "]", "]]") + "]" }
func mslit(s string) string { return "N'" + strings.ReplaceAll(s, "'", "''") + "'" }

func mssqlUsers(ctx context.Context, db *sql.DB) ([]map[string]any, error) {
	return rowsOf(ctx, db, `
SELECT dp.name, LOWER(dp.type_desc COLLATE DATABASE_DEFAULT) AS type, sp.name AS login, dp.default_schema_name AS default_schema,
       CAST(COALESCE(sp.is_disabled, 0) AS bit) AS disabled,
       COALESCE(STUFF((SELECT ',' + r.name FROM sys.database_role_members m
                       JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
                       WHERE m.member_principal_id = dp.principal_id ORDER BY r.name
                       FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'), 1, 1, ''), '') AS member_of
FROM sys.database_principals dp LEFT JOIN sys.server_principals sp ON sp.sid = dp.sid
WHERE dp.type IN ('S', 'U', 'G', 'E', 'X', 'R') AND dp.is_fixed_role = 0
  AND dp.name NOT IN ('guest', 'INFORMATION_SCHEMA', 'sys', 'public')
ORDER BY dp.name`)
}

// mssqlUserSQL is userSQL for SQL Server.
func mssqlUserSQL(action string, u UserSpec) (stmt, shown string, err error) {
	if u.Host != "" {
		return "", "", out.Usage("--from is for MySQL; SQL Server logins are not tied to a host")
	}
	id := msid(u.Name)
	// one transaction: a login is not left without its user, nor a user without its login
	wrap := func(s string) string { return "set xact_abort on; begin transaction; " + s + "; commit" }
	switch action {
	case "add":
		if u.NoLogin {
			s := "create role " + id
			return s, s, nil
		}
		user := "; create user " + id + " for login " + id
		return wrap("create login " + id + " with password = " + mslit(u.Password) + user),
			"create login " + id + " with password = '[hidden]'" + user, nil
	case "passwd":
		return "alter login " + id + " with password = " + mslit(u.Password), "alter login " + id + " with password = '[hidden]'", nil
	case "rm":
		s := "if exists (select 1 from sys.database_principals where name = " + mslit(u.Name) + " and type = 'R') drop role " + id +
			" else drop user " + id + "; if suser_id(" + mslit(u.Name) + ") is not null drop login " + id
		return wrap(s), s, nil
	}
	return "", "", out.Usage("unknown user action %q", action)
}

var msPrivs = map[string]bool{"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "EXECUTE": true, "REFERENCES": true,
	"ALTER": true, "CONTROL": true, "VIEW DEFINITION": true, "CREATE TABLE": true, "CREATE VIEW": true, "CREATE PROCEDURE": true,
	"CREATE FUNCTION": true, "CREATE SCHEMA": true, "SHOWPLAN": true, "CONNECT": true, "VIEW DATABASE STATE": true}

// mssqlGrantSQL is GrantSQL for SQL Server. OBJECT is database (the
// conn's), schema:NAME, all-tables:SCHEMA (the same) or table:[SCHEMA.]TABLE;
// --role adds the user to a database role (db_datareader, ...).
func mssqlGrantSQL(ctx context.Context, db *sql.DB, g Grant) (string, error) {
	if g.Host != "" {
		return "", out.Usage("--from is for MySQL; SQL Server logins are not tied to a host")
	}
	if g.Role != "" {
		if err := checkRole(g.Role); err != nil {
			return "", err
		}
		verb := map[bool]string{false: " add member ", true: " drop member "}[g.Revoke]
		return "alter role " + msid(g.Role) + verb + msid(g.User), nil
	}
	if len(g.Privs) == 0 {
		return "", out.Usage("name the privileges (--privileges SELECT,INSERT) or a --role")
	}
	privs := make([]string, 0, len(g.Privs))
	for _, p := range g.Privs {
		p = strings.ToUpper(strings.Join(strings.Fields(p), " "))
		if !msPrivs[p] {
			return "", out.Usage("unknown privilege %q", p)
		}
		privs = append(privs, p)
	}
	typ, name, _ := strings.Cut(g.On, ":")
	on := ""
	switch typ {
	case "database":
		if name != "" {
			var current string
			if db != nil {
				_ = db.QueryRowContext(ctx, "SELECT DB_NAME()").Scan(&current)
			}
			if !strings.EqualFold(name, current) {
				return "", out.Usage("on SQL Server, --on database means the conn's database (%s); use a conn for %s", current, name)
			}
		}
	case "schema", "all-tables":
		if !validObj.MatchString(name) {
			return "", out.Usage("schema name %q: letters, digits, _ and $", name)
		}
		on = " on schema::" + msid(name)
	case "table":
		parts := strings.Split(name, ".")
		if len(parts) > 2 {
			return "", out.Usage("--on table:SCHEMA.TABLE")
		}
		q := make([]string, len(parts))
		for i, p := range parts {
			if !validObj.MatchString(p) {
				return "", out.Usage("object name %q: letters, digits, _ and $", p)
			}
			q[i] = msid(p)
		}
		on = " on object::" + strings.Join(q, ".")
	default:
		return "", out.Usage("--on takes database, schema:NAME, all-tables:SCHEMA or table:[SCHEMA.]TABLE")
	}
	verb, prep := "grant ", " to "
	if g.Revoke {
		verb, prep = "revoke ", " from "
	}
	return verb + strings.Join(privs, ", ") + on + prep + msid(g.User), nil
}

// mssqlGrants lists a user's permissions in the conn's database, one row
// per object, and the roles it is a member of.
func mssqlGrants(ctx context.Context, db *sql.DB, user string) ([]map[string]any, error) {
	rows, err := rowsOf(ctx, db, `
SELECT CASE p.class WHEN 0 THEN 'database' WHEN 1 THEN 'table' WHEN 3 THEN 'schema' ELSE LOWER(p.class_desc COLLATE DATABASE_DEFAULT) END AS on_type,
       CASE p.class WHEN 0 THEN DB_NAME() WHEN 1 THEN OBJECT_SCHEMA_NAME(p.major_id) + '.' + OBJECT_NAME(p.major_id)
                    WHEN 3 THEN SCHEMA_NAME(p.major_id) ELSE CAST(p.major_id AS nvarchar(20)) END AS object,
       p.permission_name COLLATE DATABASE_DEFAULT + CASE p.state WHEN 'D' THEN ' (denied)' WHEN 'W' THEN ' (with grant option)' ELSE '' END AS privilege
FROM sys.database_permissions p JOIN sys.database_principals u ON u.principal_id = p.grantee_principal_id
WHERE u.name = @p1
UNION ALL
SELECT 'role', r.name, 'MEMBER' FROM sys.database_role_members m
JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
JOIN sys.database_principals u ON u.principal_id = m.member_principal_id
WHERE u.name = @p1`, user)
	if err != nil {
		return nil, err
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

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
