package dbx

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/sgnd/komando/internal/out"
)

// MongoDB's side of db kill and db user list/show. A user's stored
// credentials are never asked for (usersInfo leaves them out unless
// showCredentials is set, which komando never sets).

// MongoSession is the operation opid as db activity --all shows it.
func MongoSession(ctx context.Context, m *Mongo, opid int64) (map[string]any, error) {
	rows, err := MongoActivity(ctx, m, true)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if fmt.Sprint(r["pid"]) == strconv.FormatInt(opid, 10) {
			return r, nil
		}
	}
	return nil, out.Errf(out.ExitNotFound, "SESSION_NOT_FOUND", "list operations with `komando db activity CONN --all`", "no operation %d", opid)
}

// MongoKill stops one operation (killOp). The client stays connected.
func MongoKill(ctx context.Context, m *Mongo, opid int64) error {
	cmd := bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: opid}}
	return mongoErr(m.C.Database("admin").RunCommand(ctx, cmd).Err())
}

// MongoKillNoSession is db kill --session on MongoDB, which stops
// operations, not connections.
func MongoKillNoSession() error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"MongoDB stops operations (killOp), not connections: drop --session",
		"db kill --session is not available for mongodb")
}

// MongoNoUserChange is db user add/passwd/rm and db grant/revoke on MongoDB.
func MongoNoUserChange(what string) error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"send the command yourself with `komando db query CONN --write` (createUser, grantRolesToUser ...: it needs --allow-dangerous, so ask the user first); `db user list` and `db user show` work",
		"%s is not available for mongodb", what)
}

type mongoUser struct {
	User       string   `bson:"user"`
	DB         string   `bson:"db"`
	Mechanisms []string `bson:"mechanisms"`
	Roles      []struct {
		Role string `bson:"role"`
		DB   string `bson:"db"`
	} `bson:"roles"`
	Privileges []struct {
		Resource struct {
			DB          *string `bson:"db"`
			Collection  *string `bson:"collection"`
			Cluster     bool    `bson:"cluster"`
			AnyResource bool    `bson:"anyResource"`
		} `bson:"resource"`
		Actions []string `bson:"actions"`
	} `bson:"inheritedPrivileges"`
}

func mongoUsersInfo(ctx context.Context, m *Mongo, arg any, privileges bool) ([]mongoUser, error) {
	cmd := bson.D{{Key: "usersInfo", Value: arg}}
	if privileges {
		cmd = append(cmd, bson.E{Key: "showPrivileges", Value: true})
	}
	var reply struct {
		Users []mongoUser `bson:"users"`
	}
	if err := m.C.Database("admin").RunCommand(ctx, cmd).Decode(&reply); err != nil {
		return nil, mongoErr(err)
	}
	sort.Slice(reply.Users, func(i, j int) bool {
		a, b := reply.Users[i], reply.Users[j]
		return a.User < b.User || a.User == b.User && a.DB < b.DB
	})
	return reply.Users, nil
}

func roleList(u mongoUser) string {
	var r []string
	for _, x := range u.Roles {
		r = append(r, x.Role+"@"+x.DB)
	}
	sort.Strings(r)
	return strings.Join(r, ",")
}

// MongoUsers lists the users of every database: name, the database it
// belongs to (where it logs in), its roles and login mechanisms.
func MongoUsers(ctx context.Context, m *Mongo) ([]map[string]any, error) {
	users, err := mongoUsersInfo(ctx, m, bson.D{{Key: "forAllDBs", Value: true}}, false)
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, u := range users {
		rows = append(rows, map[string]any{"name": u.User, "database": u.DB, "roles": roleList(u), "mechanisms": strings.Join(u.Mechanisms, ",")})
	}
	return rows, nil
}

// MongoGrants is what a user may do, in db user show's shape: one row per
// role, and one per resource its roles give actions on. USER is NAME (in
// any database) or DB.NAME.
func MongoGrants(ctx context.Context, m *Mongo, user string) ([]map[string]any, error) {
	if user == "" {
		return nil, out.Usage("give the user's name")
	}
	all, err := mongoUsersInfo(ctx, m, bson.D{{Key: "forAllDBs", Value: true}}, false)
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	found := false
	for _, u := range all {
		if u.User != user && u.DB+"."+u.User != user {
			continue
		}
		found = true
		one, err := mongoUsersInfo(ctx, m, bson.D{{Key: "user", Value: u.User}, {Key: "db", Value: u.DB}}, true)
		if err != nil {
			return nil, err
		}
		for _, x := range one {
			for _, r := range x.Roles {
				rows = append(rows, map[string]any{"user": x.DB + "." + x.User, "on_type": "role", "object": r.DB, "privileges": r.Role})
			}
			for _, p := range x.Privileges {
				typ, obj := "collection", ""
				switch res := p.Resource; {
				case res.Cluster:
					typ, obj = "cluster", "cluster"
				case res.AnyResource:
					typ, obj = "any", "anyResource"
				case res.DB != nil && res.Collection != nil:
					obj = *res.DB + "." + *res.Collection
					if *res.Collection == "" {
						typ = "database"
						obj = *res.DB
					}
				}
				if obj == "" || obj == "." {
					obj = "*"
				}
				acts := append([]string(nil), p.Actions...)
				sort.Strings(acts)
				rows = append(rows, map[string]any{"user": x.DB + "." + x.User, "on_type": typ, "object": obj, "privileges": strings.Join(acts, ",")})
			}
		}
	}
	if !found {
		return nil, out.Errf(out.ExitNotFound, "DB_USER_NOT_FOUND", "list users with `komando db user list CONN`", "no database user named %q", user)
	}
	return rows, nil
}
