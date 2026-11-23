package capability

// database: SQL and MongoDB. A database keeps query and shell (its raw
// commands) and backup and restore, which query cannot do.

type dbProvider struct {
	provider
	shell   bool  // mongodb has none
	backup  State // Built where today's db dump works
	restore State
}

var dbProviders = []dbProvider{
	{provider: provider{name: "postgres", connect: []Option{credentialOpt}}, shell: true},
	{provider: provider{name: "mysql", connect: []Option{credentialOpt}}, shell: true},
	{provider: provider{name: "mariadb", state: New, connect: []Option{credentialOpt}}, shell: true, backup: New, restore: New},
	{provider: provider{name: "sqlserver", connect: []Option{credentialOpt}}, shell: true, backup: New, restore: New},
	{provider: provider{name: "oracle", connect: []Option{credentialOpt}}, shell: true, backup: New, restore: New},
	{provider: provider{name: "sqlite"}, shell: true, restore: New}, // restore refused on purpose today
	{provider: provider{name: "mongodb", connect: []Option{credentialOpt}}, backup: New, restore: New},
	{provider: provider{name: "clickhouse", connect: []Option{credentialOpt}}, shell: true, backup: New, restore: New},
	{provider: provider{name: "snowflake", connect: []Option{credentialOpt}}, shell: true, backup: New, restore: New},
	{provider: provider{name: "bigquery", connect: []Option{credentialOpt}}, shell: true, backup: New, restore: New},
}

// queryCarries are the db commands of today that query does now.
var queryCarries = join(
	idsOf("db", "activity", "explain", "grant", "info", "kill", "locks", "revoke", "schema", "sizes"),
	idsOf("db.user", "add", "list", "passwd", "rm", "show"),
)

var databaseLeaves = databaseTable(dbProviders)

func databaseTable(ps []dbProvider) []Leaf {
	var out []Leaf
	inv := conns("database", "db.add")
	for _, p := range ps {
		out = append(out, inv.leaves(p.provider)...)
		key := func(verb string) Key { return Key{Type: "database", Provider: p.name, Verb: verb} }
		out = append(out,
			Leaf{Key: key("query"), Args: []Arg{{Name: "NAME"}, {Name: "QUERY"}}, Options: []Option{writeOpt},
				Output: TargetData, State: p.state, Today: []string{"db.query"}, Carries: queryCarries},
			Leaf{Key: key("backup"), Args: []Arg{{Name: "NAME"}, {Name: "FILE"}}, State: max(p.state, p.backup),
				Today: []string{"db.dump"}},
			Leaf{Key: key("restore"), Args: []Arg{{Name: "NAME"}, {Name: "FILE"}}, State: max(p.state, p.restore),
				Today: []string{"db.restore"}},
		)
		if p.shell {
			out = append(out, Leaf{Key: key("shell"), Args: oneName, State: p.state, Today: []string{"db.shell"}})
		}
	}
	return out
}
