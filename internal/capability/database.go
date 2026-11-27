package capability

// database: SQL and MongoDB. A database keeps query and shell (its raw
// commands) and backup and restore, which query cannot do.

type dbProvider struct {
	provider
	shell   bool  // mongodb has none
	backup  State // Built where today's db dump works
	restore State
	what    string // how a Short names the provider: "PostgreSQL"
	read    string // a read in the provider's own language, for the examples
	write   string // a change, for the examples
}

var dbProviders = []dbProvider{
	{provider: provider{name: "postgres", connect: []Option{credentialOpt}, entry: "prod-db", url: "postgres://app@10.0.0.5:5432/shop"}, shell: true,
		what: "PostgreSQL", read: `"select id, email from users order by id desc limit 10"`, write: `"update users set plan = 'pro' where id = 42"`},
	{provider: provider{name: "mysql", connect: []Option{credentialOpt}, entry: "shop-mysql", url: "mysql://app@10.0.0.6:3306/shop"}, shell: true,
		what: "MySQL", read: `"select id, email from users order by id desc limit 10"`, write: `"update users set plan = 'pro' where id = 42"`},
	{provider: provider{name: "mariadb", state: New, connect: []Option{credentialOpt}, entry: "shop-maria", url: "mariadb://app@10.0.0.6:3306/shop"}, shell: true, backup: New, restore: New,
		what: "MariaDB", read: `"select id, email from users order by id desc limit 10"`, write: `"update users set plan = 'pro' where id = 42"`},
	{provider: provider{name: "sqlserver", connect: []Option{credentialOpt}, entry: "sales-mssql", url: "sqlserver://app@10.0.0.7:1433/sales"}, shell: true, backup: New, restore: New,
		what: "SQL Server", read: `"select top 10 id, email from users order by id desc"`, write: `"update users set plan = 'pro' where id = 42"`},
	{provider: provider{name: "oracle", connect: []Option{credentialOpt}, entry: "erp-oracle", url: "oracle://app@10.0.0.8:1521/ERP"}, shell: true, backup: New, restore: New,
		what: "Oracle", read: `"select id, email from users order by id desc fetch first 10 rows only"`, write: `"update users set plan = 'pro' where id = 42"`},
	{provider: provider{name: "sqlite", entry: "local", url: "sqlite:///var/lib/app.db"}, shell: true, restore: New, // restore refused on purpose today
		what: "SQLite", read: `"select id, email from users order by id desc limit 10"`, write: `"update users set plan = 'pro' where id = 42"`},
	{provider: provider{name: "mongodb", connect: []Option{credentialOpt}, entry: "prod-mongo", url: "mongodb://app@10.0.0.9:27017/app"}, backup: New, restore: New,
		what: "MongoDB", read: `'{"find": "users", "filter": {"plan": "pro"}, "limit": 10}'`, write: `'{"update": "users", "updates": [{"q": {"_id": 42}, "u": {"$set": {"plan": "pro"}}}]}'`},
	{provider: provider{name: "clickhouse", connect: []Option{credentialOpt}, entry: "events-ch", url: "clickhouse://app@10.0.0.10:8123/events"}, shell: true, backup: New, restore: New,
		what: "ClickHouse", read: `"select count() from hits where day = today()"`, write: `"alter table hits delete where day < '2026-01-01'"`},
	{provider: provider{name: "snowflake", connect: []Option{credentialOpt}, entry: "analytics", url: "snowflake://app_ro@myorg-acct/ANALYTICS/PUBLIC?warehouse=REPORTING"}, shell: true, backup: New, restore: New,
		what: "Snowflake", read: `"select count(*) from orders"`, write: `"update orders set status = 'paid' where id = 42"`},
	{provider: provider{name: "bigquery", connect: []Option{credentialOpt}, entry: "bq", url: "bigquery://my-project/shop"}, shell: true, backup: New, restore: New,
		what: "BigQuery", read: `"select count(*) from shop.orders"`, write: `"update shop.orders set status = 'paid' where id = 42"`},
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
		ls := []Leaf{
			{Key: key("query"), Args: []Arg{{Name: "NAME"}, {Name: "QUERY", Optional: true}}, Options: queryOptions(p),
				Output: TargetData, State: p.state, Today: []string{"db.query"}, Carries: queryCarries},
			{Key: key("backup"), Args: oneName, Options: backupOptions(p), State: max(p.state, p.backup),
				Today: []string{"db.dump"}},
			{Key: key("restore"), Args: oneName, Options: restoreOptions(p), State: max(p.state, p.restore),
				Today: []string{"db.restore"}},
		}
		if p.shell {
			ls = append(ls, Leaf{Key: key("shell"), Args: oneName, Options: []Option{shellWrite}, State: p.state, Today: []string{"db.shell"}})
		}
		for i := range ls {
			ls[i].Short, ls[i].Example = p.text(ls[i].Verb)
		}
		out = append(out, ls...)
	}
	return out
}

// The options of today's db query, dump, restore and shell. A number the
// body checks itself is the body's: the table names the option and the
// default the body has (TestDatabaseBodyDefaultsMatchTable).
var (
	queryLimit  = Option{Name: "limit", Short: "n", Kind: Int, Default: "500", Help: "the most rows to return per statement (0 = no limit; --max-output caps the size too)"}
	queryArg    = Option{Name: "arg", Kind: String, Repeat: true, Help: "a value for a placeholder, in order (repeatable)"}
	queryFile   = Option{Name: "file", Short: "f", Kind: File, Help: "read the query from a file ('-' for stdin)"}
	queryBytes  = Option{Name: "max-bytes", Kind: String, Help: "the most a query may read, which BigQuery bills by, like 50GB (default 10GB; 0 = no cap)"}
	backupTo    = Option{Name: "to", Kind: File, Help: "the file to create on this computer, or a folder (default: NAME-<date>.sql.gz here; SQLite: NAME-<date>.db)"}
	backupForm  = Option{Name: "format", Kind: Enum, Enum: []string{"plain", "custom"}, Default: "plain", Help: "plain (SQL) or custom (a PostgreSQL archive for pg_restore)"}
	backupBare  = Option{Name: "schema-only", Kind: Bool, Help: "tables, indexes and functions, no rows"}
	backupTable = Option{Name: "table", Kind: String, Repeat: true, Help: "only this table (repeatable; SCHEMA.TABLE on PostgreSQL)"}
	backupOn    = Option{Name: "run-on", Kind: Entry, Help: "run the dump tool on this server (default: the database's --via server)"}
	restoreFrom = Option{Name: "from", Kind: File, Help: "the backup file on this computer"}
	restoreOn   = Option{Name: "run-on", Kind: Entry, Help: "run pg_restore for a PostgreSQL archive on this server (default: the database's --via server)"}
	shellWrite  = Option{Name: "write", Kind: Bool, Help: "allow changes in this session"}
)

// queryOptions are the options of query: --max-bytes is BigQuery's own.
func queryOptions(p dbProvider) []Option {
	o := []Option{writeOpt, queryLimit, queryArg, queryFile}
	if p.name == "bigquery" {
		o = append(o, queryBytes)
	}
	return o
}

// backupOptions follow what today's db dump takes for the provider: a
// SQLite backup copies the file, so it takes only --to; --format custom is
// PostgreSQL's archive.
func backupOptions(p dbProvider) []Option {
	switch p.name {
	case "postgres":
		return []Option{backupTo, backupForm, backupBare, backupTable, backupOn}
	case "mysql":
		return []Option{backupTo, backupBare, backupTable, backupOn}
	}
	return []Option{backupTo}
}

// restoreOptions: only a PostgreSQL archive is loaded on a server.
func restoreOptions(p dbProvider) []Option {
	if p.name == "postgres" {
		return []Option{restoreFrom, restoreOn}
	}
	return []Option{restoreFrom}
}

// text is the Short and the Example of one of the provider's own verbs.
func (p dbProvider) text(verb string) (short, example string) {
	cmd := "  komando database " + p.name + " " + verb + " " + p.entry
	switch verb {
	case "query":
		short = "Run a query on a " + p.what + " database (read only unless --write)"
		example = cmd + " " + p.read + "\n" + cmd + " --write --dry-run " + p.write
		if p.name == "bigquery" {
			example += "\n" + cmd + " " + p.read + " --max-bytes 50GB"
		}
	case "backup":
		short = "Save a copy of a " + p.what + " database to a file on this computer"
		example = cmd + " --to backups/\n" + cmd + " --to " + p.entry + ".sql.gz --dry-run"
		switch p.name {
		case "postgres":
			example += "\n" + cmd + " --to " + p.entry + ".dump --format custom --run-on db1"
		case "sqlite":
			example = cmd + " --to backup.db\n" + cmd + " --to backup.db --dry-run"
		}
	case "restore":
		short = "Load a backup into a " + p.what + " database"
		example = cmd + " --from " + p.entry + ".sql.gz --dry-run\n" + cmd + " --from " + p.entry + ".sql.gz --allow-dangerous"
	case "shell":
		short = "Open komando's SQL shell on a " + p.what + " database (read only unless --write)"
		example = cmd + "\n" + cmd + " --write"
	}
	return short, example
}
