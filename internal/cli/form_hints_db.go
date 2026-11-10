package cli

// The questions for the Databases area: queries, the shell, health checks,
// backups and database users.

func init() {
	addFormHints(dbLookHints)
	addFormHints(dbChangeHints)
	addFormHints(dbUserHints)
}

// Answers several hints share.
var (
	dbConn = formArg{ask: "Which database?", pick: "db",
		help: "A database you added to komando. Add one first with Add > Database when the list is empty."}
	dbSQL = formArg{ask: "Which SQL should it run?", example: "select id, email from users order by id desc limit 10",
		help: "One or more statements, ending with ; when there are several. On MongoDB: a JSON command like {\"find\": \"users\"}."}
	dbWrite = formFlag{name: "write", ask: "May it change data?",
		help: "No runs it read-only, so nothing can change. Say yes only for insert, update, delete or create."}
	dbArg = formFlag{name: "arg", ask: "A value for a placeholder in the SQL?",
		help:    "When the SQL has $1 (PostgreSQL) or ? (MySQL, SQLite), its value goes here, so you never paste it into the SQL. Leave empty when there is none.",
		example: "bob@example.com"}
	dbLimit = formFlag{name: "limit", ask: "Show at most how many rows?",
		help: "0 shows every row. Big results are cut anyway, so keep it small for a first look.", example: "100"}
	dbUser = formArg{ask: "Which database user?", example: "app_ro",
		help: "The user name inside the database, not your SSH user. `komando db user ls` shows them."}
	dbFrom = formFlag{name: "from", ask: "MySQL only: from where does this user connect?",
		help:    "The account host, like 10.0.0.% or localhost. Leave empty for % (anywhere), or on PostgreSQL.",
		example: "10.0.0.%"}
	dbOn = formFlag{name: "on", ask: "Which server should run the backup tool?", pick: "server",
		help: "A server that has pg_dump or mysqldump and can reach the database. Leave empty to use the server the database is reached through."}
	dbPasswordRef = formFlag{name: "password-ref", ask: "Where is the password kept?", required: true,
		example: "secret:app-ro-pass",
		help:    "A secret reference, never the password itself. Save it first with `komando secret set app-ro-pass`, then type secret:app-ro-pass."}
)

// dbLookHints are the commands that only read.
var dbLookHints = map[string]formHint{
	"db query": {
		args: []formArg{dbConn, {ask: "Which SQL should it run? (leave empty to read it from a file)",
			example: dbSQL.example, help: dbSQL.help}},
		flags: []formFlag{dbWrite,
			{name: "file", ask: "Or read the SQL from which file on this computer?", example: "./migration.sql", local: true,
				help: "Only when you left the SQL empty. A .sql file on this computer."},
			dbArg, dbLimit},
	},
	"db explain": {
		args: []formArg{dbConn, {ask: "Which query should it explain?", example: "select * from orders where user_id = 42",
			help: "The SQL you want to make faster. It shows how the database finds the rows (an index or a full scan)."}},
		flags: []formFlag{
			{name: "analyze", ask: "Run the query too and measure the real time?",
				help: "Yes runs it for real, which takes as long as the query. A query that changes data then needs a yes to the next question."},
			dbWrite},
	},
	"db schema": {
		args: []formArg{dbConn, {ask: "Which tables? (leave empty to list them all)", example: "users orders",
			help: "Names of tables to see their columns and indexes. Several: separate them with spaces. On PostgreSQL also schema.table."}},
	},
	"db info": {args: []formArg{dbConn}},
	"db activity": {
		args: []formArg{dbConn},
		flags: []formFlag{{name: "all", ask: "Show idle sessions too?",
			help: "No shows only sessions running something now."}},
	},
	"db locks": {args: []formArg{dbConn}},
	"db sizes": {
		args:  []formArg{dbConn},
		flags: []formFlag{{name: "limit", ask: "Show how many of the biggest tables and indexes?", example: "10"}},
	},
	"db grants": {
		args:  []formArg{dbConn, dbUser},
		flags: []formFlag{dbFrom},
	},
	"db user ls": {args: []formArg{dbConn}},
	"db shell": {
		args: []formArg{{ask: "Which database?", pick: "db",
			help: "You type SQL in it and see the rows. \\q leaves, \\? lists what else it knows."}},
		flags: []formFlag{{name: "write", ask: "May the statements you type change data?",
			help: "No keeps the whole session read-only. Say yes only when you plan to insert, update or delete."}},
	},
}

// dbChangeHints are the commands that stop, save or load something.
var dbChangeHints = map[string]formHint{
	"db kill": {
		args: []formArg{dbConn, {ask: "Which session number (PID)?", example: "4821",
			help: "The pid column of `komando db activity` or `komando db locks`."}},
		flags: []formFlag{{name: "session", ask: "End the whole connection, not only its query?",
			help: "No stops only the running query and the program stays connected. Yes disconnects it."}},
	},
	"db dump": {
		args: []formArg{{ask: "Which database should it back up?", pick: "db",
			help: "A database you added to komando."}},
		flags: []formFlag{
			{name: "to", ask: "Save the backup to which file on this computer?", required: true, local: true,
				example: "./prod-2026-11-10.sql.gz",
				help:    "A new file; it never overwrites one. Ending in .gz makes it smaller. Only you can read it."},
			{name: "format", ask: "Which kind of backup?", choices: []string{"plain", "custom"},
				help: "plain is SQL any database tool reads. custom is PostgreSQL's own archive (needs pg_dump on a server; no .gz then)."},
			{name: "schema-only", ask: "Only the tables' shape, without the rows?",
				help: "Yes saves tables, indexes and functions but no data."},
			{name: "table", ask: "Only one table?", example: "public.orders",
				help: "Leave empty for the whole database. On PostgreSQL write schema.table."},
			dbOn},
	},
	"db restore": {
		args: []formArg{{ask: "Which database should it load the backup into?", pick: "db",
			help: "What is in it can be overwritten, so pick a test copy when you only want to try."}},
		flags: []formFlag{
			{name: "from", ask: "Which backup file on this computer?", required: true, local: true, example: "./prod-2026-11-10.sql.gz",
				help: "A file from `komando db dump`, pg_dump or mysqldump. A .gz file is read as it is."},
			{name: "on", ask: "Which server should run pg_restore?", pick: "server",
				help: "Only for a PostgreSQL custom archive. Leave empty to use the server the database is reached through."}},
	},
}

// dbUserHints are database users and what they may do.
var dbUserHints = map[string]formHint{
	"db user add": {
		args: []formArg{dbConn, {ask: "What is the new user's name?", example: "app_ro",
			help: "The name a program or person logs in to the database with. Letters, digits and underscore."}},
		flags: []formFlag{
			{name: "password-ref", ask: dbPasswordRef.ask, example: dbPasswordRef.example,
				help: dbPasswordRef.help + " Leave empty only with a user that cannot log in."},
			{name: "no-login", ask: "PostgreSQL only: a role that cannot log in?",
				help: "Yes makes a group of rights you give to other users later. It needs no password."},
			dbFrom},
	},
	"db user passwd": {
		args:  []formArg{dbConn, dbUser},
		flags: []formFlag{dbPasswordRef, dbFrom},
	},
	"db user rm": {
		args:  []formArg{dbConn, dbUser},
		flags: []formFlag{dbFrom},
	},
	"db grant":  dbGrantHint("Give the user which rights?"),
	"db revoke": dbGrantHint("Take which rights away?"),
}

// dbGrantHint is grant and revoke: privileges on an object, or a role.
func dbGrantHint(ask string) formHint {
	return formHint{
		args: []formArg{dbConn, dbUser},
		flags: []formFlag{
			{name: "privileges", ask: ask, example: "SELECT",
				help: "Separate several with commas, like SELECT,INSERT,UPDATE, or ALL. Leave empty when you give a role instead."},
			{name: "on", ask: "On what?", example: "all-tables:public",
				help: "PostgreSQL: database:NAME, schema:NAME, table:NAME or all-tables:SCHEMA. MySQL: shop.* or shop.orders. Needed with rights."},
			{name: "role", ask: "Or which role? (PostgreSQL)", example: "readers",
				help: "Makes the user a member of a role. Leave empty when you gave rights above."},
			dbFrom},
	}
}
