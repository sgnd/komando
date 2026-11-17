package driver

import "strings"

// dangerousFuncs have side effects a read-only transaction does not stop.
var dangerousFuncs = map[string]string{
	"PG_TERMINATE_BACKEND": "sql-kill", "PG_CANCEL_BACKEND": "sql-kill", "PG_PROMOTE": "sql-kill",
	"PG_RELOAD_CONF": "sql-server-config", "PG_ROTATE_LOGFILE": "sql-server-config", "PG_SWITCH_WAL": "sql-server-config",
	"PG_CREATE_RESTORE_POINT": "sql-server-config", "PG_WAL_REPLAY_PAUSE": "sql-server-config", "PG_WAL_REPLAY_RESUME": "sql-server-config",
	"PG_DROP_REPLICATION_SLOT": "sql-server-config", "PG_CREATE_PHYSICAL_REPLICATION_SLOT": "sql-server-config",
	"PG_CREATE_LOGICAL_REPLICATION_SLOT": "sql-server-config", "PG_STAT_RESET": "sql-server-config",
	"LO_EXPORT": "sql-server-file", "LO_IMPORT": "sql-server-file", "PG_READ_FILE": "sql-server-file",
	"PG_READ_BINARY_FILE": "sql-server-file", "PG_FILE_WRITE": "sql-server-file", "PG_FILE_UNLINK": "sql-server-file",
	"PG_FILE_RENAME": "sql-server-file", "PG_FILE_SYNC": "sql-server-file", "PG_STAT_FILE": "sql-server-file",
	"PG_LOGDIR_LS": "sql-server-file", "PG_CURRENT_LOGFILE": "sql-server-file", "LOAD_FILE": "sql-server-file",
	"SYS_EXEC": "sql-program", "SYS_EVAL": "sql-program",
}

// funcRule rates a function call by name; prefixes cover function families.
func funcRule(name string) (string, bool) {
	if id, ok := dangerousFuncs[name]; ok {
		return id, true
	}
	switch {
	case strings.HasPrefix(name, "DBLINK"), name == "HTTP", strings.HasPrefix(name, "HTTP_"):
		return "sql-remote", true // dblink; pgsql-http fetches a URL
	case strings.HasPrefix(name, "PG_BACKGROUND_"):
		return "sql-opaque", true // runs SQL in a worker, outside komando's read-only transaction
	case strings.HasPrefix(name, "PG_STAT_RESET"), strings.HasPrefix(name, "PG_REPLICATION_ORIGIN_"):
		return "sql-server-config", true
	case strings.HasPrefix(name, "PG_") && strings.HasSuffix(name, "_RESET"): // pg_stat_statements_reset and other extensions' counters
		return "sql-server-config", true
	case name == "PG_REPLICATION_SLOT_ADVANCE", // a slot moved on or read out loses changes for its consumer
		strings.HasPrefix(name, "PG_LOGICAL_SLOT_GET_"),
		strings.HasPrefix(name, "PG_COPY_") && strings.HasSuffix(name, "_REPLICATION_SLOT"),
		name == "PG_LOGICAL_EMIT_MESSAGE", // written to the WAL even when the transaction rolls back
		strings.HasPrefix(name, "PG_BACKUP_"), name == "PG_START_BACKUP", name == "PG_STOP_BACKUP",
		name == "PG_SYNC_REPLICATION_SLOTS", name == "PG_TRUNCATE_VISIBILITY_MAP":
		return "sql-server-config", true
	case strings.HasPrefix(name, "PG_LS_"): // pg_ls_dir, pg_ls_waldir, pg_ls_tmpdir, ...: list server directories
		return "sql-server-file", true
	}
	return "", false
}

// remoteSchemas hold functions that reach another service: aws_s3 and
// aws_lambda (RDS, Aurora), aws_commons. (pg_net's net.http_* are HTTP_.)
var remoteSchemas = map[string]bool{"AWS_S3": true, "AWS_LAMBDA": true, "AWS_COMMONS": true}

// nameOf is a token's name, bare or "quoted".
func nameOf(t token) string {
	if t.ident != "" {
		return t.ident
	}
	return t.word
}

// callRule rates the call of name at ts[i] by its name, or by the schema
// it is in (aws_s3.query_export_to_s3).
func callRule(ts []token, i int, name string) (string, bool) {
	if id, ok := funcRule(name); ok {
		return id, true
	}
	if i >= 2 && ts[i-1].punct == '.' && remoteSchemas[nameOf(ts[i-2])] {
		return "sql-remote", true
	}
	return "", false
}
