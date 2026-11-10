package driver

import (
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ClickHouse SQL, read the way ClickHouse's lexer reads it: backslash
// escapes in '...', "..." and `...`, -- and # comments that end at \n,
// nested /* */ comments. Text in $$...$$ (a heredoc) is refused, and so
// are letters outside ASCII outside quotes.
//
// ClickHouse has no transactions. Without --write every request carries
// the setting readonly=1 (dbx), so the server refuses writes, DDL and
// setting changes itself; that is the first layer. A statement that is not
// a read can never be rolled back, so it must be sent on its own, and a
// dry run only reports it (NoTx). What readonly=1 lets through is
// reading from elsewhere: table functions that reach other servers
// (url, s3, remote, mysql), files on the server (file) or programs
// (executable). Those are rated here.

func init() {
	dialects["clickhouse"] = dialect{backslash: true, backtick: true, clickhouse: true}
}

// chFirst are the words a ClickHouse statement komando knows starts with.
var chFirst = wordSet(`SELECT WITH SHOW DESCRIBE DESC EXISTS EXPLAIN SET USE INSERT ALTER CREATE DROP
	TRUNCATE RENAME EXCHANGE OPTIMIZE ATTACH DETACH UNDROP DELETE UPDATE GRANT REVOKE KILL SYSTEM
	BACKUP RESTORE MOVE CHECK BEGIN START COMMIT ROLLBACK`)

// chReads read only: they run with readonly=1 and may share a run with
// other reads. Every other statement is sent alone.
var chReads = wordSet(`SELECT WITH SHOW DESCRIBE DESC EXISTS EXPLAIN SET USE`)

// chPrincipals follow CREATE, ALTER or DROP when access rights change.
var chPrincipals = wordSet(`USER ROLE QUOTA ROW POLICY MASKING SETTINGS PROFILE`)

// chCalls rate table functions, table and database engines, and
// dictionary sources by name (upper case), when a ( follows: what reads
// or writes outside the server's own tables. readonly=1 allows reads
// from them.
var chCalls = map[string]string{
	"URL": "sql-remote", "URLCLUSTER": "sql-remote", "GCS": "sql-remote", "OSS": "sql-remote", "COSN": "sql-remote",
	"REMOTE": "sql-remote", "REMOTESECURE": "sql-remote", "MYSQL": "sql-remote", "POSTGRESQL": "sql-remote",
	"MONGODB": "sql-remote", "MONGO": "sql-remote", "REDIS": "sql-remote", "ODBC": "sql-remote", "JDBC": "sql-remote",
	"HIVE": "sql-remote", "KAFKA": "sql-remote", "RABBITMQ": "sql-remote", "NATS": "sql-remote",
	"MATERIALIZEDMYSQL": "sql-remote", "MATERIALIZEDPOSTGRESQL": "sql-remote", "EXTERNALDISTRIBUTED": "sql-remote",
	"HTTP": "sql-remote", "CLICKHOUSE": "sql-remote", "CASSANDRA": "sql-remote", "YTSAURUS": "sql-remote",
	"ARROWFLIGHT": "sql-remote", "ARROWFLIGHTSQL": "sql-remote", "DATALAKECATALOG": "sql-remote",
	"FILE": "sql-server-file", "FILECLUSTER": "sql-server-file", "FILELOG": "sql-server-file", "SQLITE": "sql-server-file",
	"FILESYSTEM": "sql-server-file", "YAMLREGEXPTREE": "sql-server-file",
	"EXECUTABLE": "sql-program", "EXECUTABLEPOOL": "sql-program", "EXECUTABLE_POOL": "sql-program",
}

// chCallPrefixes are families of the same: s3, s3Cluster, S3Queue,
// azureBlobStorage, icebergS3, deltaLakeAzure, hdfsCluster, ...
var chCallPrefixes = []string{"S3", "AZURE", "HDFS", "ICEBERG", "DELTALAKE", "HUDI", "PAIMON"}

func chCallRule(name string) string {
	if id, ok := chCalls[name]; ok {
		return id
	}
	for _, p := range chCallPrefixes {
		if strings.HasPrefix(name, p) {
			return "sql-remote"
		}
	}
	return ""
}

// clickhouseStatement rates one ClickHouse statement: the general rules,
// then ClickHouse's own statements and what reaches outside the server.
func clickhouseStatement(ts []token) (Risk, []string, error) {
	for _, t := range ts {
		if strings.IndexFunc(t.word, func(r rune) bool { return r >= utf8.RuneSelf }) >= 0 {
			return 0, nil, hiddenCode("put names with letters outside ASCII in `backticks` and text in 'quotes': komando cannot tell how ClickHouse reads other characters",
				"ClickHouse SQL has a character outside ASCII that is not quoted (%s)", strings.ToLower(t.word))
		}
		if strings.Contains(t.ident, `\`) {
			return 0, nil, hiddenCode("write the name without backslash escapes: ClickHouse decodes them (`\\x75rl` is url), so komando cannot check it",
				"a quoted name has a backslash in ClickHouse SQL")
		}
		if t.punct == '$' {
			return 0, nil, hiddenCode("write text in 'quotes' (with \\' for a quote inside): komando does not read $$ heredocs",
				"$ outside quotes is not allowed in ClickHouse SQL")
		}
	}
	// ClickHouse has no MERGE statement: merge(...) is a table function
	// that reads other tables, so the word is a name here
	general := slices.Clone(ts)
	for i, t := range general {
		if t.word == "MERGE" {
			general[i].word, general[i].ident = "", "MERGE"
		}
	}
	risk, rules, err := classifyStatement(general, true)
	if err != nil {
		return 0, nil, err
	}
	if firstWord(ts) == "EXISTS" && risk == RiskWrite && len(rules) == 0 {
		risk = RiskRead // EXISTS TABLE t: whether it is there
	}
	flag := func(id string) {
		for _, r := range rules {
			if r == id {
				risk = RiskDestructive
				return
			}
		}
		rules = append(rules, id)
		risk = RiskDestructive
	}
	word := func(i int) string {
		if i >= 0 && i < len(ts) {
			return ts[i].word
		}
		return ""
	}
	first, second := firstWord(ts), word(1)
	switch first {
	case "SYSTEM":
		if second == "SHUTDOWN" || second == "KILL" {
			flag("sql-kill")
		} else {
			flag("sql-server-config")
		}
	case "DETACH":
		flag("sql-drop")
	case "BACKUP", "RESTORE":
		flag("sql-server-file")
	case "REPLACE": // REPLACE TABLE t ...: the old table and its data go
		flag("sql-drop")
	case "MOVE": // MOVE USER ... TO another access storage
		flag("sql-privileges")
	case "CREATE", "ALTER", "DROP":
		if chPrincipals[second] || second == "OR" && word(2) == "REPLACE" && chPrincipals[word(3)] {
			flag("sql-privileges")
		}
		if first == "CREATE" && second == "OR" && word(2) == "REPLACE" && !chPrincipals[word(3)] &&
			word(3) != "VIEW" && word(3) != "FUNCTION" && word(3) != "DICTIONARY" {
			flag("sql-drop") // CREATE OR REPLACE TABLE drops the old table and its data
		}
		if second == "NAMED" && word(2) == "COLLECTION" { // holds connection settings, often passwords
			flag("sql-server-config")
		}
	}
	for i, t := range ts {
		switch {
		case first == "ALTER" && t.depth == 0 && chAlterRule(ts, i) != "":
			flag(chAlterRule(ts, i))
		case i+1 < len(ts) && ts[i+1].punct == '(':
			name := t.word
			if t.ident != "" {
				name = t.ident
			}
			if id := chCallRule(name); id != "" {
				flag(id)
			}
		case t.word == "ENGINE" && i+2 < len(ts) && ts[i+1].punct == '=':
			// an engine reaches out without arguments too: ENGINE = Filesystem
			// serves the server's user_files, ENGINE = S3 any URL, Kafka its settings
			if id := chCallRule(ts[i+2].word); id != "" {
				flag(id)
			}
		}
	}
	return risk, rules, nil
}

// chAlterRule rates the ALTER action word at ts[i].
func chAlterRule(ts []token, i int) string {
	word := func(k int) string {
		if k >= 0 && k < len(ts) {
			return ts[k].word
		}
		return ""
	}
	switch ts[i].word {
	case "CLEAR", "DETACH": // CLEAR COLUMN empties it, DETACH PARTITION takes the data away
		return "sql-drop"
	case "TTL": // MODIFY TTL, MATERIALIZE TTL, a column TTL: rows or values past it are deleted
		if word(i-1) != "REMOVE" {
			return "sql-drop"
		}
	case "REPLACE": // REPLACE PARTITION ... FROM overwrites the partition
		if word(i+1) == "PARTITION" || word(i+1) == "PART" {
			return "sql-drop"
		}
	case "MOVE": // MOVE PARTITION ... TO TABLE takes the data out of this table; TO DISK keeps it
		for k := i + 1; k+1 < len(ts) && ts[k].punct != ','; k++ {
			if ts[k].word == "TO" && ts[k+1].word == "TABLE" {
				return "sql-drop"
			}
		}
	case "FREEZE", "UNFREEZE": // copies or removes parts under shadow/ on the server
		return "sql-server-file"
	}
	return ""
}

// clickhouseRows reports statements that return rows.
func clickhouseRows(kw string) bool { return chReads[kw] && kw != "SET" && kw != "USE" }

// clickhousePlaceholders counts {p1:Type}, {p2:Type}, ... (komando passes
// --arg values as the query parameters p1, p2, ...). Other {names} are
// parameters komando cannot fill.
func clickhousePlaceholders(toks [][]token) (int, bool) {
	n := 0
	for _, ts := range toks {
		for i, t := range ts {
			if t.punct != '{' || i+2 >= len(ts) || ts[i+2].punct != ':' {
				continue
			}
			name := ts[i+1].word
			k, err := strconv.Atoi(strings.TrimPrefix(name, "P"))
			if !strings.HasPrefix(name, "P") || err != nil || k < 1 {
				return 0, false
			}
			n = max(n, k)
		}
	}
	return n, true
}
