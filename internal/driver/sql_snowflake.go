package driver

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
)

// Snowflake SQL, read the way Snowflake reads it: '...' text with
// backslash escapes and '' for a quote, "..." names with "" for a quote,
// $$...$$ text without escapes, -- and // comments to the end of the line,
// and /* */ comments. snowflakeMask turns this into text the shared lexer
// reads the same way, and refuses what komando cannot be sure of.
//
// Snowflake has no read-only setting komando could send, and each request
// to its SQL API is a session of its own, so no transaction spans two
// statements. The rating here is the only check before Snowflake runs a
// statement: a read may share a run with other reads; everything else
// needs --write, is sent on its own, and a dry run only reports it
// (NoTx). The docs tell people to give the conn a role that may only read.

func init() {
	dialects["snowflake"] = dialect{snowflake: true}
}

// sfFirst are the words a Snowflake statement komando knows starts with.
var sfFirst = wordSet(`SELECT WITH SHOW DESCRIBE DESC EXPLAIN LIST LS SET UNSET USE INSERT UPDATE DELETE MERGE
	TRUNCATE CREATE ALTER DROP UNDROP GRANT REVOKE COPY PUT GET REMOVE RM CALL EXECUTE COMMENT
	BEGIN START COMMIT ROLLBACK DECLARE`)

// sfReads only read. SET and USE change the request's own session, which
// ends with it.
var sfReads = wordSet(`SELECT WITH SHOW DESCRIBE DESC EXPLAIN LIST LS SET USE`)

// sfSystemReads are the SYSTEM$ functions that only read; every other
// SYSTEM$ function changes something (or shows secrets) and is rated.
var sfSystemReads = wordSet(`SYSTEM$CLUSTERING_INFORMATION SYSTEM$CLUSTERING_DEPTH SYSTEM$CLUSTERING_RATIO
	SYSTEM$TYPEOF SYSTEM$EXPLAIN_PLAN_JSON SYSTEM$EXPLAIN_JSON_TO_TEXT SYSTEM$GET_TAG SYSTEM$GET_TAG_ALLOWED_VALUES
	SYSTEM$GET_TAG_ON_CURRENT_COLUMN SYSTEM$GET_TAG_ON_CURRENT_TABLE SYSTEM$ALLOWLIST SYSTEM$ALLOWLIST_PRIVATELINK
	SYSTEM$WHITELIST SYSTEM$WHITELIST_PRIVATELINK SYSTEM$GET_PRIVATELINK_CONFIG SYSTEM$LAST_CHANGE_COMMIT_TIME
	SYSTEM$STREAM_HAS_DATA SYSTEM$PIPE_STATUS SYSTEM$EXTERNAL_TABLE_PIPE_STATUS SYSTEM$TASK_RUNTIME_INFO
	SYSTEM$CURRENT_USER_TASK_NAME SYSTEM$GET_PREDECESSOR_RETURN_VALUE SYSTEM$BEHAVIOR_CHANGE_BUNDLE_STATUS
	SYSTEM$WAIT SYSTEM$ESTIMATE_SEARCH_OPTIMIZATION_COSTS SYSTEM$ESTIMATE_QUERY_ACCELERATION`)

// sfKillFuncs stop other people's work.
var sfKillFuncs = wordSet(`SYSTEM$CANCEL_QUERY SYSTEM$CANCEL_ALL_QUERIES SYSTEM$ABORT_SESSION SYSTEM$ABORT_TRANSACTION`)

// sfSkip are the words between CREATE, ALTER or DROP and the kind of
// object: CREATE OR REPLACE TRANSIENT TABLE IF NOT EXISTS ...
var sfSkip = wordSet(`OR REPLACE ALTER IF NOT EXISTS TEMPORARY TEMP TRANSIENT VOLATILE SECURE LOCAL GLOBAL RECURSIVE`)

// sfPolicies and sfIntegrations come before POLICY and INTEGRATION in
// the name of a kind of object (NETWORK POLICY, STORAGE INTEGRATION), so
// a table named policy is still a table.
var (
	sfPolicies     = wordSet(`NETWORK PASSWORD SESSION MASKING AUTHENTICATION PACKAGES AGGREGATION PROJECTION JOIN PRIVACY`)
	sfIntegrations = wordSet(`API STORAGE NOTIFICATION SECURITY CATALOG`)
)

// sfServerObjects are account-wide: changing them changes what everyone
// gets (warehouses, integrations, shares, the account itself).
var sfServerObjects = wordSet(`ACCOUNT WAREHOUSE INTEGRATION SHARE CONNECTION ORGANIZATION`)

// snowflakeMask returns sql as the shared lexer should see it, with the
// same length: // comments become --, a \' inside '...' becomes two quotes, and $$...$$
// becomes '...' with its text hidden. It refuses letters outside ASCII
// outside quotes, line comments with unusual line breaks, a /* inside a
// comment (whether they nest is not documented), and $$ right after a name.
func snowflakeMask(sql string) (string, error) {
	b := []byte(sql)
	n := len(b)
	next := func(i int) byte {
		if i+1 < n {
			return b[i+1]
		}
		return 0
	}
	for i := 0; i < n; {
		c := b[i]
		switch {
		case c == '-' && next(i) == '-', c == '/' && next(i) == '/':
			b[i], b[i+1] = '-', '-'
			for i += 2; i < n && b[i] != '\n'; {
				r, size := utf8.DecodeRune(b[i:])
				switch {
				case b[i] == '\r' && next(i) == '\n':
				case b[i] < ' ' && b[i] != '\t' || b[i] == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == utf8.RuneError:
					return "", hiddenCode("end -- and // comments with a plain line break, or use /* ... */: komando cannot tell where Snowflake ends this one",
						"a line comment holds a control character or an unusual line break")
				}
				i += size
			}
		case c == '/' && next(i) == '*':
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return "", out.Usage("unterminated /* comment in SQL")
			}
			if strings.Contains(sql[i+2:i+2+end], "/*") {
				return "", hiddenCode("take the /* out of the comment: komando cannot tell whether Snowflake nests comments",
					"a /* comment holds another /*")
			}
			i += 2 + end + 2
		case c == '\'':
			j := i + 1
			for ; j < n; j++ {
				if b[j] == '\\' && j+1 < n {
					if b[j+1] == '\'' {
						b[j] = '\'' // \' is '' for the shared lexer
					}
					j++
					continue
				}
				if b[j] == '\'' {
					if next(j) != '\'' {
						break
					}
					j++
				}
			}
			if j >= n {
				return "", out.Usage("unterminated ' quote in SQL")
			}
			i = j + 1
		case c == '"':
			j := i + 1
			for j < n && (b[j] != '"' || next(j) == '"') {
				if b[j] == '"' {
					j++
				}
				j++
			}
			if j >= n {
				return "", out.Usage(`unterminated " quote in SQL`)
			}
			i = j + 1
		case c == '$' && next(i) == '$':
			if i > 0 && (isWord(b[i-1]) || b[i-1] == '$') {
				return "", hiddenCode("put a space before $$: komando cannot tell whether Snowflake reads it as part of the name",
					"$$ right after a name or number")
			}
			end := strings.Index(sql[i+2:], "$$")
			if end < 0 {
				return "", out.Usage("unterminated $$ quote in SQL")
			}
			b[i], b[i+1] = '\'', ' '
			for k := i + 2; k < i+2+end; k++ {
				b[k] = 'x'
			}
			i += 2 + end
			b[i], b[i+1] = ' ', '\''
			i += 2
		case c >= 0x80:
			return "", hiddenCode("put names with letters outside ASCII in \"double quotes\" and text in 'quotes': komando cannot tell how Snowflake reads other characters",
				"Snowflake SQL has a character outside ASCII that is not quoted")
		default:
			i++
		}
	}
	return string(b), nil
}

// sfPipes splits a statement at the pipe operator ->> (SHOW ... ->>
// SELECT ...), whose parts are statements of their own.
func sfPipes(ts []token) [][]token {
	var parts [][]token
	start := 0
	for i := 0; i+2 < len(ts); i++ {
		if ts[i].depth == 0 && ts[i].punct == '-' && ts[i+1].punct == '>' && ts[i+2].punct == '>' &&
			ts[i+1].pos == ts[i].pos+1 && ts[i+2].pos == ts[i].pos+2 {
			parts = append(parts, ts[start:i])
			start = i + 3
			i += 2
		}
	}
	return append(parts, ts[start:])
}

// snowflakeStatement rates one Snowflake statement: the general rules,
// then Snowflake's own objects, functions and file commands.
func snowflakeStatement(ts []token) (Risk, []string, error) {
	if parts := sfPipes(ts); len(parts) > 1 {
		var risk Risk
		var rules []string
		for _, p := range parts {
			r, ids, err := snowflakeStatement(p)
			if err != nil {
				return 0, nil, err
			}
			risk = max(risk, r)
			for _, id := range ids {
				if !slices.Contains(rules, id) {
					rules = append(rules, id)
				}
			}
		}
		return risk, rules, nil
	}
	word := func(i int) string {
		if i >= 0 && i < len(ts) {
			return ts[i].word
		}
		return ""
	}
	first, second := firstWord(ts), word(1)
	if first == "DECLARE" || first == "BEGIN" && second != "" && second != "TRANSACTION" && second != "WORK" && second != "NAME" {
		return 0, nil, out.Errf(out.ExitUsage, "USAGE",
			"send a Snowflake Scripting block as one statement, EXECUTE IMMEDIATE $$ ... $$ (it needs --write and --allow-dangerous)",
			"a %s ... END block is not one statement for komando", first)
	}
	risk, rules, err := classifyStatement(ts, true)
	if err != nil {
		return 0, nil, err
	}
	if (first == "LIST" || first == "LS") && risk == RiskWrite && len(rules) == 0 {
		risk = RiskRead // LIST @stage: the files there
	}
	if first == "MERGE" { // WHEN MATCHED THEN UPDATE (or DELETE) touches the matched rows only
		rules = slices.DeleteFunc(rules, func(id string) bool { return id == "sql-update-no-where" || id == "sql-delete-no-where" })
		if len(rules) == 0 {
			risk = RiskWrite
		}
	}
	if !sfReads[first] {
		risk = max(risk, RiskWrite)
	}
	flag := func(id string) {
		if !slices.Contains(rules, id) {
			rules = append(rules, id)
		}
		risk = RiskDestructive
	}
	switch first {
	case "CREATE", "ALTER", "DROP", "UNDROP":
		if first == "CREATE" && second == "OR" && word(2) == "REPLACE" {
			flag("sql-drop") // what had the name is dropped
		}
		if id := sfObjectRule(ts); id != "" {
			flag(id)
		}
	case "PUT", "GET", "REMOVE", "RM":
		flag("sql-server-file")
	case "WITH":
		// WITH p AS PROCEDURE (...) AS $$ ... $$ CALL p(): an anonymous
		// procedure, whose body komando cannot see, runs without CREATE rights
		if slices.ContainsFunc(ts, func(t token) bool { return t.word == "PROCEDURE" || t.word == "CALL" }) {
			flag("sql-opaque")
		}
	}
	for i, t := range ts {
		name := t.word
		if t.ident != "" {
			name = t.ident
		}
		switch {
		case t.word == "INTO" && i+1 < len(ts) && (ts[i+1].punct == '@' || ts[i+1].punct == '\''):
			flag("sql-server-file") // COPY INTO @stage or 's3://...': writes files
		case (t.word == "URL" || t.word == "CREDENTIALS") && i+1 < len(ts) && ts[i+1].punct == '=',
			t.word == "EXTERNAL_ACCESS_INTEGRATIONS", t.word == "EXTERNAL" && word(i+1) == "FUNCTION":
			flag("sql-remote")
		case t.word == "TABLE" && i+1 < len(ts) && ts[i+1].punct == '(' && sfOpaqueTable(ts[i+2:]):
			flag("sql-opaque") // TABLE(p()) calls a procedure, which may change anything
		case i+1 < len(ts) && ts[i+1].punct == '(' && strings.HasPrefix(name, "SYSTEM$"):
			switch {
			case sfKillFuncs[name]:
				flag("sql-kill")
			case !sfSystemReads[name]:
				flag("sql-server-config")
			}
		}
	}
	return risk, rules, nil
}

// sfTableFuncs are Snowflake's own table functions, called by a name
// without a schema: TABLE(FLATTEN(...)).
var sfTableFuncs = wordSet(`FLATTEN GENERATOR RESULT_SCAN SPLIT_TO_TABLE STRTOK_SPLIT_TO_TABLE INFER_SCHEMA`)

// sfOpaqueTable reports whether TABLE( is followed by a call komando cannot
// tell from a stored procedure: Snowflake runs a procedure that returns a
// table this way, and the procedure may write. Its own table functions and
// INFORMATION_SCHEMA's (no procedure lives there) are reads; a name
// without a call is a table.
func sfOpaqueTable(ts []token) bool {
	var parts []string
	for k := 0; k < len(ts); k++ {
		switch {
		case ts[k].ident != "": // "flatten" is a name of the user's own, never the built-in
			parts = append(parts, `"`+ts[k].ident)
		case ts[k].word != "":
			parts = append(parts, ts[k].word)
		default:
			return false // TABLE('t'), TABLE($v): a table name in text
		}
		if k+1 >= len(ts) || ts[k+1].punct != '.' {
			if k+1 >= len(ts) || ts[k+1].punct != '(' {
				return false
			}
			break
		}
		k++
	}
	if len(parts) == 1 {
		return !sfTableFuncs[parts[0]]
	}
	return parts[len(parts)-2] != "INFORMATION_SCHEMA"
}

// sfObjectRule rates the kind of object a CREATE, ALTER or DROP works on:
// users, roles and policies are privileges; warehouses, integrations,
// shares and the account are account-wide settings.
func sfObjectRule(ts []token) string {
	var w []string
	for _, t := range ts[1:] {
		if t.depth > 0 || t.word == "" {
			break
		}
		if len(w) == 0 && sfSkip[t.word] {
			continue
		}
		if w = append(w, t.word); len(w) == 3 {
			break
		}
	}
	for len(w) < 3 {
		w = append(w, "")
	}
	switch {
	case w[0] == "USER" || w[0] == "ROLE" || w[1] == "ROLE" && (w[0] == "DATABASE" || w[0] == "APPLICATION"),
		w[1] == "POLICY" && sfPolicies[w[0]], w[2] == "POLICY" && (w[0] == "ROW" || w[0] == "STORAGE"):
		return "sql-privileges"
	case sfServerObjects[w[0]], w[1] == "INTEGRATION" && sfIntegrations[w[0]], w[0] == "EXTERNAL" && w[1] == "ACCESS",
		w[0] == "RESOURCE" && w[1] == "MONITOR", w[0] == "NETWORK" && w[1] == "RULE", w[0] == "MANAGED" && w[1] == "ACCOUNT",
		(w[0] == "REPLICATION" || w[0] == "FAILOVER") && w[1] == "GROUP":
		return "sql-server-config"
	}
	return ""
}

// snowflakeRows reports statements that return rows.
func snowflakeRows(kw string) bool {
	return sfReads[kw] && kw != "SET" && kw != "USE" || kw == "CALL" || kw == "EXECUTE"
}

// snowflakeNoTx: everything but a read runs alone, as nothing can be
// rolled back.
func snowflakeNoTx(ts []token) bool {
	risk, _, err := snowflakeStatement(ts)
	return err != nil || risk != RiskRead
}
