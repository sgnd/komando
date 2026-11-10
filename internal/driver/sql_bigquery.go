package driver

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
)

// GoogleSQL, BigQuery's dialect, read the way BigQuery reads it: '...'
// and "..." are both text, with backslash escapes; '''...''' and """..."""
// may span lines; r'...' is raw text (no escapes) and b'...' bytes;
// `...` quotes names (project-id.dataset.table), also with backslash
// escapes; # and -- comment to the end of the line, /* */ does not nest.
// bigqueryMask turns this into text the shared lexer reads the same way,
// and refuses what komando cannot be sure of.
//
// Each statement is a job of its own: there is no transaction across
// statements. Before it runs, every statement goes to BigQuery as a dry
// run, which says what kind of statement BigQuery sees (statementType);
// without --write anything but SELECT is refused there, too. The rating
// here comes first and decides what needs --write or --allow-dangerous.

func init() {
	dialects["bigquery"] = dialect{bigquery: true}
}

// bqFirst are the words a BigQuery statement komando knows starts with.
var bqFirst = wordSet(`SELECT WITH FROM INSERT UPDATE DELETE MERGE TRUNCATE CREATE ALTER DROP UNDROP GRANT REVOKE
	EXPORT LOAD CALL EXECUTE BEGIN START COMMIT ROLLBACK DECLARE SET ASSERT`)

// bqReads only read: queries, also in pipe syntax (FROM t |> WHERE ...).
var bqReads = wordSet(`SELECT WITH FROM`)

// bqScript are procedural statements: they only mean something inside a
// script, and komando sends each statement as a job of its own.
var bqScript = wordSet(`DECLARE SET IF LOOP WHILE REPEAT FOR CASE BREAK LEAVE CONTINUE ITERATE RAISE RETURN EXCEPTION`)

// bigqueryMask returns sql as the shared lexer should see it, with the
// same length: comments become spaces, text in any quotes becomes '...'
// with its content hidden, and `names` become "names" (hidden when they
// hold a backslash or a "). It refuses letters outside ASCII outside
// quotes, line comments with unusual line breaks, a /* inside a comment,
// and a raw string with a backslash before a quote.
func bigqueryMask(sql string) (string, error) {
	b := []byte(sql)
	n := len(b)
	at := func(i int) byte {
		if i < n {
			return b[i]
		}
		return 0
	}
	blank := func(from, to int) {
		for k := from; k < to; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	for i := 0; i < n; {
		c := b[i]
		switch {
		case c == '#', c == '-' && at(i+1) == '-':
			j := i
			for ; j < n && b[j] != '\n'; j++ {
				r, size := utf8.DecodeRune(b[j:])
				switch {
				case b[j] == '\r' && at(j+1) == '\n':
				case b[j] < ' ' && b[j] != '\t' || b[j] == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == utf8.RuneError:
					return "", hiddenCode("end # and -- comments with a plain line break, or use /* ... */: komando cannot tell where BigQuery ends this one",
						"a line comment holds a control character or an unusual line break")
				}
				j += size - 1
			}
			blank(i, j)
			i = j
		case c == '/' && at(i+1) == '*':
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return "", out.Usage("unterminated /* comment in SQL")
			}
			if strings.Contains(sql[i+2:i+2+end], "/*") {
				return "", hiddenCode("take the /* out of the comment: komando reads comments as BigQuery does, without nesting, and will not guess",
					"a /* comment holds another /*")
			}
			blank(i, i+2+end+2)
			i += 2 + end + 2
		case c == '\'' || c == '"':
			j, err := bqStringEnd(b, i)
			if err != nil {
				return "", err
			}
			b[i], b[j-1] = '\'', '\''
			for k := i + 1; k < j-1; k++ {
				b[k] = 'x'
			}
			i = j
		case c == '`':
			j := i + 1
			plain := true
			for ; j < n && b[j] != '`'; j++ {
				if b[j] == '\\' || b[j] == '"' || b[j] < ' ' {
					plain = false
				}
				if b[j] == '\\' {
					j++
				}
			}
			if j >= n {
				return "", out.Usage("unterminated ` quote in SQL")
			}
			b[i], b[j] = '"', '"'
			if !plain {
				for k := i + 1; k < j; k++ {
					b[k] = 'X'
				}
			}
			i = j + 1
		case c >= 0x80:
			return "", hiddenCode("put names with letters outside ASCII in `backticks` and text in 'quotes': komando cannot tell how BigQuery reads other characters",
				"BigQuery SQL has a character outside ASCII that is not quoted")
		default:
			i++
		}
	}
	return string(b), nil
}

// bqStringEnd returns the position after the text literal that starts
// at b[i] (a ' or "), single or triple quoted. The letters before it say
// whether it is raw (r'...'): there a backslash escapes nothing, and
// komando refuses one before a quote rather than guess where it ends.
func bqStringEnd(b []byte, i int) (int, error) {
	q := b[i]
	k := i
	for k > 0 && isWord(b[k-1]) {
		k--
	}
	p := strings.ToLower(string(b[k:i]))
	raw := p == "r" || p == "rb" || p == "br"
	quote := []byte{q}
	if i+2 < len(b) && b[i+1] == q && b[i+2] == q {
		quote = []byte{q, q, q}
	}
	for j := i + len(quote); j < len(b); j++ {
		if b[j] == '\\' {
			if raw && j+1 < len(b) && b[j+1] == q {
				return 0, hiddenCode("write the raw string without a backslash before a quote, or as a plain string: komando cannot tell where BigQuery ends it",
					"a raw string has a backslash before a quote")
			}
			if !raw {
				j++
			}
			continue
		}
		if b[j] == q && j+len(quote) <= len(b) && string(b[j:j+len(quote)]) == string(quote) {
			return j + len(quote), nil
		}
	}
	return 0, out.Usage("unterminated %s quote in SQL", quote)
}

// bigqueryStatement rates one BigQuery statement: the general rules, then
// BigQuery's own objects, exports and functions that reach elsewhere.
func bigqueryStatement(ts []token) (Risk, []string, error) {
	word := func(i int) string {
		if i >= 0 && i < len(ts) {
			return ts[i].word
		}
		return ""
	}
	first, second := firstWord(ts), word(1)
	if bqScript[first] || first == "BEGIN" && second != "" && second != "TRANSACTION" {
		return 0, nil, out.Errf(out.ExitUsage, "USAGE",
			"komando sends each statement as a job of its own, so a script's variables and blocks do not carry over: write it as plain statements, or as EXECUTE IMMEDIATE '...' (it needs --write and --allow-dangerous)",
			"%s is part of a BigQuery script, not a statement komando runs on its own", first)
	}
	risk, rules, err := classifyStatement(ts, true)
	if err != nil {
		return 0, nil, err
	}
	if first == "FROM" && len(rules) == 0 && !hasWord(ts, "INSERT") && !hasWord(ts, "UPDATE") && !hasWord(ts, "DELETE") && !hasWord(ts, "MERGE") {
		risk = RiskRead // pipe syntax: FROM t |> WHERE ... is a query
	}
	// WHEN MATCHED THEN UPDATE (or DELETE) touches the matched rows only;
	// WHEN NOT MATCHED BY SOURCE touches every row the source lacks, which
	// is all of them for an empty source or ON FALSE
	if first == "MERGE" && !slices.ContainsFunc(ts[1:], func(t token) bool { return t.word == "SOURCE" }) {
		rules = slices.DeleteFunc(rules, func(id string) bool { return id == "sql-update-no-where" || id == "sql-delete-no-where" })
		if len(rules) == 0 {
			risk = RiskWrite
		}
	}
	if !bqReads[first] {
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
		if id := bqObjectRule(ts); id != "" {
			flag(id)
		}
	case "EXPORT": // EXPORT DATA (to Cloud Storage, Bigtable, Pub/Sub, Spanner), EXPORT MODEL
		flag("sql-remote")
	case "LOAD":
		if hasWord(ts, "OVERWRITE") {
			flag("sql-truncate") // the table's rows are replaced
		}
	case "CALL":
		if second == "BQ" && word(3) == "ABORT_SESSION" {
			flag("sql-kill")
		}
	}
	for i, t := range ts {
		name := t.word
		if t.ident != "" {
			name = t.ident
		}
		switch {
		case name == "EXTERNAL_QUERY" && word(i+1) == "" && i+1 < len(ts) && ts[i+1].punct == '(':
			flag("sql-remote") // runs SQL on a Cloud SQL or Spanner database
		case t.word == "REMOTE" && word(i+1) == "WITH" && word(i+2) == "CONNECTION":
			flag("sql-remote") // a remote function or model calls another service
		}
	}
	return risk, rules, nil
}

// bqObjectRule rates the kind of object a CREATE, ALTER or DROP works on:
// row access policies are privileges; capacity commitments, reservations,
// assignments and the project's or organization's options are settings
// (and money) for everyone.
func bqObjectRule(ts []token) string {
	var w []string
	for _, t := range ts[1:] {
		if t.depth > 0 || t.word == "" {
			break
		}
		if len(w) == 0 && (t.word == "OR" || t.word == "REPLACE" || t.word == "TEMP" || t.word == "TEMPORARY") {
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
	case w[0] == "ROW" && w[1] == "ACCESS", w[0] == "ALL" && w[1] == "ROW":
		return "sql-privileges"
	case w[0] == "CAPACITY", w[0] == "RESERVATION", w[0] == "ASSIGNMENT", w[0] == "PROJECT", w[0] == "ORGANIZATION", w[0] == "BI_CAPACITY":
		return "sql-server-config"
	}
	return ""
}

// bigqueryRows reports statements that return rows.
func bigqueryRows(kw string) bool { return bqReads[kw] || kw == "CALL" || kw == "EXECUTE" }

// bigqueryNoTx: everything but a read runs alone, as nothing can be
// rolled back.
func bigqueryNoTx(ts []token) bool {
	risk, _, err := bigqueryStatement(ts)
	return err != nil || risk != RiskRead
}
