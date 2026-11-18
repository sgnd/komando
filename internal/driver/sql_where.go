package driver

import "strings"

// BigQuery and ClickHouse refuse a DELETE or UPDATE without WHERE, so
// "every row" is written WHERE true, WHERE 1 or WHERE 1=1 there, and it
// works on every other database too. A WHERE that keeps every row limits
// nothing: it is rated like no WHERE (sql-delete-no-where,
// sql-update-no-where). Only conditions made of constants are read; one
// that names a column or calls a function counts as a real WHERE.

// whereEnds are the words that end a WHERE condition at its own level.
var whereEnds = map[string]bool{"RETURNING": true, "ORDER": true, "LIMIT": true, "OFFSET": true, "FETCH": true,
	"SETTINGS": true, "WHEN": true, "OPTION": true, "OUTPUT": true, "THEN": true}

// whereKeepsAll reports whether the condition after the WHERE (or ON) at
// ts[w] is true for every row.
func whereKeepsAll(ts []token, w int) bool {
	d := ts[w].depth
	end := w + 1
	for end < len(ts) {
		t := ts[end]
		if t.depth < d || t.punct == ')' && t.depth == d-1 || t.punct == ';' && t.depth == d || t.depth == d && whereEnds[t.word] {
			break
		}
		end++
	}
	return constTrue(ts[w+1:end]) == 1
}

// constTrue reads a condition made only of constants: 1 always true,
// 0 always false, -1 anything else (a column, a function, text komando
// does not read).
func constTrue(ts []token) int {
	for len(ts) >= 2 && ts[0].punct == '(' && closes(ts) {
		ts = ts[1 : len(ts)-1]
	}
	if len(ts) == 0 {
		return -1
	}
	base := ts[0].depth
	for _, op := range []string{"OR", "AND"} {
		var parts [][]token
		from := 0
		for i, t := range ts {
			if t.depth == base && t.word == op {
				parts = append(parts, ts[from:i])
				from = i + 1
			}
		}
		if len(parts) == 0 {
			continue
		}
		parts = append(parts, ts[from:])
		all, any, unknown := true, false, false
		for _, p := range parts {
			switch constTrue(p) {
			case 1:
				any = true
			case 0:
				all = false
			default:
				all, unknown = false, true
			}
		}
		switch {
		case op == "OR" && any, op == "AND" && all:
			return 1 // x OR true keeps every row whatever x is
		case unknown:
			return -1
		}
		return 0
	}
	if ts[0].word == "NOT" {
		switch constTrue(ts[1:]) {
		case 1:
			return 0
		case 0:
			return 1
		}
		return -1
	}
	if len(ts) == 1 {
		return constValue(ts[0])
	}
	// literal = literal, literal <> literal, literal IS NOT NULL
	if len(ts) == 3 && ts[1].punct == '=' && isLiteral(ts[0]) && isLiteral(ts[2]) {
		if sameLiteral(ts[0], ts[2]) {
			return 1
		}
		return -1 // '1' = 1 depends on the database: not read
	}
	if len(ts) == 4 && isLiteral(ts[0]) && ts[1].word == "IS" && ts[2].word == "NOT" && ts[3].word == "NULL" && ts[0].word != "NULL" {
		return 1
	}
	return -1
}

// closes: the '(' at ts[0] is closed by the ')' at the end of ts.
func closes(ts []token) bool {
	last := ts[len(ts)-1]
	if last.punct != ')' || last.depth != ts[0].depth {
		return false
	}
	for _, t := range ts[1 : len(ts)-1] {
		if t.depth <= ts[0].depth {
			return false
		}
	}
	return true
}

func isNumber(t token) bool {
	return t.word != "" && t.word[0] >= '0' && t.word[0] <= '9' && strings.Trim(t.word, "0123456789") == ""
}

func isLiteral(t token) bool {
	return isNumber(t) || t.punct == '\'' && !t.esc || t.word == "TRUE" || t.word == "FALSE"
}

func sameLiteral(a, b token) bool {
	if a.punct == '\'' || b.punct == '\'' {
		return a.punct == b.punct && a.str == b.str
	}
	return a.word == b.word
}

// constValue: TRUE and a number other than zero are true, FALSE and zero
// false.
func constValue(t token) int {
	switch {
	case t.word == "TRUE":
		return 1
	case t.word == "FALSE":
		return 0
	case isNumber(t):
		if strings.Trim(t.word, "0") == "" {
			return 0
		}
		return 1
	}
	return -1
}

// mergeOnKeepsAll: a MERGE whose ON condition is true for every pair
// matches every row of the target, so its WHEN MATCHED THEN UPDATE or
// DELETE touches them all.
func mergeOnKeepsAll(ts []token) bool {
	for i, t := range ts {
		if t.depth == 0 && t.word == "ON" {
			return whereKeepsAll(ts, i)
		}
	}
	return false
}
