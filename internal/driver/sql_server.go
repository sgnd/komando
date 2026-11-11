package driver

import "strings"

// serverRules are the rules a statement hits by reaching past the
// database into the server's machine: running a program or native code
// (sql-program), or reading or writing its files (sql-server-file).
func serverRules(first, second string, ts []token) []string {
	var rules []string
	switch first {
	case "CREATE":
		if loadsNativeCode(ts) {
			rules = append(rules, "sql-program")
		}
	case "INSTALL": // MySQL INSTALL PLUGIN, COMPONENT, SONAME: a shared library
		rules = append(rules, "sql-program")
	case "LOAD":
		switch second {
		case "DATA", "XML": // MySQL LOAD DATA INFILE: a file on the server unless LOCAL
			if hasWord(ts, "INFILE") && !hasWord(ts, "LOCAL") {
				rules = append(rules, "sql-server-file")
			}
		case "INDEX":
		default: // PostgreSQL LOAD 'lib.so'
			rules = append(rules, "sql-program")
		}
	case "COPY":
		if hasWord(ts, "PROGRAM") {
			rules = append(rules, "sql-program")
		}
		for i, t := range ts { // COPY t TO '/file' or FROM '/file' (not STDIN/STDOUT)
			if (t.word == "TO" || t.word == "FROM") && t.depth == 0 && i+1 < len(ts) && ts[i+1].punct == '\'' {
				rules = append(rules, "sql-server-file")
				break
			}
		}
	}
	return rules
}

// untrustedLangs are function languages that reach the operating system:
// C and internal load native code, and the untrusted (...U) Perl, Python
// and Tcl run as the database server's user.
var untrustedLangs = map[string]bool{"C": true, "INTERNAL": true, "PLPYTHONU": true, "PLPYTHON2U": true,
	"PLPYTHON3U": true, "PLPERLU": true, "PLTCLU": true}

// createModifiers come between CREATE and the kind of object it makes.
var createModifiers = map[string]bool{"OR": true, "REPLACE": true, "TRUSTED": true, "PROCEDURAL": true,
	"EDITIONABLE": true, "NONEDITIONABLE": true, "AND": true, "COMPILE": true, "RESOLVE": true, "NOFORCE": true}

// loadsNativeCode reports a CREATE that brings code into the server which
// a read-only transaction does not hold back once called: an extension, a
// procedural language, an Oracle library or Java class, a SQL Server
// assembly (.NET code), or a function in an untrusted language or from a
// shared library (MySQL SONAME).
func loadsNativeCode(ts []token) bool {
	kind := ""
	for _, t := range ts[1:] {
		if !createModifiers[t.word] {
			kind = t.word
			break
		}
	}
	switch kind {
	case "EXTENSION", "LANGUAGE", "LIBRARY", "ASSEMBLY", "JAVA":
		return true
	}
	for i, t := range ts {
		if t.depth > 0 {
			continue
		}
		if t.word == "SONAME" {
			return true
		}
		if t.word == "LANGUAGE" && i+1 < len(ts) {
			n := ts[i+1]
			lang := n.word
			if n.ident != "" {
				lang = n.ident
			} else if n.punct == '\'' {
				lang = strings.ToUpper(n.str)
			}
			if untrustedLangs[lang] {
				return true
			}
		}
	}
	return false
}
