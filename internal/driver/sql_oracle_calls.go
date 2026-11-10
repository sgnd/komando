package driver

import "strings"

// Oracle runs a stored function called from a query with the caller's
// rights to do anything: one with PRAGMA AUTONOMOUS_TRANSACTION changes
// rows and commits on its own, even inside komando's read-only
// transaction, and a dry run's rollback does not undo it. So a call to a
// function that is not one of Oracle's own is code komando cannot see
// into (sql-opaque), and a name across a database link (f@link, t@link)
// reaches another server (sql-remote).
//
// A function without arguments can also be called without (), which
// looks like a column; komando cannot tell those apart.

// oracleBuiltins are Oracle's own SQL functions, which only compute.
var oracleBuiltins = wordSet(`
ABS ACOS ADD_MONTHS ANY_VALUE APPROX_COUNT APPROX_COUNT_DISTINCT APPROX_COUNT_DISTINCT_AGG
APPROX_COUNT_DISTINCT_DETAIL APPROX_MEDIAN APPROX_PERCENTILE APPROX_PERCENTILE_AGG
APPROX_PERCENTILE_DETAIL APPROX_RANK APPROX_SUM ASCII ASCIISTR ASIN ATAN ATAN2 AVG
BIN_TO_NUM BITAND BIT_AND_AGG BIT_OR_AGG BIT_XOR_AGG BOOLEAN_AND_AGG BOOLEAN_OR_AGG
CARDINALITY CAST CEIL CHARTOROWID CHECKSUM CHR COALESCE COLLATION COLLECT COMPOSE
CON_DBID_TO_ID CON_GUID_TO_ID CON_NAME_TO_ID CON_UID_TO_ID CONCAT CONVERT CORR CORR_K
CORR_S COS COSH COUNT COVAR_POP COVAR_SAMP CUME_DIST CURRENT_DATE CURRENT_TIMESTAMP CV
DBTIMEZONE DECODE DECOMPOSE DENSE_RANK DEPTH DEREF DUMP EMPTY_BLOB EMPTY_CLOB EXISTSNODE
EXP EXTRACT EXTRACTVALUE FIRST FIRST_VALUE FLOOR FROM_TZ GREATEST GROUP_ID GROUPING
GROUPING_ID HEXTORAW INITCAP INSTR INSTR2 INSTR4 INSTRB INSTRC ITERATION_NUMBER
JSON_ARRAY JSON_ARRAYAGG JSON_EQUAL JSON_EXISTS JSON_MERGEPATCH JSON_OBJECT
JSON_OBJECTAGG JSON_QUERY JSON_SCALAR JSON_SERIALIZE JSON_TABLE JSON_TEXTCONTAINS
JSON_TRANSFORM JSON_VALUE KURTOSIS_POP KURTOSIS_SAMP LAG LAST LAST_DAY LAST_VALUE LEAD
LEAST LENGTH LENGTH2 LENGTH4 LENGTHB LENGTHC LISTAGG LN LNNVL LOCALTIMESTAMP LOG LOWER
LPAD LTRIM MAKE_REF MAX MEDIAN MIN MOD MONTHS_BETWEEN NANVL NCHR NEW_TIME NEXT_DAY
NLS_CHARSET_DECL_LEN NLS_CHARSET_ID NLS_CHARSET_NAME NLS_COLLATION_ID NLS_COLLATION_NAME
NLS_INITCAP NLS_LOWER NLS_UPPER NLSSORT NTH_VALUE NTILE NULLIF NUMTODSINTERVAL
NUMTOYMINTERVAL NVL NVL2 ORA_DST_AFFECTED ORA_DST_CONVERT ORA_DST_ERROR ORA_HASH
PERCENT_RANK PERCENTILE_CONT PERCENTILE_DISC POWER POWERMULTISET POWERMULTISET_BY_CARDINALITY
PRESENTNNV PRESENTV PREVIOUS RANK RATIO_TO_REPORT RAWTOHEX RAWTONHEX REF REFTOHEX
REGEXP_COUNT REGEXP_INSTR REGEXP_LIKE REGEXP_REPLACE REGEXP_SUBSTR REGR_AVGX REGR_AVGY
REGR_COUNT REGR_INTERCEPT REGR_R2 REGR_SLOPE REGR_SXX REGR_SXY REGR_SYY REMAINDER REPLACE
ROUND ROUND_TIES_TO_EVEN ROW_NUMBER ROWIDTOCHAR ROWIDTONCHAR RPAD RTRIM SCN_TO_TIMESTAMP
SESSIONTIMEZONE SIGN SIN SINH SKEWNESS_POP SKEWNESS_SAMP SOUNDEX SQRT STANDARD_HASH
STDDEV STDDEV_POP STDDEV_SAMP SUBSTR SUBSTR2 SUBSTR4 SUBSTRB SUBSTRC SUM
SYS_CONNECT_BY_PATH SYS_CONTEXT SYS_EXTRACT_UTC SYS_GUID SYS_TYPEID SYS_XMLAGG SYS_XMLGEN
SYSDATE SYSTIMESTAMP TAN TANH TIMESTAMP_TO_SCN TO_APPROX_COUNT_DISTINCT TO_APPROX_PERCENTILE
TO_BINARY_DOUBLE TO_BINARY_FLOAT TO_BLOB TO_BOOLEAN TO_CHAR TO_CLOB TO_DATE TO_DSINTERVAL
TO_LOB TO_MULTI_BYTE TO_NCHAR TO_NCLOB TO_NUMBER TO_SINGLE_BYTE TO_TIMESTAMP
TO_TIMESTAMP_TZ TO_UTC_TIMESTAMP_TZ TO_YMINTERVAL TRANSLATE TREAT TRIM TRUNC TZ_OFFSET
UID UNISTR UPPER USER USERENV VALIDATE_CONVERSION VALUE VAR_POP VAR_SAMP VARIANCE VSIZE
WIDTH_BUCKET XMLAGG XMLCAST XMLCDATA XMLCOLATTVAL XMLCOMMENT XMLCONCAT XMLDIFF XMLELEMENT
XMLEXISTS XMLFOREST XMLISVALID XMLPARSE XMLPATCH XMLPI XMLQUERY XMLROOT XMLSEQUENCE
XMLSERIALIZE XMLTABLE XMLTRANSFORM XMLTYPE`)

// oracleParenWords are keywords and type names that a ( follows in
// Oracle SQL without being a function call.
var oracleParenWords = wordSet(`
ALL AND ANY APPLY AS BETWEEN BY CASE COLUMNS CROSS CUBE CURSOR CYCLE DEFAULT DEFINE
DELETE DIMENSION DISTINCT ELSE EXCEPT EXISTS FETCH FILTER FOR FROM GROUP HAVING IN
INCLUDE INSERT INTERSECT INTO IS JOIN KEEP LATERAL LIKE MATCH_RECOGNIZE MEASURES MINUS
MULTISET NOT OF OFFSET ON OR ORDER OVER PARTITION PATTERN PIVOT PRIOR RANGE RETURN
RETURNING ROLLUP ROWS RULES SAMPLE SEED SELECT SET SETS SOME SUBPARTITION SUBSET TABLE
THE THEN TO TRUNCATE UNION UNIQUE UNPIVOT UPDATE USING VALUES WHEN WHERE WITH WITHIN
DAY MONTH YEAR HOUR MINUTE SECOND
BINARY_DOUBLE BINARY_FLOAT BLOB BOOLEAN CHAR CHARACTER CLOB DATE DEC DECIMAL DOUBLE FLOAT
INT INTEGER INTERVAL JSON LONG NCHAR NCLOB NUMBER NUMERIC NVARCHAR2 PRECISION RAW REAL
ROWID SMALLINT TIMESTAMP UROWID VARCHAR VARCHAR2 VARYING VECTOR`)

func wordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// oracleOwnRule reports names the rest of oracleStatement already rates:
// DBMS_ and UTL_ packages, and the ones that reach out or read files.
func oracleOwnRule(name string) bool {
	return strings.HasPrefix(name, "DBMS_") || strings.HasPrefix(name, "UTL_") || remotePackages[name] ||
		name == "BFILENAME"
}

// oracleCalls returns the rules for what statement ts calls: sql-remote
// for a database link, and with funcs sql-opaque for a stored function.
// (DDL leaves funcs out: it needs --write and never runs in a dry run.)
func oracleCalls(ts []token, funcs bool) []string {
	var rules []string
	add := func(id string) {
		for _, r := range rules {
			if r == id {
				return
			}
		}
		rules = append(rules, id)
	}
	name := func(t token) string {
		if t.ident != "" {
			return t.ident
		}
		return t.word
	}
	for i, t := range ts {
		if t.punct == '@' {
			add("sql-remote")
			continue
		}
		if !funcs || t.word == "" || i+1 >= len(ts) || ts[i+1].punct != '(' || i > 0 && ts[i-1].punct == ':' {
			continue
		}
		// the name may be qualified: schema.package.function
		parts := []string{name(t)}
		j := i
		for j >= 2 && ts[j-1].punct == '.' && ts[j-2].word != "" {
			parts = append(parts, name(ts[j-2]))
			j -= 2
		}
		if j > 0 && ts[j-1].word == "INTO" { // INSERT INTO t (a, b)
			continue
		}
		if len(parts) == 1 && t.ident == "" && (oracleBuiltins[parts[0]] || oracleParenWords[parts[0]]) {
			continue
		}
		if len(parts) == 1 && columnList(ts, i+1) { // WITH x (a, b) AS (...)
			continue
		}
		own := false
		for _, p := range parts {
			own = own || oracleOwnRule(p)
		}
		if !own {
			add("sql-opaque")
		}
	}
	return rules
}

// columnList reports a ( at ts[open] whose ) AS follows: a list of
// column names, not arguments.
func columnList(ts []token, open int) bool {
	d := ts[open].depth
	for k := open + 1; k < len(ts); k++ {
		if ts[k].punct == ')' && ts[k].depth == d {
			return k+1 < len(ts) && ts[k+1].word == "AS"
		}
	}
	return false
}

// oracleExternal returns the rules for an inline external table (SELECT
// ... FROM EXTERNAL (...), or EXTERNAL MODIFY): it reads files on the
// database server, and with a PREPROCESSOR runs a program there. The
// access parameters can also come from a query (USING CLOB), which
// komando cannot read.
func oracleExternal(ts []token) []string {
	external := false
	for i, t := range ts {
		next := token{}
		if i+1 < len(ts) {
			next = ts[i+1]
		}
		switch {
		case t.word == "EXTERNAL" && (next.punct == '(' || next.word == "MODIFY"),
			t.word == "ORACLE_LOADER", t.word == "ORACLE_DATAPUMP", t.word == "ORACLE_HDFS",
			t.word == "ORACLE_HIVE", t.word == "ORACLE_BIGDATA":
			external = true
		}
	}
	if !external {
		return nil
	}
	for i, t := range ts {
		if t.word == "PREPROCESSOR" || t.word == "PARAMETERS" && i+1 < len(ts) && ts[i+1].word == "USING" {
			return []string{"sql-server-file", "sql-program"}
		}
	}
	return []string{"sql-server-file"}
}
