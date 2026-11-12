package dbx

import (
	"context"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	kdriver "github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// sfColumn is one column of a result (resultSetMetaData.rowType).
type sfColumn struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Precision int64  `json:"precision"`
	Scale     int64  `json:"scale"`
}

// sfRows reads a result partition by partition: the first came with the
// statement, the others are fetched when the reader gets to them.
type sfRows struct {
	ctx    context.Context
	c      *sfConnector
	cols   []sfColumn
	data   [][]any
	i      int
	part   int
	parts  int
	handle string
}

func newSFRows(ctx context.Context, c *sfConnector, res *sfResult) *sfRows {
	r := &sfRows{ctx: ctx, c: c, data: res.Data, parts: 1, handle: res.StatementHandle}
	if res.Meta != nil {
		r.cols = res.Meta.RowType
		r.parts = max(1, len(res.Meta.PartitionInfo))
	}
	return r
}

func (r *sfRows) Columns() []string {
	names := make([]string, len(r.cols))
	for i, c := range r.cols {
		names[i] = c.Name
	}
	return names
}

func (r *sfRows) Close() error { return nil }

// ColumnTypeDatabaseTypeName is the column's Snowflake type: NUMBER(38,0),
// VARCHAR, TIMESTAMP_NTZ, VARIANT, ...
func (r *sfRows) ColumnTypeDatabaseTypeName(i int) string {
	c := r.cols[i]
	switch t := strings.ToLower(c.Type); t {
	case "fixed":
		return fmt.Sprintf("NUMBER(%d,%d)", c.Precision, c.Scale)
	case "real":
		return "FLOAT"
	case "text":
		return "VARCHAR"
	default:
		return strings.ToUpper(t)
	}
}

func (r *sfRows) Next(dest []driver.Value) error {
	for r.i >= len(r.data) {
		if r.part+1 >= r.parts {
			return io.EOF
		}
		r.part++
		status, res, err := r.c.do(r.ctx, http.MethodGet,
			"/api/v2/statements/"+url.PathEscape(r.handle)+"?partition="+strconv.Itoa(r.part), nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return sfFailure(status, res)
		}
		r.data, r.i = res.Data, 0
	}
	row := r.data[r.i]
	r.i++
	if len(row) != len(dest) {
		return fmt.Errorf("unexpected answer from Snowflake: a row of %d values for %d columns", len(row), len(dest))
	}
	for i, v := range row {
		dest[i] = sfValue(v, r.cols[i])
	}
	return nil
}

// sfValue turns one value of the SQL API's JSON (text, or null) into
// what komando prints. NUMBER without a scale becomes a number where
// JSON holds it exactly, with a scale it stays text with every digit;
// dates and times (sent as seconds since 1970) become text in the
// column's own form; VARIANT, OBJECT and ARRAY keep their shape.
func sfValue(v any, col sfColumn) driver.Value {
	s, ok := v.(string)
	if !ok {
		return v
	}
	switch strings.ToLower(col.Type) {
	case "fixed":
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && col.Scale == 0 {
			return n
		}
	case "real":
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	case "boolean":
		if b, err := strconv.ParseBool(s); err == nil {
			return b
		}
	case "date":
		if d, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.Unix(d*86400, 0).UTC().Format("2006-01-02")
		}
	case "time":
		if t, ok := sfEpoch(s); ok {
			return t.UTC().Format("15:04:05.999999999")
		}
	case "timestamp_ntz":
		if t, ok := sfEpoch(s); ok {
			return t.UTC().Format("2006-01-02 15:04:05.999999999")
		}
	case "timestamp_ltz":
		if t, ok := sfEpoch(s); ok {
			return t.UTC().Format(time.RFC3339Nano)
		}
	case "timestamp_tz":
		secs, off, _ := strings.Cut(s, " ")
		t, ok := sfEpoch(secs)
		if m, err := strconv.Atoi(off); ok && err == nil {
			return t.In(time.FixedZone("", (m-1440)*60)).Format(time.RFC3339Nano) // the offset comes as minutes + 1440
		}
	case "binary":
		if b, err := hex.DecodeString(s); err == nil {
			return map[string]string{"base64": base64.StdEncoding.EncodeToString(b)}
		}
	case "variant", "object", "array", "map", "vector":
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		var x any
		if dec.Decode(&x) == nil {
			return sfNumbers(x)
		}
	}
	return s
}

// sfEpoch reads seconds since 1970 with up to nine decimals
// ("1616173619.123000000"); a plain number this big is nanoseconds.
func sfEpoch(s string) (time.Time, bool) {
	whole, frac, _ := strings.Cut(s, ".")
	sec, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || len(frac) > 9 || strings.Trim(frac, "0123456789") != "" {
		return time.Time{}, false
	}
	if frac == "" && (sec >= 1e14 || sec <= -1e14) {
		return time.Unix(0, sec), true
	}
	ns, _ := strconv.ParseInt((frac + "000000000")[:9], 10, 64)
	if strings.HasPrefix(whole, "-") {
		ns = -ns
	}
	return time.Unix(sec, ns), true
}

// sfNumbers turns json.Number inside a VARIANT into int64 or float64 (text
// when neither holds it exactly).
func sfNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		if f, err := x.Float64(); err == nil && !math.IsInf(f, 0) && strconv.FormatFloat(f, 'g', -1, 64) == x.String() {
			return f
		}
		return x.String()
	case []any:
		for i := range x {
			x[i] = sfNumbers(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = sfNumbers(x[k])
		}
	}
	return v
}

// sfColValue is colValue for Snowflake: the driver already chose the form.
func sfColValue(v any) any {
	switch x := v.(type) {
	case []any, map[string]any, map[string]string:
		return x
	}
	return kdriver.JSONValue(v)
}

// sfError is a statement Snowflake refused or could not run.
type sfError struct {
	Status int
	Code   string
	Msg    string
}

func (e *sfError) Error() string {
	if e.Code == "" {
		return e.Msg
	}
	return fmt.Sprintf("%s (Snowflake error %s)", e.Msg, e.Code)
}

func sfFailure(status int, res *sfResult) error {
	if res == nil {
		res = &sfResult{}
	}
	msg := strings.Join(strings.Fields(res.Message), " ")
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d %s", status, http.StatusText(status))
	}
	return &sfError{Status: status, Code: res.Code, Msg: strings.TrimSuffix(msg, ".")}
}

// snowflakeErr maps a failed statement to an error code. Snowflake's
// codes here come from its documentation and messages; none was checked
// against a live account (docs/design/snowflake.md).
func snowflakeErr(err error) error {
	var e *sfError
	if !errors.As(err, &e) {
		return out.Errf(out.ExitRemote, "DB_ERROR", "run `komando conn test NAME` to check the account and the login", "%v", err)
	}
	low := strings.ToLower(e.Msg)
	switch {
	case e.Code == "000606" || strings.Contains(low, "no active warehouse"):
		return out.Errf(out.ExitRemote, "DB_ERROR", "this needs a warehouse: add ?warehouse=NAME to the conn URL (`komando conn edit CONN --url ...`); SHOW WAREHOUSES lists them", "%s", e)
	case strings.Contains(low, "does not have a current database"):
		return out.Errf(out.ExitRemote, "DB_ERROR", "add the database to the conn URL: snowflake://USER@ACCOUNT/DATABASE/SCHEMA", "%s", e)
	case e.Code == "003001" || strings.Contains(low, "insufficient privileges"):
		return out.Errf(out.ExitRemote, "DB_PRIVILEGE", "the conn's role lacks this right; `komando db user show CONN ROLE` shows what it has, ?role= in the URL picks another", "%s", e)
	case e.Code == "000630" || strings.Contains(low, "statement reached its statement or warehouse timeout"):
		return out.Errf(out.ExitTimeout, "TIMEOUT", "narrow the query (WHERE, LIMIT) or raise --timeout", "%s", e)
	case e.Code == "000604":
		return out.Errf(out.ExitRemote, "DB_ERROR", "someone stopped this query (`komando db kill`, or SYSTEM$CANCEL_QUERY); run it again if it is still needed", "%s", e)
	case strings.Contains(low, "statement count"):
		return out.Errf(out.ExitUsage, "USAGE", "Snowflake read more than one statement where komando saw one, so nothing ran: send each statement on its own", "%s", e)
	case e.Status == http.StatusTooManyRequests:
		return out.Errf(out.ExitRemote, "DB_ERROR", "Snowflake is limiting requests from this account; wait a little and run it again", "%s", e)
	case e.Code == "002003" || strings.Contains(low, "does not exist or not authorized"):
		return out.Errf(out.ExitRemote, "DB_ERROR", "check the name (`komando db schema CONN`), and that the conn's role may see it (?role= in the URL); names without \"quotes\" are upper case", "%s", e)
	}
	return out.Errf(out.ExitRemote, "DB_ERROR", "fix the SQL; `komando db schema CONN TABLE` shows columns and types", "%s", e)
}

// sfConnectErr is snowflakeErr for the first statement of a connection:
// what the URL names may not exist.
func sfConnectErr(err error) error {
	var e *sfError
	if errors.As(err, &e) && strings.Contains(strings.ToLower(e.Msg), "does not exist") {
		return out.Errf(out.ExitNotFound, "DB_NOT_FOUND", "check the database, schema, warehouse and role in the conn URL (`komando conn show NAME`); names without \"quotes\" are upper case", "%s", e)
	}
	if e != nil {
		return snowflakeErr(e)
	}
	return err
}
