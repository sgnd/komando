package dbx

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	kdriver "github.com/sgnd/komando/internal/driver"
)

// chRows reads ClickHouse's JSONCompactEachRowWithNamesAndTypes as it
// arrives: the names, the types, then one JSON array per row. Closing it
// early ends the request, and ClickHouse stops the query
// (cancel_http_readonly_queries_on_client_close).
type chRows struct {
	body   io.ReadCloser
	dec    *json.Decoder
	names  []string
	types  []string
	rowErr bool // a failure may come as a row of one string
}

func newCHRows(body io.ReadCloser, rowErr bool) (*chRows, error) {
	r := &chRows{body: body, dec: json.NewDecoder(body), rowErr: rowErr}
	r.dec.UseNumber()
	if err := r.dec.Decode(&r.names); err != nil {
		body.Close()
		return nil, r.failed(err)
	}
	if err := r.dec.Decode(&r.types); err != nil || len(r.types) != len(r.names) {
		body.Close()
		return nil, r.failed(err)
	}
	return r, nil
}

func (r *chRows) Columns() []string { return r.names }
func (r *chRows) Close() error      { return r.body.Close() }

// ColumnTypeDatabaseTypeName is ClickHouse's own type name (Nullable(String)).
func (r *chRows) ColumnTypeDatabaseTypeName(i int) string { return r.types[i] }

// chFailure is how a query that fails after its first rows ends: the
// error text in place of the next row, as text or (when komando could not
// ask for text) as a row of one string.
var chFailure = regexp.MustCompile(`^Code: \d+\. DB::Exception: `)

func (r *chRows) Next(dest []driver.Value) error {
	var row []any
	if err := r.dec.Decode(&row); err != nil {
		if err == io.EOF {
			return io.EOF
		}
		return r.failed(err)
	}
	if len(row) == 1 && (len(dest) != 1 || r.rowErr && !r.dec.More()) {
		if s, ok := row[0].(string); ok && chFailure.MatchString(s) {
			return newCHError("", s, "")
		}
	}
	if len(row) != len(dest) {
		return fmt.Errorf("ClickHouse sent a row of %d values for %d columns", len(row), len(dest))
	}
	for i, v := range row {
		dest[i] = chValue(v, r.types[i])
	}
	return nil
}

// failed reads what the server sent in place of JSON: its error text.
func (r *chRows) failed(err error) error {
	if err == nil || err == io.EOF {
		return errors.New("ClickHouse sent no column names and types")
	}
	rest, _ := io.ReadAll(io.LimitReader(io.MultiReader(r.dec.Buffered(), r.body), 64<<10))
	if text := strings.TrimSpace(string(rest)); strings.Contains(text, "Code: ") {
		return newCHError("", text[strings.Index(text, "Code: "):], "")
	}
	return fmt.Errorf("unexpected answer from ClickHouse: %v", err)
}

// chBase strips the wrappers that do not change a value's form:
// Nullable(Int64) and LowCardinality(String) are Int64 and String.
func chBase(typ string) string {
	for {
		inner, ok := strings.CutPrefix(typ, "Nullable(")
		if !ok {
			inner, ok = strings.CutPrefix(typ, "LowCardinality(")
		}
		if !ok {
			return typ
		}
		typ = strings.TrimSuffix(inner, ")")
	}
}

// chValue turns one JSON value into what komando prints. ClickHouse sends
// 64-bit and wider integers as text: they become numbers where JSON holds
// them exactly (int64, or uint64 for UInt64), Decimal stays text with
// every digit, and arrays, maps and tuples keep their shape.
func chValue(v any, typ string) any {
	base := chBase(typ)
	switch x := v.(type) {
	case json.Number:
		switch {
		case strings.HasPrefix(base, "Decimal"):
			return x.String()
		case strings.HasPrefix(base, "Int") || strings.HasPrefix(base, "UInt"):
			return chInt(x.String(), base)
		}
		f, err := x.Float64()
		if err != nil {
			return x.String()
		}
		return f
	case string:
		if strings.HasPrefix(base, "Int") || strings.HasPrefix(base, "UInt") {
			return chInt(x, base)
		}
		return x
	case []any:
		for i := range x {
			x[i] = chValue(x[i], "")
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = chValue(x[k], "")
		}
		return x
	}
	return v // bool, nil
}

// chInt reads an integer: int64 when it fits, uint64 for a bigger UInt64,
// text for wider ones (Int128, UInt256).
func chInt(s, base string) any {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if base == "UInt64" {
		if n, err := strconv.ParseUint(s, 10, 64); err == nil {
			return n
		}
	}
	return s
}

// chColValue is colValue for ClickHouse: the driver already chose the
// form; numbers JSON cannot hold exactly become text.
func chColValue(v any) any {
	switch x := v.(type) {
	case []any, map[string]any:
		return x
	}
	return kdriver.JSONValue(v)
}
