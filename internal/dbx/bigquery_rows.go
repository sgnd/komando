package dbx

import (
	"bytes"
	"context"
	"database/sql/driver"
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

	"github.com/sgnd/komando/internal/out"
)

// The BigQuery API's JSON, as much of it as komando reads.

type bqJobRef struct {
	ProjectID string `json:"projectId"`
	JobID     string `json:"jobId,omitempty"`
	Location  string `json:"location,omitempty"`
}

type bqField struct {
	Name   string    `json:"name"`
	Type   string    `json:"type"`
	Mode   string    `json:"mode,omitempty"`
	Fields []bqField `json:"fields,omitempty"`
}

type bqSchema struct {
	Fields []bqField `json:"fields"`
}

// bqJob is a job (jobs.insert's answer): a dry run's statistics, or a
// started job's state.
type bqJob struct {
	JobReference bqJobRef `json:"jobReference"`
	Status       struct {
		State       string      `json:"state"`
		ErrorResult *bqErrProto `json:"errorResult"`
	} `json:"status"`
	Statistics struct {
		TotalBytesProcessed string `json:"totalBytesProcessed"`
		Query               struct {
			StatementType               string    `json:"statementType"`
			TotalBytesProcessed         string    `json:"totalBytesProcessed"`
			TotalBytesProcessedAccuracy string    `json:"totalBytesProcessedAccuracy"`
			Schema                      *bqSchema `json:"schema"`
			ReferencedTables            []struct {
				ProjectID string `json:"projectId"`
				DatasetID string `json:"datasetId"`
				TableID   string `json:"tableId"`
			} `json:"referencedTables"`
		} `json:"query"`
	} `json:"statistics"`
}

// bytes is what the dry run says the query would read.
func (j *bqJob) bytes() int64 {
	s := j.Statistics.Query.TotalBytesProcessed
	if s == "" {
		s = j.Statistics.TotalBytesProcessed
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// bqResults is a page of a finished job's results (jobs.getQueryResults).
type bqResults struct {
	JobReference        bqJobRef  `json:"jobReference"`
	JobComplete         bool      `json:"jobComplete"`
	Schema              *bqSchema `json:"schema"`
	Rows                []bqRow   `json:"rows"`
	PageToken           string    `json:"pageToken"`
	TotalBytesProcessed string    `json:"totalBytesProcessed"`
	NumDmlAffectedRows  string    `json:"numDmlAffectedRows"`
}

// bqRow is {"f": [{"v": ...}, ...]}; a STRUCT value has the same shape,
// an ARRAY is [{"v": ...}, ...].
type bqRow struct {
	F []struct {
		V any `json:"v"`
	} `json:"f"`
}

// bqRows reads a result page by page: the first came with the job, the
// others are fetched when the reader gets to them.
type bqRows struct {
	ctx  context.Context
	c    *bqConnector
	res  *bqResults
	page []bqRow
	i    int
}

func (r *bqRows) fields() []bqField {
	if r.res.Schema == nil {
		return nil
	}
	return r.res.Schema.Fields
}

func (r *bqRows) Columns() []string {
	names := make([]string, len(r.fields()))
	for i, f := range r.fields() {
		names[i] = f.Name
	}
	return names
}

func (r *bqRows) Close() error { return nil }

// ColumnTypeDatabaseTypeName is the column's type: INT64, STRING,
// TIMESTAMP, STRUCT, ARRAY<STRING>, ...
func (r *bqRows) ColumnTypeDatabaseTypeName(i int) string { return bqTypeName(r.fields()[i]) }

func bqTypeName(f bqField) string {
	t := map[string]string{"INTEGER": "INT64", "FLOAT": "FLOAT64", "BOOLEAN": "BOOL", "RECORD": "STRUCT"}[f.Type]
	if t == "" {
		t = f.Type
	}
	if f.Mode == "REPEATED" {
		return "ARRAY<" + t + ">"
	}
	return t
}

func (r *bqRows) Next(dest []driver.Value) error {
	for r.i >= len(r.page) {
		if r.res.PageToken == "" {
			return io.EOF
		}
		ref := r.res.JobReference
		q := url.Values{"pageToken": {r.res.PageToken}, "maxResults": {"1000"}, "formatOptions.useInt64Timestamp": {"true"}}
		if ref.Location != "" {
			q.Set("location", ref.Location)
		}
		var next bqResults
		if err := r.c.call(r.ctx, http.MethodGet, "/projects/"+url.PathEscape(ref.ProjectID)+"/queries/"+url.PathEscape(ref.JobID), q, nil, &next); err != nil {
			return err
		}
		r.res.PageToken, r.page, r.i = next.PageToken, next.Rows, 0
	}
	row := r.page[r.i]
	r.i++
	fields := r.fields()
	if len(row.F) != len(dest) || len(fields) != len(dest) {
		return fmt.Errorf("unexpected answer from BigQuery: a row of %d values for %d columns", len(row.F), len(dest))
	}
	for i, cell := range row.F {
		dest[i] = bqValue(cell.V, fields[i])
	}
	return nil
}

// bqValue turns one value of the API's JSON (text, null, or the nested
// shapes of ARRAY and STRUCT) into what komando prints: INT64 a number,
// NUMERIC text with every digit, TIMESTAMP RFC 3339 in UTC, BYTES
// {"base64": ...}, JSON its shape, a STRUCT an object, an ARRAY a list.
func bqValue(v any, f bqField) any {
	if v == nil {
		return nil
	}
	if f.Mode == "REPEATED" {
		items, _ := v.([]any)
		one := f
		one.Mode = "NULLABLE"
		list := make([]any, 0, len(items))
		for _, it := range items {
			cell, _ := it.(map[string]any)
			list = append(list, bqValue(cell["v"], one))
		}
		return list
	}
	if f.Type == "RECORD" || f.Type == "STRUCT" {
		rec, _ := v.(map[string]any)
		cells, _ := rec["f"].([]any)
		obj := map[string]any{}
		for i, sub := range f.Fields {
			if i < len(cells) {
				cell, _ := cells[i].(map[string]any)
				obj[sub.Name] = bqValue(cell["v"], sub)
			}
		}
		return obj
	}
	s, ok := v.(string)
	if !ok {
		return v
	}
	switch f.Type {
	case "INTEGER", "INT64":
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
	case "FLOAT", "FLOAT64":
		if x, err := strconv.ParseFloat(s, 64); err == nil && !math.IsInf(x, 0) && !math.IsNaN(x) {
			return x
		}
	case "BOOLEAN", "BOOL":
		if b, err := strconv.ParseBool(s); err == nil {
			return b
		}
	case "TIMESTAMP":
		if us, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.UnixMicro(us).UTC().Format(time.RFC3339Nano)
		}
		if secs, err := strconv.ParseFloat(s, 64); err == nil {
			return time.UnixMicro(int64(math.Round(secs * 1e6))).UTC().Format(time.RFC3339Nano)
		}
	case "BYTES":
		return map[string]string{"base64": s}
	case "JSON":
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		var x any
		if dec.Decode(&x) == nil {
			return sfNumbers(x)
		}
	}
	return s
}

// call sends one request to the API and reads the JSON answer into res.
func (c *bqConnector) call(ctx context.Context, method, path string, q url.Values, body, res any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "komando")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return c.connectErr(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return bqFailure(resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, res); err != nil {
		return fmt.Errorf("unexpected answer from BigQuery (HTTP %d): %v", resp.StatusCode, err)
	}
	return nil
}

// bqErrProto is one error in the API's answer.
type bqErrProto struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (p *bqErrProto) err(status int) error {
	return &bqError{Status: status, Reason: p.Reason, Msg: strings.TrimSuffix(strings.Join(strings.Fields(p.Message), " "), ".")}
}

// bqError is a request BigQuery refused or a job it could not run.
type bqError struct {
	Status int
	Reason string
	Msg    string
}

func (e *bqError) Error() string {
	if e.Reason == "" {
		return e.Msg
	}
	return fmt.Sprintf("%s (BigQuery: %s)", e.Msg, e.Reason)
}

func bqFailure(status int, raw []byte) error {
	var doc struct {
		Error struct {
			Message string       `json:"message"`
			Status  string       `json:"status"`
			Errors  []bqErrProto `json:"errors"`
		} `json:"error"`
	}
	e := &bqError{Status: status}
	if json.Unmarshal(raw, &doc) == nil {
		e.Msg = doc.Error.Message
		if len(doc.Error.Errors) > 0 {
			e.Reason = doc.Error.Errors[0].Reason
		}
	}
	if e.Msg == "" {
		e.Msg = strings.TrimSpace(string(raw[:min(len(raw), 300)]))
	}
	if e.Msg == "" {
		e.Msg = fmt.Sprintf("HTTP %d %s", status, http.StatusText(status))
	}
	e.Msg = strings.TrimSuffix(strings.Join(strings.Fields(e.Msg), " "), ".")
	return e
}

// bqRetry reports an answer worth asking again: BigQuery is busy, or
// had an error of its own.
func bqRetry(err error) bool {
	var e *bqError
	if !errors.As(err, &e) {
		return false
	}
	switch e.Status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return e.Reason != "quotaExceeded" && e.Reason != "bytesBilledLimitExceeded"
	}
	return e.Reason == "backendError" || e.Reason == "rateLimitExceeded"
}

// humanBytes is n as people read it: 1.5 GiB.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ParseBytes reads a size such as 10GB, 500MiB, 1TB or 1048576 (bytes);
// the units are powers of 1024, as BigQuery bills. 0 is no cap.
func ParseBytes(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	num, mult := strings.TrimSuffix(t, "B"), int64(1)
	for i, u := range []string{"K", "M", "G", "T", "P"} {
		for _, suffix := range []string{u + "IB", u + "B", u} {
			if rest, ok := strings.CutSuffix(t, suffix); ok && rest != "" && mult == 1 {
				num, mult = rest, int64(1)<<(10*(i+1))
			}
		}
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
	if err != nil || f < 0 || math.IsInf(f, 0) || f*float64(mult) > math.MaxInt64/2 {
		return 0, out.Usage("size %q: write it like 10GB, 500MB or 1TB", s)
	}
	return int64(f * float64(mult)), nil
}
