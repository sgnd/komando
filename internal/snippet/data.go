package snippet

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// Data is one target's answer: the JSON contract of `snippet exec` (design
// 5.1). Result is exactly what the replaced command put in a server's data.
// A failure has no result and no raw text, except the rows a carried check
// keeps (a unit not found still returns the units that were read).
type Data struct {
	Snippet  string     `json:"snippet"`
	Shape    string     `json:"shape"`
	Target   string     `json:"target"`
	OK       bool       `json:"ok"`
	Result   any        `json:"result,omitempty"`
	ExitCode *int       `json:"exit_code,omitempty"`
	Warnings []string   `json:"warnings,omitempty"`
	Error    *out.Error `json:"error,omitempty"`
}

// noResult are the failures after which nothing of the result may show.
var noResult = map[string]bool{"SNIPPET_PARSE_FAILED": true, "SNIPPET_OS_UNSUPPORTED": true, "SNIPPET_TYPE_UNSUPPORTED": true}

// NewData is one target's answer.
func NewData(b Builtin, target string, result any, err *out.Error, exit *int, warnings []string) Data {
	d := Data{Snippet: b.Name, Shape: b.Shape, Target: target, OK: err == nil, Result: result, ExitCode: exit, Warnings: warnings, Error: err}
	if err != nil && (noResult[err.Code] || result == nil) {
		d.Result = nil
	}
	return d
}

// Parse turns one target's output into the result. A parser's own coded
// error (*out.Error) is a check it carries from the replaced command and
// stays, with the rows it returns. Any other failure, a panic, or no
// result at all is SNIPPET_PARSE_FAILED with no result: never a partial or
// guessed shape, and never the raw text.
func Parse(b Builtin, f Family, o Output) (res any, perr *out.Error) {
	defer func() {
		if recover() != nil {
			res, perr = nil, parseFailed(b)
		}
	}()
	res, err := b.Parse(o, f)
	var coded *out.Error
	if errors.As(err, &coded) {
		if coded != nil {
			return res, coded
		}
		err = nil // a nil *out.Error inside the error interface
	}
	if err != nil || res == nil {
		return nil, parseFailed(b)
	}
	return res, nil
}

func parseFailed(b Builtin) *out.Error {
	return out.Errf(out.ExitRemote, "SNIPPET_PARSE_FAILED", "read it as text with `komando host ssh exec TARGET -- COMMAND`; the snippet has no JSON for it",
		"the output of snippet %s did not read as %s", b.Name, b.Shape)
}

// ParseShape splits "svc-list/1" into its name and major.
func ParseShape(s string) (string, int, error) {
	name, major, ok := strings.Cut(s, "/")
	n, err := strconv.Atoi(major)
	if !ok || name == "" || err != nil || n < 1 || strconv.Itoa(n) != major {
		return "", 0, fmt.Errorf("a shape is NAME/MAJOR with MAJOR from 1, not %q", s)
	}
	return name, n, nil
}

// Decode reads one target's answer for a reader that knows shape want
// (such as "svc-list/1"). It refuses another snippet or another major;
// fields it does not know are ignored, since an added field does not raise
// the major.
func Decode(raw []byte, want string) (Data, error) {
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return Data{}, fmt.Errorf("snippet data: %w", err)
	}
	gotName, gotMajor, err := ParseShape(d.Shape)
	if err != nil {
		return Data{}, err
	}
	wantName, wantMajor, err := ParseShape(want)
	if err != nil {
		return Data{}, err
	}
	if gotName != wantName || gotMajor != wantMajor {
		return Data{}, fmt.Errorf("shape %s is not the %s this reader knows", d.Shape, want)
	}
	return d, nil
}
