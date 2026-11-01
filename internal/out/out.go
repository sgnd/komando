// Package out renders every command result as a stable, machine-readable
// envelope. AI agents parse stdout; humans can ask for -o text.
package out

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Exit codes are part of the public contract. Agents may branch on them.
const (
	ExitOK       = 0
	ExitError    = 1 // generic / internal error
	ExitUsage    = 2 // bad flags or arguments
	ExitNotFound = 3 // host, key, secret, job ... not found
	ExitConnect  = 4 // ssh connection / auth / host-key failure
	ExitRemote   = 5 // remote command ran but exited non-zero
	ExitPolicy   = 6 // blocked by safety policy (needs --yes / --allow-dangerous)
	ExitTimeout  = 7 // command or connection timed out
	ExitConflict = 8 // precondition failed (e.g. replace text not found / ambiguous)
)

// Error is a typed error carrying a stable code, an exit code and a hint
// that tells the agent how to recover.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Exit    int    `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func (e *Error) WithHint(h string) *Error { e.Hint = h; return e }

func Errf(exit int, code, hint, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...), Hint: hint, Exit: exit}
}

func NotFound(kind, name string) *Error {
	return Errf(ExitNotFound, strings.ToUpper(kind)+"_NOT_FOUND",
		fmt.Sprintf("run `komando %s list` to see available %ss", kind, kind),
		"%s %q not found", kind, name)
}

func Usage(format string, a ...any) *Error {
	return Errf(ExitUsage, "USAGE", "run with --help or `komando schema` for the full command reference", format, a...)
}

// Envelope is the single JSON object printed on stdout for every command.
type Envelope struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	Data    any    `json:"data,omitempty"`
	Error   *Error `json:"error,omitempty"`
	Meta    Meta   `json:"meta"`
}

type Meta struct {
	Version    string `json:"version"`
	DurationMS int64  `json:"duration_ms"`
	DryRun     bool   `json:"dry_run,omitempty"`
}

// Printer is configured once by the root command.
type Printer struct {
	Format  string // json | text | yaml-ish not supported, keep it simple
	Pretty  bool
	Version string
	Start   time.Time
	DryRun  bool
	W       io.Writer
}

var P = &Printer{Format: "json", W: os.Stdout, Start: time.Now()}

// Texter lets a result type provide a human rendering for -o text.
type Texter interface{ Text() string }

func (p *Printer) meta() Meta {
	return Meta{Version: p.Version, DurationMS: time.Since(p.Start).Milliseconds(), DryRun: p.DryRun}
}

// Success prints data. A non-nil softErr marks the envelope not-ok but still
// carries data (e.g. multi-host exec with partial failures).
func (p *Printer) Print(command string, data any, softErr *Error) {
	env := Envelope{OK: softErr == nil, Command: command, Data: data, Error: softErr, Meta: p.meta()}
	if p.Format == "text" {
		if t, ok := data.(Texter); ok {
			s := t.Text()
			fmt.Fprint(p.W, s)
			if s != "" && !strings.HasSuffix(s, "\n") {
				fmt.Fprintln(p.W)
			}
		} else if data != nil {
			fmt.Fprint(p.W, renderText(data))
		}
		if softErr != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", softErr.Message)
			if softErr.Hint != "" {
				fmt.Fprintf(os.Stderr, "hint: %s\n", softErr.Hint)
			}
		}
		return
	}
	p.writeJSON(env)
}

func (p *Printer) Fail(command string, err error) int {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Code: "ERROR", Message: err.Error(), Exit: ExitError}
	}
	if p.Format == "text" {
		fmt.Fprintf(os.Stderr, "error [%s]: %s\n", e.Code, e.Message)
		if e.Hint != "" {
			fmt.Fprintf(os.Stderr, "hint: %s\n", e.Hint)
		}
		return e.Exit
	}
	p.writeJSON(Envelope{OK: false, Command: command, Error: e, Meta: p.meta()})
	return e.Exit
}

func (p *Printer) writeJSON(v any) {
	enc := json.NewEncoder(p.W)
	enc.SetEscapeHTML(false)
	if p.Pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(v)
}

// NDJSON emits one streaming event line (used by --stream / follow modes).
func (p *Printer) Event(v any) {
	enc := json.NewEncoder(p.W)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// renderText is a generic fallback: JSON round-trip into maps and print
// key: value lines / simple tables.
func renderText(data any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprint(data)
	}
	var v any
	_ = json.Unmarshal(b, &v)
	var sb strings.Builder
	writeAny(&sb, v, "")
	return sb.String()
}

func writeAny(sb *strings.Builder, v any, indent string) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch c := t[k].(type) {
			case map[string]any, []any:
				fmt.Fprintf(sb, "%s%s:\n", indent, k)
				writeAny(sb, c, indent+"  ")
			default:
				fmt.Fprintf(sb, "%s%s: %v\n", indent, k, scalar(c))
			}
		}
	case []any:
		for _, item := range t {
			switch item.(type) {
			case map[string]any:
				fmt.Fprintf(sb, "%s-\n", indent)
				writeAny(sb, item, indent+"  ")
			default:
				fmt.Fprintf(sb, "%s- %v\n", indent, scalar(item))
			}
		}
	default:
		fmt.Fprintf(sb, "%s%v\n", indent, scalar(t))
	}
}

func scalar(v any) any {
	if v == nil {
		return "-"
	}
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return int64(f)
	}
	return v
}
