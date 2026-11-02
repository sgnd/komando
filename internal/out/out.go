// Package out renders every command result as a stable, machine-readable
// envelope. AI agents parse stdout; humans can ask for -o text.
package out

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
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

// Contract is the version of komando's output contract: the envelope,
// field names, error codes and exit codes. Within one contract, fields
// and codes are only added, never renamed or removed; a breaking change
// raises it (docs/design/ux.md, section 13).
const Contract = 1

type Meta struct {
	Contract   int    `json:"contract"`
	Version    string `json:"version"`
	DurationMS int64  `json:"duration_ms"`
	DryRun     bool   `json:"dry_run,omitempty"`
	// Skipped lists targets a selector picked that this command cannot work
	// with (a database picked by `exec @prod`, a server by `db query @prod`).
	Skipped []Skipped `json:"skipped,omitempty"`
}

type Skipped struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // host, or the conn kind (postgres, redis, ...)
	Reason string `json:"reason"`
}

// Printer is configured once by the root command.
type Printer struct {
	Format  string // json | text | yaml-ish not supported, keep it simple
	Pretty  bool
	Version string
	Start   time.Time
	DryRun  bool
	W       io.Writer
	skipped []Skipped

	// Secrets returns the secret values (by name) that must never appear in
	// output: remote files, logs and command output that happen to contain
	// one show [secret:NAME] instead. It is called once, on first use.
	Secrets  func() map[string]string
	NoRedact bool // `secret get --reveal`: a person asked for the value
	once     sync.Once
	hide     []hidden
}

type hidden struct{ raw, json, label string }

// minSecret is the shortest value hidden: shorter ones would match
// ordinary words and garble output.
const minSecret = 6

func (p *Printer) load() {
	p.once.Do(func() {
		if p.Secrets == nil {
			return
		}
		for name, v := range p.Secrets() {
			if len(v) < minSecret {
				continue
			}
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(v)
			j := strings.TrimSuffix(strings.TrimSpace(b.String()), `"`)
			p.hide = append(p.hide, hidden{raw: v, json: strings.TrimPrefix(j, `"`), label: "[secret:" + name + "]"})
		}
		// longest first, so a secret that contains another is hidden whole
		sort.Slice(p.hide, func(i, j int) bool { return len(p.hide[i].raw) > len(p.hide[j].raw) })
	})
}

// Redact hides secret values in plain text.
func (p *Printer) Redact(s string) string {
	if p.NoRedact {
		return s
	}
	p.load()
	for _, h := range p.hide {
		s = strings.ReplaceAll(s, h.raw, h.label)
	}
	return s
}

func (p *Printer) redactJSON(b []byte) []byte {
	if p.NoRedact {
		return b
	}
	p.load()
	for _, h := range p.hide {
		b = bytes.ReplaceAll(b, []byte(h.json), []byte(h.label))
	}
	return b
}

var P = &Printer{Format: "json", W: os.Stdout, Start: time.Now()}

// Texter lets a result type provide a human rendering for -o text.
type Texter interface{ Text() string }

func (p *Printer) meta() Meta {
	return Meta{Contract: Contract, Version: p.Version, DurationMS: time.Since(p.Start).Milliseconds(), DryRun: p.DryRun, Skipped: p.skipped}
}

// Skip records a target the command leaves out. It is reported in
// meta.skipped, and on stderr in text mode.
func (p *Printer) Skip(s Skipped) {
	p.skipped = append(p.skipped, s)
	if p.Format == "text" {
		fmt.Fprintf(os.Stderr, "skipped %s (%s): %s\n", s.Name, s.Kind, s.Reason)
	}
}

// Success prints data. A non-nil softErr marks the envelope not-ok but still
// carries data (e.g. multi-host exec with partial failures).
func (p *Printer) Print(command string, data any, softErr *Error) {
	env := Envelope{OK: softErr == nil, Command: command, Data: data, Error: softErr, Meta: p.meta()}
	if p.Format == "text" {
		if t, ok := data.(Texter); ok {
			s := p.Redact(t.Text())
			fmt.Fprint(p.W, s)
			if s != "" && !strings.HasSuffix(s, "\n") {
				fmt.Fprintln(p.W)
			}
		} else if data != nil {
			fmt.Fprint(p.W, p.Redact(renderText(data)))
		}
		if softErr != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", p.Redact(softErr.Message))
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
		fmt.Fprintf(os.Stderr, "error [%s]: %s\n", e.Code, p.Redact(e.Message))
		if e.Hint != "" {
			fmt.Fprintf(os.Stderr, "hint: %s\n", e.Hint)
		}
		return e.Exit
	}
	p.writeJSON(Envelope{OK: false, Command: command, Error: e, Meta: p.meta()})
	return e.Exit
}

func (p *Printer) writeJSON(v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if p.Pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(v)
	_, _ = p.W.Write(p.redactJSON(b.Bytes()))
}

// NDJSON emits one streaming event line (used by --stream / follow modes).
func (p *Printer) Event(v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	_, _ = p.W.Write(p.redactJSON(b.Bytes()))
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
	if m, ok := v.(map[string]any); ok {
		if rs, ok := m["results"].([]any); ok {
			writeResults(&sb, rs, m["summary"])
			return sb.String()
		}
	}
	writeAny(&sb, v, "")
	return sb.String()
}

// writeResults renders multi-host results as one block per host:
//
//	● web1  ok
//	  key: value
func writeResults(sb *strings.Builder, rs []any, summary any) {
	for _, r := range rs {
		m, ok := r.(map[string]any)
		if !ok {
			writeAny(sb, r, "")
			continue
		}
		status := "ok"
		if m["ok"] == false {
			status = "FAILED"
		}
		fmt.Fprintf(sb, "● %v  %s\n", m["host"], status)
		rest := map[string]any{}
		for k, val := range m {
			if k != "host" && k != "ok" {
				rest[k] = val
			}
		}
		switch d := rest["data"].(type) {
		case string:
			delete(rest, "data")
			sb.WriteString(indentLines(d, "  "))
		case map[string]any:
			delete(rest, "data")
			for k, val := range d {
				rest[k] = val
			}
		}
		if rest["exit_code"] == float64(0) {
			delete(rest, "exit_code")
		}
		writeAny(sb, rest, "  ")
	}
	if s, ok := summary.(map[string]any); ok {
		fmt.Fprintf(sb, "\n%v ok, %v failed\n", scalar(s["ok"]), scalar(s["failed"]))
	}
}

func indentLines(s, prefix string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix) + "\n"
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
			if t[k] == nil {
				continue
			}
			if inline, ok := scalarList(t[k]); ok {
				fmt.Fprintf(sb, "%s%s: %s\n", indent, k, inline)
				continue
			}
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
				var sub strings.Builder
				writeAny(&sub, item, indent+"  ")
				sb.WriteString(strings.Replace(sub.String(), indent+"  ", indent+"- ", 1))
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

// scalarList renders a list of plain values on one line ("a, b, c").
func scalarList(v any) (string, bool) {
	l, ok := v.([]any)
	if !ok {
		return "", false
	}
	parts := make([]string, 0, len(l))
	for _, x := range l {
		switch x.(type) {
		case map[string]any, []any:
			return "", false
		}
		parts = append(parts, fmt.Sprint(scalar(x)))
	}
	if len(parts) == 0 {
		return "-", true
	}
	return strings.Join(parts, ", "), true
}
