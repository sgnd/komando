// Package out renders every command result as a stable, machine-readable
// envelope. AI agents parse stdout; humans can ask for -o text.
package out

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
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
	ExitConnect  = 4 // ssh connection / auth / host-key failure; CONNECTION_LOST: broke mid-command
	ExitRemote   = 5 // remote command ran but exited non-zero
	ExitPolicy   = 6 // blocked for safety: needs a person's yes or a person at a terminal
	ExitTimeout  = 7 // command or connection timed out
	ExitConflict = 8 // precondition failed (e.g. replace text not found / ambiguous)
)

// Error is a typed error carrying a stable code, an exit code and a hint
// that tells the agent how to recover.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	// Thing says which kind of item a code shared by several kinds is
	// about (KEY_NOT_FOUND: ssh_key or cache_key), S-8.3; additive
	Thing string `json:"thing,omitempty"`
	// Suggestion is the word komando thinks was meant ("did you mean"),
	// S-8.8; the hint has the whole command line with it; additive
	Suggestion string `json:"suggestion,omitempty"`
	Exit       int    `json:"-"`
	// Final: no flag lifts this stop (no --yes, --allow-dangerous or
	// --reveal), so an AI agent is not told that adding one asks the user
	Final bool `json:"-"`

	// text-mode wording for a person; JSON keeps Message and Hint
	say, sayHint string
	cancelled    bool
	need         []string // more flags the real run needs (Need)
}

// Say sets the words a person reads in text mode. JSON is unchanged, so
// agents and scripts keep the stable Message and Hint. An empty hint keeps
// the usual one.
func (e *Error) Say(msg, hint string) *Error { e.say, e.sayHint = msg, hint; return e }

// PlainHint drops the hint Say set for a person, so text mode prints Hint
// as JSON does (an AI agent reads -o text too).
func (e *Error) PlainHint() *Error { e.sayHint = ""; return e }

// Cancel marks a stop the person chose at the terminal: text mode prints
// msg alone, without "Stopped:", a hint or the code.
func (e *Error) Cancel(msg string) *Error { e.say, e.cancelled = msg, true; return e }

// TextMessage and TextHint are what text mode prints.
func (e *Error) TextMessage() string {
	if e.say != "" {
		return e.say
	}
	return e.Message
}

func (e *Error) TextHint() string {
	if e.sayHint != "" {
		return e.sayHint
	}
	return e.hintOrDefault()
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// NoFlag marks a stop that no flag lifts (see Final).
func (e *Error) NoFlag() *Error { e.Final = true; return e }

func (e *Error) WithHint(h string) *Error { e.Hint = h; return e }

// About sets error.thing: which kind of item a shared code is about.
func (e *Error) About(thing string) *Error { e.Thing = thing; return e }

// MarshalJSON writes the error with a hint even when the code that made it
// gave none: error.hint always says what to try next.
func (e Error) MarshalJSON() ([]byte, error) {
	type plain Error
	p := plain(e)
	p.Hint = e.hintOrDefault()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // the outer encoder decides, as for any field
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

func (e Error) hintOrDefault() string {
	if e.Hint != "" {
		return e.Hint
	}
	return DefaultHint(e.Exit)
}

// DefaultHint is the next step for an error whose code gives no hint of
// its own, by its exit code.
func DefaultHint(exit int) string {
	switch exit {
	case ExitUsage:
		return UsageHint
	case ExitNotFound:
		return "check the name; `komando list` shows the servers, conns and VPNs komando knows"
	case ExitConnect:
		return "check that it answers and accepts the login: `komando test TARGET`"
	case ExitRemote:
		return "read the message: it carries the server's own words about what failed; fix that, then run it again"
	case ExitPolicy:
		return "stop and tell the user what you want to do and why; `komando guide` explains the safety stops"
	case ExitTimeout:
		return "give it more time with --timeout (for example --timeout 30m), or run long work as a job: `komando job start TARGET -- COMMAND`"
	case ExitConflict:
		return "the state is not what the command expected: look at it again, then run it again"
	}
	return "read the message; `komando doctor` checks this computer's setup"
}

func Errf(exit int, code, hint, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...), Hint: hint, Exit: exit}
}

// UsageHint is the hint a usage error gets when its command gives none.
// The error handler swaps it for the failing command's own --help and
// example, which says more than a hint shared by every command.
const UsageHint = "run with --help or `komando schema` for the full command reference"

func Usage(format string, a ...any) *Error {
	return Errf(ExitUsage, "USAGE", UsageHint, format, a...)
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
// raises it (docs/design/principles.md, section 5).
const Contract = 1

type Meta struct {
	Contract   int    `json:"contract"`
	Version    string `json:"version"`
	DurationMS int64  `json:"duration_ms"`
	DryRun     bool   `json:"dry_run,omitempty"`
	// Skipped lists targets a selector picked that this command cannot work
	// with (a database picked by `exec @prod`, a server by `db query @prod`).
	Skipped []Skipped `json:"skipped,omitempty"`
	// WouldBeBlocked: under --dry-run, the safety stop the real run would hit
	WouldBeBlocked *Error `json:"would_be_blocked,omitempty"`
	// WouldNeed: under --dry-run, every approval flag the real run needs
	// (--allow-dangerous and --yes for a delete on a protected server),
	// sorted; would_be_blocked names only the first stop.
	WouldNeed []string `json:"would_need,omitempty"`
	// HostKeysPinned lists the servers whose host key this command trusted
	// for the first time (host_key_policy accept-new). Nothing proved the
	// key is the server's: compare the fingerprint with the server's own.
	HostKeysPinned []HostKey `json:"host_keys_pinned,omitempty"`
	// Warnings are things that went wrong beside the result (an audit
	// record that could not be written); they are on stderr too.
	Warnings []string `json:"warnings,omitempty"`
	// Truncated: a list stopped at --limit; more items are there
	// (--limit 0 shows them all).
	Truncated bool `json:"truncated,omitempty"`
	// NotSimulated: under --dry-run, the steps the dry run could not try
	// without making them (a MySQL DDL statement commits by itself); the
	// rest of the preview holds, these were not checked.
	NotSimulated []string `json:"not_simulated,omitempty"`
}

// HostKey is a server's host key, as komando pinned it.
type HostKey struct {
	Host        string `json:"host"`
	Address     string `json:"address"`
	Type        string `json:"key_type"`
	Fingerprint string `json:"fingerprint"` // SHA256:...
}

type Skipped struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // host, or the conn kind (postgres, redis, ...)
	Reason string `json:"reason"`
}

// Printer prints one call's output. Each call has its own (no two calls
// share one), set up by the root command.
type Printer struct {
	Format  string // json | text
	Pretty  bool
	Version string
	Start   time.Time
	DryRun  bool
	W       io.Writer // stdout: the envelope, or the text
	// Err is stderr: notes, warnings, hints and, in text mode, errors.
	// nil writes them nowhere.
	Err io.Writer
	// Width is the column a person's stderr lines wrap at, 0 for none (a
	// pipe, an AI agent). nil wraps nothing.
	Width   func() int
	skipped []Skipped
	blocked *Error
	need    []string // meta.would_need
	pinned  []HostKey
	warns   []string
	mu      sync.Mutex // pinned, warns: connections run side by side

	cutAt    int      // the --limit a list stopped at (Cut)
	cut      bool     // meta.truncated
	cutNoted bool     // the command's own text says it was cut
	notSim   []string // meta.not_simulated

	// Secrets returns the secret values (by name) that must never appear in
	// output: remote files, logs and command output that happen to contain
	// one show [secret:NAME] instead. It is called once, on first use.
	Secrets  func() map[string]string
	NoRedact bool // `secret get --reveal`: a person asked for the value
	// Mask also hides values that look like passwords, keys and tokens
	// (mask.go). It is on for AI agents.
	Mask bool
	// Personal, with Mask, also hides personal data: email addresses,
	// phone numbers, card numbers and IBANs (personal.go). A command that
	// reads data from a target turns it on when the mask_personal setting
	// covers that target.
	Personal bool
	once     sync.Once
	hmu      sync.RWMutex // hide: AddValue may run beside a command's output
	hide     []hidden
}

type hidden struct {
	raw, json, label string
	added            bool // by AddValue: forgotten when the next command starts (Reset)
}

// minSecret is the shortest value hidden: shorter ones would match
// ordinary words and garble output.
const minSecret = 6

func (p *Printer) load() {
	p.once.Do(func() {
		if p.Secrets == nil {
			return
		}
		p.hmu.Lock()
		defer p.hmu.Unlock()
		for name, v := range p.Secrets() {
			p.addLocked(v, "[secret:"+name+"]", false)
		}
	})
}

// RedactExact hides only the exact values komando keeps secret, never
// what merely looks like one: for text a person must see whole (the
// approval window), where a pattern could hide more than a value.
func (p *Printer) RedactExact(s string) string {
	if p.NoRedact {
		return s
	}
	for _, h := range p.hideList() {
		s = strings.ReplaceAll(s, h.raw, h.label)
	}
	return s
}

// Redact hides secret values in plain text.
func (p *Printer) Redact(s string) string {
	if p.NoRedact {
		return s
	}
	s = p.RedactExact(s)
	if p.Mask {
		s = MaskSecrets(s)
		if p.Personal {
			s = MaskPersonal(s)
		}
	}
	return s
}

func (p *Printer) redactJSON(b []byte) []byte {
	if p.NoRedact {
		return b
	}
	for _, h := range p.hideList() {
		b = bytes.ReplaceAll(b, []byte(h.json), []byte(h.label))
	}
	if p.Mask {
		b = maskJSON(b)
		if p.Personal {
			b = maskPersonalJSON(b)
		}
	}
	return b
}

// Stderr is where the printer's stderr lines go.
func (p *Printer) Stderr() io.Writer {
	if p.Err == nil {
		return io.Discard
	}
	return p.Err
}

// width is the column stderr lines wrap at.
func (p *Printer) width() int {
	if p.Width == nil {
		return 0
	}
	return p.Width()
}

// Texter lets a result type provide a human rendering for -o text.
type Texter interface{ Text() string }

// PrinterTexter is a Texter whose text depends on the printer that prints
// it: its dry run ("would write" instead of "wrote"), or its stderr and
// what it hides, for the lines a result sends there.
type PrinterTexter interface{ TextFor(p *Printer) string }

func (p *Printer) meta() Meta {
	p.mu.Lock()
	pinned, warns, cut, ns := slices.Clone(p.pinned), slices.Clone(p.warns), p.cut, slices.Clone(p.notSim)
	p.mu.Unlock()
	return Meta{Contract: Contract, Version: p.Version, DurationMS: time.Since(p.Start).Milliseconds(), DryRun: p.DryRun, Skipped: p.skipped, WouldBeBlocked: p.blocked, WouldNeed: slices.Clone(p.need),
		HostKeysPinned: pinned, Warnings: warns, Truncated: cut, NotSimulated: ns}
}

// NotSimulated records a step a dry run left out because trying it would
// make it (meta.not_simulated).
func (p *Printer) NotSimulated(what string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.notSim = append(p.notSim, what)
}

// HostKeyPinned records a host key trusted on first use, for
// meta.host_keys_pinned (a person reads it on stderr).
func (p *Printer) HostKeyPinned(k HostKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pinned = append(p.pinned, k)
}

// WouldBlock records, under --dry-run, the first safety stop the real run
// would hit (meta.would_be_blocked), and the flag every stop needs
// (meta.would_need).
func (p *Printer) WouldBlock(e *Error) {
	if p.blocked == nil {
		p.blocked = e
	}
	for _, f := range e.Flags() {
		if !slices.Contains(p.need, f) {
			p.need = append(p.need, f)
		}
	}
	slices.Sort(p.need)
}

// ApprovalFlag is the flag that lets a safety stop through (--yes,
// --allow-dangerous, --reveal), or "" for a stop no flag lifts.
func ApprovalFlag(e *Error) string {
	if e == nil || e.Final || e.Exit != ExitPolicy {
		return ""
	}
	switch e.Code {
	case "POLICY_BLOCKED":
		return "--allow-dangerous"
	case "PROTECTED_HOST", "PROTECTED_TARGET", "SAFETY_SETTING", "OPEN_BIND", "SECRET_DESTINATION", "CONFIRM_REQUIRED":
		return "--yes"
	case "REVEAL_NEEDS_PERSON":
		return "--reveal"
	}
	return ""
}

// Reset forgets what one command recorded (tests run many in one process).
func (p *Printer) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blocked, p.need, p.skipped, p.pinned, p.warns, p.notSim = nil, nil, nil, nil, nil, nil
	p.cut, p.cutNoted, p.cutAt = false, false, 0
	p.forgetAdded()
}

// Warn records something that went wrong beside the result: it goes to
// stderr now and into meta.warnings of the envelope printed after it.
func (p *Printer) Warn(msg string) {
	p.mu.Lock()
	p.warns = append(p.warns, msg)
	p.mu.Unlock()
	fmt.Fprintln(p.Stderr(), Marks("Warning: "+Wrap(noteText(p.Redact(msg)), len("Warning: "), p.width())))
}

// Blocked is the stop WouldBlock recorded, or nil.
func (p *Printer) Blocked() *Error { return p.blocked }

// Skip records a target the command leaves out. It is reported in
// meta.skipped, and on stderr in text mode. A command may resolve its
// target more than once (exec checks the OS mix first): the same target
// is listed once.
func (p *Printer) Skip(s Skipped) {
	for _, have := range p.skipped {
		if have.Name == s.Name && have.Kind == s.Kind {
			return
		}
	}
	p.skipped = append(p.skipped, s)
}

// printSkipped tells a person, on stderr, what the target picked that this
// command left out: each one when there are a few, one line when many
// (`pkg upgradable all` would otherwise start with a screen of them).
func (p *Printer) printSkipped() {
	switch n := len(p.skipped); {
	case n == 0:
	case n <= 3:
		for _, s := range p.skipped {
			fmt.Fprintf(p.Stderr(), "Skipped %s (%s): %s\n", s.Name, s.Kind, s.Reason)
		}
	default:
		names := make([]string, n)
		for i, s := range p.skipped {
			names[i] = s.Name
		}
		fmt.Fprintf(p.Stderr(), "Skipped %d targets this command does not work with: %s (details with -o json)\n", n, strings.Join(names, ", "))
	}
}

// OnGenericText, when set (by a test), hears each command whose -o text
// came from the generic renderer, not a Text method of its own (S-9.7).
var OnGenericText func(command string)

// Print prints data. A non-nil softErr marks the envelope not-ok but still
// carries data (e.g. multi-host exec with partial failures).
func (p *Printer) Print(command string, data any, softErr *Error) {
	env := Envelope{OK: softErr == nil, Command: command, Data: data, Error: softErr, Meta: p.meta()}
	if p.Format == "text" {
		p.printSkipped()
		if p.DryRun {
			// a person must never read a preview as a result
			fmt.Fprintln(p.Stderr(), "Dry run: nothing was changed")
			if p.blocked != nil {
				fmt.Fprintf(p.Stderr(), "Without --dry-run this stops here: [%s] %s\n", p.blocked.Code, Marks(noteText(p.Redact(p.blocked.Message))))
				p.hint(p.blocked.hintOrDefault())
			}
		}
		if t, ok := data.(PrinterTexter); ok {
			s := SafeText(p.Redact(t.TextFor(p))) // data: a file or a row is shown as it is
			fmt.Fprint(p.W, s)
			if s != "" && !strings.HasSuffix(s, "\n") {
				fmt.Fprintln(p.W)
			}
		} else if t, ok := data.(Texter); ok {
			s := SafeText(p.Redact(t.Text())) // data: a file or a row is shown as it is
			fmt.Fprint(p.W, s)
			if s != "" && !strings.HasSuffix(s, "\n") {
				fmt.Fprintln(p.W)
			}
		} else if data != nil {
			if OnGenericText != nil {
				OnGenericText(command)
			}
			s := renderText(data, p.DryRun)
			fmt.Fprint(p.W, SafeText(p.Redact(s)))
			if s == "" {
				// an empty list would print nothing, and a person cannot tell
				// "no results" from "did not run"; stderr keeps pipes clean
				fmt.Fprintln(p.Stderr(), "Nothing to show")
			}
		}
		p.printCut()
		if softErr != nil {
			p.printErr(softErr, false)
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
		p.printSkipped()
		p.printErr(e, true)
		return e.Exit
	}
	p.writeJSON(Envelope{OK: false, Command: command, Error: e, Meta: p.meta()})
	return e.Exit
}

// printErr prints an error for a person: what happened first, then what
// to do, then the code and exit code for looking it up. stopped is true
// when the command ended here (Fail), so a safety stop changed nothing.
func (p *Printer) printErr(e *Error, stopped bool) {
	msg := Marks(noteText(p.Redact(e.TextMessage())))
	if e.cancelled {
		fmt.Fprintln(p.Stderr(), msg)
		return
	}
	label := "Error: "
	if strings.HasPrefix(msg, "Stopped") {
		label = "" // a person's stop line (Say) is its own label (M-12)
	} else if stopped && e.Exit == ExitPolicy {
		// a one-line error is a fragment (M-3): the state joins it after
		// a semicolon, and no full stop ends it
		label = "Stopped: "
		msg = strings.TrimRight(msg, " .")
		if !strings.Contains(strings.ToLower(msg), "nothing was changed") {
			msg += "; nothing was changed"
		}
	}
	fmt.Fprintln(p.Stderr(), label+Wrap(msg, len(label), p.width()))
	p.hint(e.TextHint())
	fmt.Fprintf(p.Stderr(), "(code %s, exit %d)\n", e.Code, e.Exit)
}

// hint prints an error's hint in text mode, hidden and made safe like the
// message: a hint can carry the command line, which may hold a secret or
// terminal escapes.
func (p *Printer) hint(h string) {
	if h != "" {
		fmt.Fprintf(p.Stderr(), "Hint: %s\n", Marks(Wrap(noteText(p.Redact(h)), len("Hint: "), p.width())))
	}
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

// Event emits one NDJSON line (--stream and follow modes).
func (p *Printer) Event(v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	_, _ = p.W.Write(p.redactJSON(b.Bytes()))
}

// renderText is a generic fallback: JSON round-trip into maps and print
// key: value lines / simple tables.
func renderText(data any, dryRun bool) string {
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
		if h := headline(m, dryRun); h != "" {
			// what happened comes first, in words; the record follows. The
			// command to run next is data.next, and for a person the Next:
			// line on stderr: nothing next goes to stdout (S-9.3)
			sb.WriteString(h + "\n")
			for _, k := range []string{"action", "changed", "name", "created_at", "updated_at", "next"} {
				delete(m, k)
			}
			for k, v := range m {
				if v == false { // "replaced: false" says nothing after "stored x"
					delete(m, k)
				}
			}
			writeAny(&sb, m, "  ")
			return sb.String()
		}
	}
	writeAny(&sb, v, "")
	return sb.String()
}

// Headline is headline, for a command's own Text method.
func Headline(m map[string]any, dryRun bool) string { return headline(m, dryRun) }

// headline says in words what a change did to a named item ("added web2",
// "web2: nothing to change"), for results that carry an action or a
// changed flag; under --dry-run, what it would do. "" when the result is
// not such a change.
func headline(m map[string]any, dryRun bool) string {
	name, _ := m["name"].(string)
	if name == "" {
		return ""
	}
	if a, ok := m["action"].(string); ok && a != "" {
		switch a {
		case "unchanged", "none":
			return name + ": nothing to change"
		}
		if w, ok := strings.CutPrefix(a, "would_"); ok {
			return "would " + strings.ReplaceAll(w, "_", " ") + " " + name + " (dry run)"
		}
		return strings.ReplaceAll(a, "_", " ") + " " + name
	}
	if c, ok := m["changed"].(bool); ok {
		switch {
		case !c:
			return name + ": nothing to change"
		case dryRun:
			return "would change " + name + " (dry run)"
		}
		return "changed " + name
	}
	return ""
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
			status = "failed"
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
		// the name says what the record is, so it leads; the rest by key
		sort.Slice(keys, func(i, j int) bool {
			if (keys[i] == "name") != (keys[j] == "name") {
				return keys[i] == "name"
			}
			return keys[i] < keys[j]
		})
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
			case string:
				if strings.Contains(strings.TrimRight(c, "\n"), "\n") {
					// a block, as YAML writes one: every line under the key
					fmt.Fprintf(sb, "%s%s: |\n%s", indent, k, indentLines(c, indent+"  "))
					continue
				}
				fmt.Fprintf(sb, "%s%s: %v\n", indent, k, scalar(c))
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
	// JSON times are UTC; a person reads local time with its zone (ux.md, section 4)
	if s, ok := v.(string); ok && len(s) >= 20 && s[4] == '-' && s[10] == 'T' {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.Local().Format("2006-01-02 15:04:05 MST")
		}
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
