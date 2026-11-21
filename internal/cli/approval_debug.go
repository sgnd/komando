package cli

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/rundir"
)

// While KOMANDO_APPROVAL_DEBUG is set, each macOS approval panel adds what
// it saw to approval-debug.log in the per-user run folder (C237): the keys,
// the first responder, handler errors, how it ended and how osascript
// exited. It never holds the texts the panel shows.
const (
	approvalDebugEnv  = "KOMANDO_APPROVAL_DEBUG"
	approvalDebugFile = "approval-debug.log"
	// macDebugMark starts each line the panel script notes on stderr
	macDebugMark = "komando-debug "
	// macDebugMaxLines bounds one run's lines: a held arrow key repeats
	macDebugMaxLines = 400
)

// openApprovalDebug opens the log for adding, or nil when the variable is
// not set. A log that cannot open is a warning; the panel still shows.
func openApprovalDebug(cl *call) io.WriteCloser {
	if cl.getenv(approvalDebugEnv) == "" {
		return nil
	}
	dir, err := rundir.Dir()
	if err == nil {
		f, ferr := rundir.Append(dir, approvalDebugFile)
		if ferr == nil {
			return f
		}
		err = ferr
	}
	cl.out.Warn(fmt.Sprintf("%s is set, but komando could not open its debug log: %v", approvalDebugEnv, err))
	return nil
}

// macDebugArgs is macArgs with "1" as the script's argv[10], which turns
// its notes on.
func macDebugArgs(v approvalView) []string { return append(macArgs(v), "1") }

// macRun is one osascript run of the panel, as askMac saw it.
type macRun struct {
	start       time.Time
	took        time.Duration
	out, errOut []byte
	err         error
	ans         macOutcome
	shown       bool
}

var macOutcomeName = map[macOutcome]string{
	macDenied:       "denied",
	macAllowed:      "allowed",
	macOwnerFailed:  "owner check failed",
	macOwnerTimeout: "owner check timed out",
	macGaveUp:       "gave up",
}

// macAnswers are what the panel prints; the log copies stdout only when it
// is one of these.
var macAnswers = []string{"Deny", "gave up", "Allow once", "Allow once\nowner ok", "Allow once\nowner denied",
	"Allow once\nowner timeout", "Allow once\nowner unavailable"}

// macDebugLog writes one panel run to w: the view's shape, each line the
// script noted, how osascript ended, its other error output and the
// outcome. Every text the panel showed is taken out first.
func macDebugLog(w io.Writer, v approvalView, r macRun) {
	var b strings.Builder
	fmt.Fprintf(&b, "== %s macOS approval panel, komando %s\n", r.start.Format("2006-01-02 15:04:05.000 MST"), buildName())
	b.WriteString("view: " + viewShape(v) + "\n")
	hide := panelTexts(v)
	var notes, other []string
	for _, l := range strings.Split(string(r.errOut), "\n") {
		if l = strings.TrimRight(l, "\r"); l == "" {
			continue
		}
		l = hide.Replace(l)
		if n, ok := strings.CutPrefix(l, macDebugMark); ok {
			notes = append(notes, "js "+n)
		} else {
			other = append(other, "stderr: "+l)
		}
	}
	writeCapped(&b, notes)
	b.WriteString("osascript: " + macExit(r) + "\n")
	b.WriteString("stdout: " + macStdout(r.out) + "\n")
	writeCapped(&b, other)
	outcome := macOutcomeName[r.ans]
	if !r.shown {
		outcome = "no window"
	}
	b.WriteString("outcome: " + outcome + "\n")
	_, _ = io.WriteString(w, b.String())
}

// writeCapped writes lines, at most macDebugMaxLines of them.
func writeCapped(b *strings.Builder, lines []string) {
	for i, l := range lines {
		if i == macDebugMaxLines {
			fmt.Fprintf(b, "(%d more lines left out)\n", len(lines)-i)
			return
		}
		b.WriteString(l + "\n")
	}
}

// macExit is how osascript ended: its exit status and how long it ran,
// or why it did not start.
func macExit(r macRun) string {
	var ee *exec.ExitError
	switch {
	case r.err == nil:
		return "exit 0 after " + r.took.Round(100*time.Millisecond).String()
	case !errors.As(r.err, &ee):
		return "did not start: " + r.err.Error()
	}
	s := ee.ProcessState.String() + " after " + r.took.Round(100*time.Millisecond).String()
	if r.took >= macWindowTimeout {
		s += " (komando stops it at " + macWindowTimeout.String() + ")"
	}
	return s
}

// macStdout is what osascript printed, when it is one of the answers.
func macStdout(out []byte) string {
	s := strings.TrimSuffix(string(out), "\n")
	switch {
	case s == "":
		return "nothing"
	case slices.Contains(macAnswers, s):
		return strconv.Quote(s)
	}
	return fmt.Sprintf("%d bytes, not one of the answers", len(out))
}

// viewShape is what the panel showed, by size only.
func viewShape(v approvalView) string {
	s := fmt.Sprintf("%d lines, %d bytes shown, lang %s", v.bodyLines(), len(v.shown()), v.Lang)
	if v.raw != "" {
		return s + ", a text with no parts"
	}
	return s + ", flags " + strings.Join(v.Flags, " ")
}

// scriptLineNo is the number approval_body.go puts before a script line.
var scriptLineNo = regexp.MustCompile(`^ *\d+  `)

// panelTexts replaces each text the panel shows, whole and line by line
// (a script line without its number), with "[panel text]"; the longest
// first, so a line goes whole before a part of it.
func panelTexts(v approvalView) *strings.Replacer {
	var texts []string
	add := func(s string) {
		for _, l := range append([]string{s}, strings.Split(s, "\n")...) {
			l = strings.TrimSpace(scriptLineNo.ReplaceAllString(l, ""))
			if utf8.RuneCountInString(l) >= 4 && !slices.Contains(texts, l) {
				texts = append(texts, l)
			}
		}
	}
	for _, s := range append([]string{v.title(), v.info(), v.ownerReason(), v.shown(), noBreakHyphens(v.shown()), v.Line, v.Body, v.Agent}, v.Targets...) {
		add(s)
	}
	sort.SliceStable(texts, func(i, j int) bool { return len(texts[i]) > len(texts[j]) })
	pairs := make([]string, 0, 2*len(texts))
	for _, t := range texts {
		pairs = append(pairs, t, "[panel text]")
	}
	return strings.NewReplacer(pairs...)
}

// buildName is komando's version, with the module version or commit of a
// build that is not a release.
func buildName() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok || Version != "dev" {
		return Version
	}
	if mv := bi.Main.Version; mv != "" && mv != "(devel)" {
		return Version + " (" + mv + ")"
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return Version + " (" + s.Value[:12] + ")"
		}
	}
	return Version
}
