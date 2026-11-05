package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
)

// Who is asking decides how komando's safety stops open (docs/features/safety.md):
//
//   - a person at a terminal answers a question there, or passes the flag;
//   - a script (no terminal, no AI agent) passes the flag, as always;
//   - an AI agent passes the flag too, but then a person must allow it in a
//     window komando opens on the screen. The agent cannot click it. With no
//     screen to show it on, the agent is refused and the person runs the
//     command themselves.

// agentVars are environment variables AI coding agents set in the shells
// they run commands in. KOMANDO_AGENT is for any other agent. A harness
// that sets more than one is listed with each, so clearing one variable
// does not make the agent a script.
var agentVars = []struct{ env, name string }{
	{"CLAUDECODE", "Claude Code"},
	{"CLAUDE_CODE_ENTRYPOINT", "Claude Code"},
	{"GEMINI_CLI", "Gemini CLI"},
	{"CODEX_SANDBOX", "Codex"},
	{"CODEX_THREAD_ID", "Codex"},
	{"CURSOR_AGENT", "Cursor"},
	{"KOMANDO_AGENT", "An AI agent"},
	{"AI_AGENT", "An AI agent"},
}

// agentName is the AI agent running komando, or "" for a person or a script.
// A variable that is there counts whatever its value, also 0, false and
// empty: an agent told to run `CLAUDECODE=0 komando ...` or `read CLAUDECODE
// </dev/null` must not turn its own safety stops off. The guard hook
// (guard.go) refuses shell lines that change or remove these variables.
func agentName() string {
	for _, a := range agentVars {
		if _, ok := os.LookupEnv(a.env); ok {
			return a.name
		}
	}
	return ""
}

func isAgent() bool { return agentName() != "" }

var approval struct {
	sync.Mutex
	asked, allowed bool
	why            string          // why there was no yes, for the error hint
	unshown        string          // why the window could not show the command
	shown          map[string]bool // the actions a window named (personAllowsFor)
}

func resetApproval() {
	approval.Lock()
	defer approval.Unlock()
	approval.asked, approval.allowed, approval.why, approval.unshown, approval.shown = false, false, "", "", nil
}

func allowedByPerson() bool {
	approval.Lock()
	defer approval.Unlock()
	return approval.allowed
}

// yesOK reports whether --yes counts. dangerOK and revealOK do the same for
// --allow-dangerous and --reveal. Call them only where the flag would let
// something through, so an agent's window appears only when it matters.
// why, when given, says what the stop is about (the matched rule, the
// targets); the window shows it on its own line.
func yesOK(why ...string) bool { return g.yes && personAllows("--yes", why...) }
func dangerOK(why ...string) bool {
	return g.allowDangerous && personAllows("--allow-dangerous", why...)
}

// revealOK never counts under --dry-run: a preview still prints what it
// reads, and a dry run never asks the person, so it stays masked.
func revealOK() bool { return g.reveal && !g.dryRun && personAllows("--reveal") }

// approvalMaxLen is the longest command line the window shows. A longer one
// is not cut (the hidden part could be the one that matters): the agent is
// told to have the person run it.
const approvalMaxLen = 500

// personAllows: a person or a script used the flag themselves; for an AI
// agent a person must allow it on the screen. One answer covers the whole
// command, so a command that passes two checks asks once.
//
// Under --dry-run nothing the flag lets through runs, so no window opens and
// the preview goes on. The callers that act under --dry-run (output masking,
// see revealOK) must not count on this.
func personAllows(flag string, why ...string) bool { return personAllowsFor(flag, "", why...) }

// personAllowsFor is personAllows that names in the window what the flag
// lets through (a program that runs on this computer), when the command
// line alone does not show it. A yes given in a window that did not name
// it does not cover it: the person is asked again, with it named.
func personAllowsFor(flag, what string, why ...string) bool {
	if !isAgent() || g.dryRun {
		return true
	}
	approval.Lock()
	defer approval.Unlock()
	if approval.asked && (what == "" || approval.shown[what] || !approval.allowed) {
		return approval.allowed
	}
	approval.asked, approval.allowed = true, false
	if what != "" {
		if approval.shown == nil {
			approval.shown = map[string]bool{}
		}
		approval.shown[what] = true
	}
	line := commandLine()
	bad := hiddenArgs(os.Args[1:])
	if bad == "" {
		bad = unshowable(line)
	}
	if bad != "" {
		approval.why, approval.unshown = "unshowable", bad
		return false
	}
	text := fmt.Sprintf("%s wants komando to run:\n\n%s\n\n", agentName(), line)
	for _, w := range why {
		if w = strings.TrimSpace(w); w != "" {
			if unshowable(w) != "" {
				w = strconv.QuoteToASCII(w)
			}
			text += "komando stops here because: " + w + "\n\n"
		}
	}
	text += fmt.Sprintf("%s skips one of komando's safety stops (%s).", flag, flagMeaning[flag])
	if what != "" {
		if unshowable(what) != "" {
			what = strconv.QuoteToASCII(what)
		}
		text += " Here it lets this through:\n\n" + what
	}
	text += "\n\nAllow this once?"
	var allowed, shown bool
	if secret := approvalCodeSecret(); secret != nil {
		// a second factor: the code from the person's authenticator app
		code, pressed, ok := askCodeOnScreen(text)
		allowed, shown = pressed && len(secret) > 0 && codeOK(secret, code, time.Now()), ok
		if pressed && !allowed {
			approval.why = "wrong-code"
		}
	} else {
		allowed, shown = askOnScreen(text)
	}
	switch {
	case allowed:
		approval.allowed = true
	case shown && approval.why == "":
		approval.why = "denied"
	case shown:
	default:
		approval.why = "no-screen"
	}
	return approval.allowed
}

var flagMeaning = map[string]string{
	"--yes":             "a change to a protected server or conn, or to a safety setting",
	"--allow-dangerous": "an action that can delete or break things",
	"--reveal":          "show or send passwords, keys and tokens that komando keeps from AI agents",
}

// unshowable says why a text cannot be shown in the approval window as it
// is, or "". The person must see every character that runs: a long line
// would be cut, and line breaks, control characters, invisible Unicode
// (bidi overrides, zero-width marks), letters that draw as blank (U+3164
// HANGUL FILLER) and combining marks can hide, fake or overdraw parts of
// it. commandLine writes such characters of an argument as escapes, so for
// the command line itself only its length, invalid text and invisible
// characters are left (see hiddenArgs).
func unshowable(s string) string {
	if !utf8.ValidString(s) {
		return "it is not valid text"
	}
	if n := utf8.RuneCountInString(s); n > approvalMaxLen {
		return fmt.Sprintf("it is %d characters long, more than the %d the window shows", n, approvalMaxLen)
	}
	spaces := 0
	for _, r := range s {
		switch {
		case r == ' ':
			if spaces++; spaces > maxSpaces {
				return "it has a long run of spaces, which can push a part of it out of view"
			}
			continue
		case r == '\n' || r == '\r':
			return "it has a line break"
		case unicode.IsControl(r):
			return fmt.Sprintf("it has the control character %U", r)
		case unicode.Is(unicode.Cf, r):
			return fmt.Sprintf("it has the invisible character %U", r)
		case !plainRune(r):
			return fmt.Sprintf("it has the character %U, which may not show as it runs", r)
		}
		spaces = 0
	}
	return ""
}

// maxSpaces is the longest run of spaces the window shows as spaces.
const maxSpaces = 16

// plainRune reports whether r shows as itself in the window: printable
// ASCII, or a letter, digit, punctuation or symbol that draws something.
// Spaces other than ' ', combining marks and the fillers that draw blank
// are not.
func plainRune(r rune) bool {
	if r >= 0x20 && r < 0x7f {
		return true
	}
	switch r {
	case 0x115f, 0x1160, 0x17b4, 0x17b5, 0x2800, 0x3164, 0xffa0:
		return false // fillers and blank patterns: letters that draw nothing
	}
	if unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf) || unicode.IsSpace(r) || unicode.IsControl(r) {
		return false
	}
	return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S, unicode.Mc)
}

// hiddenArgs says why the arguments as given cannot be put before a person,
// or "": invalid text cannot be written back exactly, and bidi overrides
// and zero-width marks are refused outright, even escaped.
func hiddenArgs(args []string) string {
	for _, a := range args {
		if !utf8.ValidString(a) {
			return "it is not valid text"
		}
		for _, r := range a {
			if unicode.Is(unicode.Cf, r) {
				return fmt.Sprintf("it has the invisible character %U", r)
			}
		}
	}
	return ""
}

// policyStop is how every safety stop returns. Under --dry-run it does not
// stop: the command goes on to show its plan, and meta.would_be_blocked
// says the real run would stop here. A preview of a change on a protected
// server is exactly when people need one.
func policyStop(e *out.Error) error {
	if g.dryRun {
		out.P.WouldBlock(e)
		return nil
	}
	return e
}

// approvalHint rewrites the hint of a safety stop for an AI agent: it tells
// it how a person allows the command, or that the person said no.
func approvalHint(e *out.Error) {
	if e == nil || e.Exit != out.ExitPolicy || !isAgent() {
		return
	}
	switch approval.why {
	case "denied":
		e.Hint = "the user clicked Deny in komando's window; do not retry. Ask the user what they want instead"
	case "wrong-code":
		e.Hint = "the code typed in komando's window was wrong or missing; ask the user whether to try again"
	case "no-screen":
		e.Hint = "komando could not show the user an approval window (no screen). Ask the user to run this exact command in their own terminal: " + commandLine()
	case "unshowable":
		e.Hint = "komando did not ask the user in its window, because " + approval.unshown +
			". Make the command shorter (put a long script in a file for `komando script`, change a big file with a few smaller `komando fs replace` runs) and without invisible characters, or ask the user to run it in their own terminal"
	default:
		if e.Code == "REVEAL_NEEDS_HUMAN" || e.Code == "NEEDS_PERSON" { // no flag allows these
			return
		}
		e.Hint += ". Tell the user what you want to do and why; when you add the flag, komando asks the user in a window on their screen"
	}
}

// askOnScreen shows a native window with Deny and "Allow once". shown is
// false when no window could be shown (no screen, no dialog tool, a remote
// session, or KOMANDO_NO_DIALOG=1). The tools are found in system folders
// only, so a fake one earlier in PATH cannot answer for the person.
var askOnScreen = func(text string) (allowed, shown bool) {
	if os.Getenv("KOMANDO_NO_DIALOG") != "" || os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	switch runtime.GOOS {
	case "darwin":
		const script = `on run argv
display dialog (item 1 of argv) with title "komando: allow?" buttons {"Deny", "Allow once"} default button "Deny" cancel button "Deny" giving up after 120 with icon caution
return button returned of result
end run`
		b, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script, text).Output()
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			return false, false
		}
		return strings.TrimSpace(string(b)) == "Allow once", true
	case "linux", "freebsd", "openbsd":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false, false
		}
		if z := systemTool("zenity"); z != "" {
			err := exec.CommandContext(ctx, z, "--question", "--title=komando: allow?", "--text="+text, "--ok-label=Allow once", "--cancel-label=Deny", "--default-cancel", "--no-markup", "--timeout=120").Run()
			return err == nil, true
		}
		if k := systemTool("kdialog"); k != "" {
			err := exec.CommandContext(ctx, k, "--title", "komando: allow?", "--warningyesno", text, "--yes-label", "Allow once", "--no-label", "Deny").Run()
			return err == nil, true
		}
	}
	return false, false
}

func systemTool(name string) string {
	for _, d := range []string{"/usr/bin", "/bin", "/usr/local/bin"} {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// commandLine is this command as typed, quoted where needed. An argument
// with a line break, a tab, a control character, a long run of spaces or a
// character that does not show as itself (plainRune) is written as $'...'
// with escapes (\n, \x1b, \u3164), which shells read back as the same
// text, so a person sees every character and can run it as it is.
func commandLine() string {
	parts := []string{"komando"}
	for _, a := range os.Args[1:] {
		switch {
		case needsEscapes(a):
			a = ansiQuote(a)
		case a == "" || strings.ContainsAny(a, " \t\n'\"$`\\|&;<>()*?![]{}#~"):
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

func needsEscapes(a string) bool {
	return strings.Contains(a, strings.Repeat(" ", maxSpaces+1)) || strings.IndexFunc(a, func(r rune) bool { return r != ' ' && !plainRune(r) }) >= 0
}

// ansiQuote writes a as $'...': \n, \t and \r by name, other characters
// that do not show as themselves and the spaces of a long run as \xNN or
// \uXXXX.
func ansiQuote(a string) string {
	var b strings.Builder
	b.WriteString("$'")
	run := 0
	for i, r := range a {
		if r == ' ' {
			if run == 0 {
				run = len(a[i:]) - len(strings.TrimLeft(a[i:], " "))
			}
			if run > maxSpaces {
				b.WriteString(`\x20`)
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		run = 0
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\\' || r == '\'':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == utf8.RuneError:
			b.WriteString(`\uFFFD`)
		case plainRune(r):
			b.WriteRune(r)
		case r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			fmt.Fprintf(&b, `\U%08X`, r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}
