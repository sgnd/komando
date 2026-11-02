package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

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
// they run commands in. KOMANDO_AGENT is for any other agent.
var agentVars = []struct{ env, name string }{
	{"CLAUDECODE", "Claude Code"},
	{"GEMINI_CLI", "Gemini CLI"},
	{"CODEX_SANDBOX", "Codex"},
	{"CODEX_THREAD_ID", "Codex"},
	{"CURSOR_AGENT", "Cursor"},
	{"KOMANDO_AGENT", "An AI agent"},
	{"AI_AGENT", "An AI agent"},
}

// agentName is the AI agent running komando, or "" for a person or a script.
func agentName() string {
	for _, a := range agentVars {
		if v := os.Getenv(a.env); v != "" && v != "0" && v != "false" {
			return a.name
		}
	}
	return ""
}

func isAgent() bool { return agentName() != "" }

var approval struct {
	sync.Mutex
	asked, allowed bool
	why            string // why there was no yes, for the error hint
}

func resetApproval() {
	approval.Lock()
	defer approval.Unlock()
	approval.asked, approval.allowed, approval.why = false, false, ""
}

func allowedByPerson() bool {
	approval.Lock()
	defer approval.Unlock()
	return approval.allowed
}

// yesOK reports whether --yes counts. dangerOK and revealOK do the same for
// --allow-dangerous and --reveal. Call them only where the flag would let
// something through, so an agent's window appears only when it matters.
func yesOK() bool    { return g.yes && personAllows("--yes") }
func dangerOK() bool { return g.allowDangerous && personAllows("--allow-dangerous") }
func revealOK() bool { return g.reveal && personAllows("--reveal") }

// personAllows: a person or a script used the flag themselves; for an AI
// agent a person must allow it on the screen. One answer covers the whole
// command, so a command that passes two checks asks once.
func personAllows(flag string) bool {
	if !isAgent() || g.dryRun {
		return true
	}
	approval.Lock()
	defer approval.Unlock()
	if approval.asked {
		return approval.allowed
	}
	approval.asked = true
	text := fmt.Sprintf("%s wants komando to run:\n\n%s\n\n%s skips one of komando's safety stops (%s).\n\nAllow this once?",
		agentName(), clip(commandLine(), 600), flag, flagMeaning[flag])
	allowed, shown := askOnScreen(text)
	switch {
	case allowed:
		approval.allowed = true
	case shown:
		approval.why = "denied"
	default:
		approval.why = "no-screen"
	}
	return approval.allowed
}

var flagMeaning = map[string]string{
	"--yes":             "a change to a protected server or conn, or to a safety setting",
	"--allow-dangerous": "an action that can delete or break things",
	"--reveal":          "show passwords, keys and tokens that komando hides from AI agents",
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
	case "no-screen":
		e.Hint = "komando could not show the user an approval window (no screen). Ask the user to run this exact command in their own terminal: " + commandLine()
	default:
		if e.Code == "REVEAL_NEEDS_HUMAN" {
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

// commandLine is this command as typed, quoted where needed.
func commandLine() string {
	parts := []string{"komando"}
	for _, a := range os.Args[1:] {
		if a == "" || strings.ContainsAny(a, " \t\n'\"$`\\|&;<>()*?![]{}#~") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
