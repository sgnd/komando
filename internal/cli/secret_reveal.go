package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// Showing a secret value again (`secret show --reveal`, `key show
// --reveal`) is for a person only (docs/design/principles.md):
//   - an AI agent, or a key through ssh-gate, never gets the value, not
//     even with the person's yes: it references secret:NAME instead;
//   - a person at a terminal gets it, as they typed the command;
//   - any other caller (the Komando Mac app, which runs komando without a
//     terminal) gets it only after the person says yes in komando's own
//     window, with the approval code when that is on. Where no window can
//     ask, it stops with REVEAL_NEEDS_HUMAN.
//
// Every reveal is in the audit log (how the person allowed it, and the
// programs that started komando), and so is every refusal, with the name
// of what was asked for. The value itself never is.

// revealNever are the commands whose --reveal an AI agent never gets: the
// root's masking does not ask the person for them.
var revealNever = map[string]bool{"secret.show": true, "key.show": true}

// revealGate says how the person allowed showing what (for example
// secret:db-pass): "terminal" or "window". It is "" in a dry run, which
// shows no value and asks nobody. cmdName and field name the audit line
// of a refusal (secret.show, "secret": NAME).
func revealGate(cl *call, cmdName, field, name, what string) (string, error) {
	refuse := func(e *out.Error) (string, error) {
		audit(cl, nil, cmdName, nil, "", false, map[string]any{field: name, "blocked": e.Code, "message": e.Message})
		return "", e
	}
	if cl.isAgent() {
		return refuse(needsHuman(cmdName, name, false))
	}
	if cl.flags.dryRun {
		return "", nil
	}
	if cl.interactive() {
		return "terminal", nil
	}
	allowed, shown := askReveal(cl, what)
	switch {
	case allowed:
		return "window", nil
	case shown && cl.sess.Window().Why == "no-answer":
		return refuse(out.Errf(out.ExitPolicy, "DECLINED", "nobody answered komando's window within 2 minutes; run it again to be asked again",
			"not run: the person said no; nothing was changed").NoFlag())
	case shown:
		return refuse(out.Errf(out.ExitPolicy, "DECLINED", "run it again to be asked again",
			"not run: the person said no; nothing was changed").NoFlag())
	}
	return refuse(needsHuman(cmdName, name, true))
}

// needsHuman is REVEAL_NEEDS_HUMAN for cmdName (secret.show, key.show) and
// name: for an AI agent, or where no window could ask (noScreen).
func needsHuman(cmdName, name string, noScreen bool) *out.Error {
	e := out.Errf(out.ExitPolicy, "REVEAL_NEEDS_HUMAN",
		"ask a person to run `komando secret show "+name+" --reveal` in a terminal; to use the secret in a command, reference it (secret:"+name+") instead",
		"--reveal only works for a person at a terminal")
	run := "`komando " + strings.ReplaceAll(cmdName, ".", " ") + " " + name + " --reveal`"
	switch {
	case noScreen:
		e.Hint = "komando could not ask in a window here (no screen, or a Linux or BSD desktop without the approval code); run " + run + " in a terminal"
	case cmdName != "secret.show":
		e.Hint = "ask a person to run " + run + " in a terminal; an AI agent never gets a private key"
	}
	return e
}

// askReveal asks the person in komando's window whether to show what. A
// Linux or BSD desktop gets no click-only window (clickForgeable): there
// another program could press "Allow once", so it needs the approval code.
func askReveal(cl *call, what string) (allowed, shown bool) {
	if cl.ask == nil && clickForgeable(cl) && approvalCodeSecret() == nil {
		return false, false
	}
	line := commandLine(cl)
	if unshowable(line) != "" {
		line = strconv.QuoteToASCII(line)
	}
	text := "A program wants komando to show the value of " + what + ":\n\n" + line + "\n\n"
	if from := startedFrom(cl); from != "" {
		text += "Started from: " + from + "\n\n"
	}
	text += "Show it once? Allow this only if you asked for it just now: the value goes to the program that asked."
	sess := cl.sess
	sess.Lock()
	defer sess.Unlock()
	sess.SetAsked(false)
	sess.SetGaveUp(false)
	allowed, shown = cl.askPerson(text)
	gaveUp := tookGaveUp(text)
	switch {
	case shown && gaveUp:
		sess.SetWhy("no-answer")
	case shown && !allowed && sess.Window().Why == "":
		sess.SetWhy("denied")
	}
	return allowed, shown
}

// startedFrom names the programs that started komando, nearest first
// ("zsh ← iTerm2", "Komando"), so the window and the audit log say who
// asked. A program names itself, so this is a hint for the person, not
// proof. It is "" where it cannot be read (Windows). A test seam: tests
// set another.
var startedFrom = func(cl *call) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	ps := systemTool("ps")
	if ps == "" {
		return ""
	}
	var names []string
	pid := os.Getppid()
	for i := 0; i < 4 && pid > 1; i++ {
		c := exec.Command(ps, "-o", "ppid=", "-o", "comm=", "-p", strconv.Itoa(pid))
		c.Env = cl.environ() // the call's, unlock values out; never nil (nil inherits the process's)
		b, err := c.Output()
		if err != nil {
			break
		}
		f := strings.Fields(strings.TrimSpace(string(b)))
		if len(f) < 2 {
			break
		}
		name := strings.TrimPrefix(filepath.Base(strings.Join(f[1:], " ")), "-") // -zsh: a login shell
		if unshowable(name) != "" {
			name = strconv.QuoteToASCII(name)
		}
		names = append(names, name)
		if pid, err = strconv.Atoi(f[0]); err != nil {
			break
		}
	}
	return strings.Join(names, " ← ")
}

// revealAudit records a value shown to a person: what, how they allowed
// it, and who started komando. Never the value.
func revealAudit(cl *call, cmdName, field, name, via string) {
	rec := map[string]any{field: name, "via": via}
	if from := startedFrom(cl); from != "" {
		rec["started_from"] = from
	}
	audit(cl, nil, cmdName, nil, "", true, rec)
}
