package cli

import (
	"fmt"
	"path"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// commandWords is the remote command of exec and job start: -c, or the
// words after --, never both (one would be dropped without a word).
func commandWords(cmdStr string, words []string, verb string) (string, error) {
	if cmdStr != "" {
		if len(words) > 0 {
			return "", out.Usage("give the command with -c or after --, not both")
		}
		return cmdStr, nil
	}
	if err := komandoFlagsAfterDash(verb, words); err != nil {
		return "", err
	}
	return strings.Join(words, " "), nil
}

// komandoFlagsAfterDash refuses words after -- that end with komando's
// own safety flags (exec web1 -- uptime --dry-run): after -- every word is
// part of the remote command, so the flag would not stop the real run.
// Other global flags in between (-o json, -P 2) are moved with them.
// verb is how the command line starts ("exec web1"), for the hint.
func komandoFlagsAfterDash(verb string, words []string) error {
	valued := map[string]bool{"-o": true, "--output": true, "-P": true, "--parallel": true, "--timeout": true, "--connect-timeout": true, "--max-output": true, "--host-key-policy": true}
	plain := map[string]bool{"--pretty": true, "--read-only": true, "--stream": true, "--fail-fast": true}
	// not --yes or -y: tools on the server take them (yum update -y), and
	// komando sending them on stops nothing, a protected server still asks
	safety := map[string]bool{"--dry-run": true, "--allow-dangerous": true, "--reveal": true}
	cut, found := len(words), false
scan:
	for cut > 0 {
		w := words[cut-1]
		name, _, _ := strings.Cut(w, "=")
		switch {
		case safety[w]:
			found = true
			cut--
		case plain[w] || strings.HasPrefix(w, "--") && valued[name] && strings.Contains(w, "="):
			cut--
		case cut >= 2 && valued[words[cut-2]]:
			cut -= 2
		default:
			break scan
		}
	}
	if !found {
		return nil
	}
	flags, command := strings.Join(words[cut:], " "), strings.Join(words[:cut], " ")
	return out.Errf(out.ExitUsage, "USAGE",
		fmt.Sprintf("write `komando %s %s -- %s`; if the command on the server takes these flags itself, give it as one string: -c %s", verb, flags, command, sshx.Q(strings.Join(words, " "))),
		"%s after -- would be sent to the server as part of the command, not read by komando; komando's flags go before --", flags)
}

// shebangInterpreter is the interpreter a script's #! line names, with
// its arguments ("bash -e"), or sh. Through env, the program after env's
// own options and VAR=value words is the interpreter
// (#!/usr/bin/env -S python3 -u gives "python3 -u").
func shebangInterpreter(body string) string {
	first, _, _ := strings.Cut(body, "\n")
	if !strings.HasPrefix(first, "#!") {
		return "sh"
	}
	f := strings.Fields(strings.TrimPrefix(first, "#!"))
	switch i := envProgram(f); {
	case len(f) == 0 || i == len(f):
		return "sh"
	case i > 0:
		return strings.Join(f[i:], " ")
	}
	return strings.Join(f, " ")
}

// envProgram is the index of the program env runs in the words f (an env
// command line), len(f) when there is none, or 0 when f does not start
// with env.
func envProgram(f []string) int {
	if len(f) == 0 || path.Base(f[0]) != "env" {
		return 0
	}
	i := 1
	for i < len(f) {
		w := f[i]
		switch {
		case w == "-u" || w == "--unset" || w == "-C" || w == "--chdir" || w == "-P":
			i += 2 // these take a value
		case w == "--":
			return min(i+1, len(f))
		case strings.HasPrefix(w, "-") || strings.Contains(w, "="):
			i++
		default:
			return i
		}
	}
	return len(f)
}
