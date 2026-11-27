package store

import (
	"strconv"
	"strings"
)

// What a person does when the move to format 3 stops on a field of the
// store (C558). The move and `komando doctor --dry-run` give the same
// steps, so a person can make the fix before updating.

// LastFormat2Release is the newest komando release that opens a store of
// format 2, where a field that the move cannot take is fixed. It is the
// one place the version is spelled: raise it when a newer v0.17 release
// ships (TestLastFormat2ReleaseSpelledOnce).
const LastFormat2Release = "v0.17.4"

// installFormat2 is the install line of docs/features/install.md (macOS
// and Linux) for LastFormat2Release.
const installFormat2 = "curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/sgnd/komando/" +
	LastFormat2Release + "/install.sh | KOMANDO_VERSION=" + LastFormat2Release + " sh"

// getFormat2 is the first step: which release, and how to install it.
const getFormat2 = "install komando " + LastFormat2Release + ", the last release that opens this store: " + installFormat2 +
	" (on Windows: komando_windows_amd64.zip of " + LastFormat2Release + " from https://github.com/sgnd/komando/releases)"

// outsideLoginWhy is why the move stops on a login field that names an
// outside store (C547), never the reference itself.
func outsideLoginWhy(provider string) string {
	return "names an outside store (" + provider + "), which a login no longer reads"
}

// fixSteps are the steps for the fields the plan cannot move: outside is
// whether one names an outside store for a login, other whether any other
// field stops the move.
func fixSteps(outside, other bool) []string {
	steps := []string{getFormat2}
	if outside {
		steps = append(steps, "there, for each field that names an outside store: save the secret with `komando secret set NAME`, "+
			"then point the field at it, for example `komando host edit HOST --password-ref secret:<NAME>`")
	}
	if other {
		steps = append(steps, "there, fix each other field listed")
	}
	last := "then run `komando update` again"
	if outside {
		last += "; the move makes each saved secret credential:NAME"
	}
	return append(steps, last)
}

// numbered is the steps on one line: "1. ... 2. ...".
func numbered(steps []string) string {
	parts := make([]string, len(steps))
	for i, s := range steps {
		parts[i] = strconv.Itoa(i+1) + ". " + s
	}
	return strings.Join(parts, " ")
}
