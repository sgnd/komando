package cli

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

// localTool finds the program name on this computer for a step that hands
// it a secret (a database password, a VPN password), and returns its full
// path, so the program checked is the program run. For an AI agent, a
// program that any program of this user could have put there or changed
// (a folder in PATH it can write, Homebrew's bin, ~/.local/bin) gets the
// secrets only with a person's yes: an agent that puts a fake pg_dump
// first in PATH would otherwise be handed the password it may not read.
func localTool(name string, refs []string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	if p, err = filepath.Abs(p); err != nil {
		return "", err
	}
	var given []string
	for _, r := range refs {
		if r != "" {
			given = append(given, r)
		}
	}
	real, err := filepath.EvalSymlinks(p)
	if len(given) > 0 && (err != nil || !toolSafe(p) || !toolSafe(real)) {
		where := fmt.Sprintf("%s on this computer (a program any program of yours can replace)", p)
		if err := guardSecretUse(given, where); err != nil {
			return "", err
		}
	}
	return p, nil
}
