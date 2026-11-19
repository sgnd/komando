//go:build !linux

package cli

import "os/exec"

// endWithKomando does nothing here: only Linux can end a program when its
// parent dies. docs/features/secrets.md says so.
func endWithKomando(c *exec.Cmd) {}
