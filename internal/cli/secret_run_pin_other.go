//go:build !linux

package cli

import (
	"os"
	"os/exec"
)

// pinProgram checks once more that the program is the file komando
// checked. Without /proc there is no way to run an open file, so a rename
// in the moment before the start is still possible; the approval window
// says when the program's folder is one any program of the user can write.
func pinProgram(c *exec.Cmd, checked os.FileInfo) (func(), error) {
	fi, err := os.Stat(c.Path)
	if err != nil || !sameFile(checked, fi) {
		return nil, os.ErrNotExist
	}
	return func() {}, nil
}
