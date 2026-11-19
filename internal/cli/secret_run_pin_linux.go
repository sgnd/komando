package cli

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
)

// pinProgram makes c start the file komando checked: it opens the program,
// checks it is still that file, and runs it through the open file
// (/proc/self/fd/N), so a rename after the check cannot swap it.
func pinProgram(c *exec.Cmd, checked os.FileInfo) (func(), error) {
	f, err := os.Open(c.Path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !sameFile(checked, fi) {
		f.Close()
		return nil, errors.Join(err, errors.New("the program changed"))
	}
	c.ExtraFiles = append(c.ExtraFiles, f)
	c.Path = "/proc/self/fd/" + strconv.Itoa(2+len(c.ExtraFiles))
	return func() { f.Close() }, nil
}
