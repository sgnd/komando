package rundir

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Check: the folder is in this user's own LocalAppData, which other users
// cannot open; a link (a reparse point) is still refused.
func Check(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("komando's run folder %s is a link or a file, not a folder; remove it and komando makes a new one", dir)
	}
	return nil
}

// Free is the space on dir's drive this user may write.
func Free(dir string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, nil, nil); err != nil {
		return 0, err
	}
	return free, nil
}
