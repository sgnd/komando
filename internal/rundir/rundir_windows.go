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

// create opens path CREATE_NEW (an existing name or link is never opened)
// and shares it for reading only. os.OpenFile would share it for writing
// too, so another handle could write into the bytes komando checked; here
// no other handle may write, truncate, rename or delete the file while
// komando holds it. DELETE_ON_CLOSE removes it when the handle closes,
// also when komando ends without its own clean-up.
func create(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
		windows.FILE_SHARE_READ, nil, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
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
