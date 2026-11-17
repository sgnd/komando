package cli

import (
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// toolSafe reports a program under the Windows or Program Files folders,
// which a user's programs cannot change without an administrator. The
// folders come from Windows itself, never from SystemRoot or ProgramFiles
// in the environment, which the caller sets: an agent's
// `ProgramFiles=C:\Users\me\tools` would make its own program count as
// safe.
func toolSafe(_ *call, p string) bool {
	for _, d := range windowsToolDirs() {
		if rel, err := filepath.Rel(d, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}

// windowsToolDirs are the Windows folder and the Program Files folders, as
// Windows names them for this computer.
var windowsToolDirs = sync.OnceValue(func() []string {
	var dirs []string
	if d, err := windows.GetWindowsDirectory(); err == nil && d != "" {
		dirs = append(dirs, d)
	}
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		if d, err := windows.KnownFolderPath(id, 0); err == nil && d != "" {
			dirs = append(dirs, d)
		}
	}
	return dirs
})
