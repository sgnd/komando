package cli

import (
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// toolSafe reports a program under the Windows system or Program Files folders,
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

// windowsDir is the Windows folder as Windows names it, never SystemRoot
// from the environment, which the caller sets.
func windowsDir() string {
	d, err := windows.GetWindowsDirectory()
	if err != nil {
		return ""
	}
	return d
}

// windowsToolDirs are the system folders and the Program Files folders, as
// Windows names them for this computer.
// Of the Windows folder only System32 and SysWOW64 count: Temp, Tasks
// and others under it can be written by every user.
var windowsToolDirs = sync.OnceValue(func() []string {
	var dirs []string
	if d := windowsDir(); d != "" {
		dirs = append(dirs, filepath.Join(d, "System32"), filepath.Join(d, "SysWOW64"))
	}
	// X64 is the 64-bit folder also for a 32-bit komando (an error on a
	// 32-bit Windows, where it does not exist)
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86, windows.FOLDERID_ProgramFilesX64} {
		if d, err := windows.KnownFolderPath(id, 0); err == nil && d != "" {
			dirs = append(dirs, d)
		}
	}
	return dirs
})
