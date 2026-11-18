package cli

import (
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// toolSafe reports a program that only an administrator can change: it
// lies under the Windows system or Program Files folders, and the file and
// every folder from it up to that folder belong to the system or the
// administrators, and no one else may write them (adminsAlone; the Unix
// check is rootsAlone). An installer may give every user write access to
// its folder under Program Files; such a program does not count. The
// folders come from Windows itself, never from SystemRoot or ProgramFiles
// in the environment, which the caller sets: an agent's
// `ProgramFiles=C:\Users\me\tools` would make its own program count as
// safe.
func toolSafe(_ *call, p string) bool {
	for _, d := range windowsToolDirs() {
		if rel, err := filepath.Rel(d, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return pathAdminsAlone(p, d)
		}
	}
	return false
}

// pathAdminsAlone checks p and every folder above it up to and including
// top with adminsAlone.
func pathAdminsAlone(p, top string) bool {
	for {
		if !adminsAlone(p) {
			return false
		}
		if strings.EqualFold(filepath.Clean(p), filepath.Clean(top)) {
			return true
		}
		up := filepath.Dir(p)
		if up == p {
			return false // never reached top: not under it
		}
		p = up
	}
}

// trustedInstaller is the service that owns Windows' own files.
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// adminSID: the system, the administrators group or TrustedInstaller.
func adminSID(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.String() == trustedInstaller)
}

// writeRights are the rights that let a holder change a file, or add,
// replace or remove files in a folder (FILE_DELETE_CHILD is 0x40).
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | 0x40 |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

// adminsAlone reports whether p belongs to an admin SID and its access
// list lets no one else write it. An entry that only passes down to new
// files (inherit-only) is skipped; a deny entry is not counted in p's
// favour, so a list komando cannot read with certainty counts as unsafe.
// An empty (null) access list lets everyone in.
func adminsAlone(p string) bool {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || !adminSID(owner) {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 ||
			uint32(ace.Mask)&writeRights == 0 {
			continue
		}
		if !adminSID((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return false
		}
	}
	return true
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
