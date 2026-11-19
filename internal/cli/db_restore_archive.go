package cli

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/sgnd/komando/internal/out"
)

// pg_dump tar (-Ft) and directory (-Fd) archives are refused by name:
// komando checks only custom archives (-Fc) and plain SQL (C135).

// isTar: head is the start of a tar file (a ustar header). Any tar is
// refused, so one whose first member is not toc.dat gets a tar message, not
// an SQL error.
func isTar(head []byte) bool {
	return len(head) >= 512 && bytes.Equal(head[257:262], []byte("ustar"))
}

// tarKind names the tar for the refusal: toc.dat first is what pg_dump -Ft
// writes (pg_backup_tar.c).
func tarKind(head []byte) string {
	name, _, _ := bytes.Cut(head[:100], []byte{0})
	if string(name) == "toc.dat" {
		return "tar archive (pg_dump -Ft)"
	}
	return "tar file"
}

// isPGDirArchive: path is a folder holding toc.dat, as pg_dump -Fd makes.
func isPGDirArchive(path string, fi os.FileInfo) bool {
	if !fi.IsDir() {
		return false
	}
	toc, err := os.Stat(filepath.Join(path, "toc.dat"))
	return err == nil && toc.Mode().IsRegular()
}

func otherPGArchive(from, format string) error {
	return out.Errf(out.ExitUsage, "USAGE",
		"dump it again as a custom archive (pg_dump -Fc, what `komando db dump` makes) or plain SQL (pg_dump -Fp)",
		"%s is a %s, which komando cannot check; it restores custom archives and plain SQL only", from, format)
}
