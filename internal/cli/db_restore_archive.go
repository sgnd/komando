package cli

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/sgnd/komando/internal/out"
)

// pg_dump tar (-Ft) and directory (-Fd) archives are refused by name:
// komando checks only custom archives (-Fc) and plain SQL (C135).

// isPGTarArchive: head is the start of a tar file whose first member is
// toc.dat, which pg_dump -Ft writes first (pg_backup_tar.c).
func isPGTarArchive(head []byte) bool {
	if len(head) < 512 || !bytes.Equal(head[257:262], []byte("ustar")) {
		return false
	}
	name, _, _ := bytes.Cut(head[:100], []byte{0})
	return string(name) == "toc.dat"
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
		"%s is a pg_dump %s, which komando cannot check; it restores custom archives and plain SQL only", from, format)
}
