package cli

import (
	"os"
	"path/filepath"
	"strings"
)

// toolSafe reports a program under the Windows or Program Files folders,
// which a user's programs cannot change without an administrator.
func toolSafe(p string) bool {
	for _, v := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)"} {
		d := os.Getenv(v)
		if d == "" {
			continue
		}
		if rel, err := filepath.Rel(d, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}
