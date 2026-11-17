package cli

import (
	"path/filepath"
	"strings"
)

// toolSafe reports a program under the Windows or Program Files folders,
// which a user's programs cannot change without an administrator.
func toolSafe(cl *call, p string) bool {
	for _, v := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)"} {
		d := cl.getenv(v)
		if d == "" {
			continue
		}
		if rel, err := filepath.Rel(d, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}
