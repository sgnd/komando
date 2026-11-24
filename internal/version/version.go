// Package version holds komando's version. Releases set it at link time
// with -X github.com/sgnd/komando/internal/version.Version (the Makefile).
package version

import (
	"runtime/debug"
	"strings"
)

var Version = "dev"

func init() {
	if Version == "dev" {
		// `go install ...@v1.2.3` records the module version in the binary
		if bi, ok := debug.ReadBuildInfo(); ok && isRelease(bi.Main.Version) {
			Version = bi.Main.Version
		}
	}
}

// isRelease reports whether a module version is a real tag (not a local or
// pseudo version).
func isRelease(v string) bool {
	return strings.HasPrefix(v, "v") && !strings.HasPrefix(v, "v0.0.0-") && !strings.Contains(v, "+")
}
