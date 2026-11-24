package version

import "testing"

// A `go install ...@vX.Y.Z` build takes its version from the module; a
// local or pseudo version must not pass for a release.
func TestIsRelease(t *testing.T) {
	for _, c := range []struct {
		name string
		v    string
		want bool
	}{
		{"tag", "v0.17.1", true},
		{"pre-release tag", "v1.0.0-rc.1", true},
		{"pseudo version", "v0.0.0-20261124101500-bb8c67f20000", false},
		{"dirty build", "v0.17.1+dirty", false},
		{"devel", "(devel)", false},
		{"empty", "", false},
		{"no v", "0.17.1", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := isRelease(c.v); got != c.want {
				t.Errorf("isRelease(%q) = %v, want %v", c.v, got, c.want)
			}
		})
	}
}
