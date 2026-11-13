package cli

import (
	"strings"
	"testing"
)

// The audit log's os_user is the account komando runs as, on every
// system: Windows has no uid (os.Getuid is -1 there), so it must not read
// "uid -1".
func TestOSUser(t *testing.T) {
	if u := osUser(); u == "" || u == "unknown" || strings.HasPrefix(u, "uid -") {
		t.Fatalf("osUser() = %q", u)
	}
}
