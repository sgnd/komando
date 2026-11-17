package cli

import (
	"strings"
	"testing"
)

// --all-users reports only the users whose file held the key, and those
// whose file could not be changed.
func TestParseRevokeAll(t *testing.T) {
	got := parseRevokeAll("root 0\nagent 2\nops err\nbad line here\nwww 1\n")
	if len(got) != 3 || got[0] != (revokedUser{"agent", 2}) || got[1] != (revokedUser{"ops", -1}) || got[2] != (revokedUser{"www", 1}) || got.total() != 3 {
		t.Errorf("%+v", got)
	}
	s := revokeAllScript("AAAAkey", true)
	if !strings.Contains(s, "getent passwd") || !strings.Contains(s, "su -s /bin/sh") || strings.Contains(s, "grep -vF") {
		t.Errorf("dry script: %s", s)
	}
}

// --user and --all-users do not go together.
func TestKeyRevokeAllUsersFlags(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@10.0.0.5")
	wantCode(t, "USAGE", "key", "revoke", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA x", "web1", "--user", "deploy", "--all-users")
}
