package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

// replayFile is the content of p on the replay server's SFTP tree.
func replayFile(t *testing.T, rs *replayServer, p string) string {
	t.Helper()
	r, err := rs.sftp.FileGet.Fileread(sftp.NewRequest("Get", p))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(io.NewSectionReader(r, 0, 1<<20))
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return string(b)
}

// Audit E1-3: the marker of format 2 ({{secret:NAME}}) in text for a file
// on a server is refused with a usage error that names {{credential:NAME}}.
// It never passes as literal text: nothing reaches the server.
func TestOldSecretMarkerRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"fs write", []string{"fs", "write", "dev", "/etc/app.env", "--content", "DB={{secret:db-pass}}\n"}},
		{"fs write, spaces in the marker", []string{"fs", "write", "dev", "/etc/app.env", "--content", "DB={{ secret:db-pass }}\n"}},
		{"fs replace", []string{"fs", "replace", "dev", "/etc/app.env", "--old", "OLD", "--new", "DB={{secret:db-pass}}"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := startReplayServerWith(t, map[string]string{"/etc/app.env": "OLD\n"})
			e := wantCode(t, "BAD_REFERENCE", tc.args...)
			if !strings.Contains(e.Hint, "{{credential:db-pass}}") {
				t.Fatalf("hint %q does not name {{credential:db-pass}}", e.Hint)
			}
			if got := replayFile(t, rs, "/etc/app.env"); got != "OLD\n" {
				t.Fatalf("the file changed to %q", got)
			}
			if len(rs.execs) != 0 {
				t.Fatalf("the server ran %q", rs.execs)
			}
		})
	}
}
