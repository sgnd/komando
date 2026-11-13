//go:build !windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// O13: a download or a sync down takes the server's mode, but a file
// never ends up writable by others here (0777 there is 0755 here).
func TestDownloadModeNotWorldWritable(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ there, here os.FileMode }{
		{0o777, 0o755}, {0o666, 0o644}, {0o640, 0o640}, {0o444, 0o644}, {0o700, 0o700},
	} {
		dst := filepath.Join(dir, "f"+c.there.String())
		if _, _, _, err := fetchFile(context.Background(), strings.NewReader("x"), dst, c.there, time.Time{}, true, nil); err != nil {
			t.Fatal(err)
		}
		if m := mode(t, dst); m != c.here {
			t.Errorf("download of %04o: %04o, want %04o", c.there, m, c.here)
		}
		rel := "s" + c.there.String()
		if err := (localSide{root: dir}).write(context.Background(), rel, strings.NewReader("x"), syncFile{Mode: c.there}); err != nil {
			t.Fatal(err)
		}
		if m := mode(t, filepath.Join(dir, rel)); m != c.here {
			t.Errorf("sync of %04o: %04o, want %04o", c.there, m, c.here)
		}
	}
}
