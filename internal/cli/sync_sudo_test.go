package cli

import (
	"strings"
	"testing"
)

// sync --sudo writes as root on servers only: not to storage, and not on
// the way down (download --sudo reads one file as root).
func TestSyncSudoWhere(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@10.0.0.5")
	dir := t.TempDir()
	if e := wantCode(t, "USAGE", "sync", "web1:/etc/nginx", dir, "--sudo"); e.Hint == "" && e.Message == "" {
		t.Error("no message")
	}
	if _, e := invRun(t, "sync", "web1:/etc/nginx", dir, "--sudo"); e == nil || !strings.Contains(e.Message, "download") {
		t.Errorf("down: %+v", e)
	}
}
