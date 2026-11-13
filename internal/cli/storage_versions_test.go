package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// A storage conn that keeps no versions komando can see says so.
func TestVersionsOnlyOnS3(t *testing.T) {
	var b storex.Bucket = struct{ storex.Bucket }{}
	if _, err := versioned(&store.Conn{Name: "files", Kind: "sftp"}, b); toErr(err).Code != "NOT_SUPPORTED" {
		t.Errorf("sftp: %v", err)
	}
	invHome(t)
	wantCode(t, "USAGE", "storage", "rm", "x", "--prefix", "daily/", "--all-versions")
}
