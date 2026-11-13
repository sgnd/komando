package cli

import (
	"context"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// fakeVersioned is a bucket that keeps versions.
type fakeVersioned struct{ storex.Bucket }

func (fakeVersioned) Versions(context.Context, string, int) ([]storex.ObjectVersion, bool, error) {
	return nil, false, nil
}
func (fakeVersioned) RemoveVersion(context.Context, string, string) error { return nil }

// A storage conn that keeps no versions komando can see says so; one that
// does is found inside the wrapper that closes its connection path too.
func TestVersionsOnlyOnS3(t *testing.T) {
	var b storex.Bucket = struct{ storex.Bucket }{}
	if _, err := versioned(&store.Conn{Name: "files", Kind: "sftp"}, b); toErr(err).Code != "NOT_SUPPORTED" {
		t.Errorf("sftp: %v", err)
	}
	if _, err := versioned(&store.Conn{Name: "b", Kind: "s3"}, closeBoth{fakeVersioned{}, func() {}}); err != nil {
		t.Errorf("wrapped S3: %v", err)
	}
	invHome(t)
	wantCode(t, "USAGE", "storage", "rm", "x", "--prefix", "daily/", "--all-versions")
}
