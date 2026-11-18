package cli

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/storex"
	"github.com/sgnd/komando/internal/storex/ftptest"
)

// C124: an FTPS source whose listing of one folder is cut off (the data
// connection closes before TLS is set up, and the server still says 226)
// must stop sync --delete. Read as an empty folder, its files would be
// deleted on the destination.
func TestSyncDeleteStopsOnACutFTPSListing(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	certs := srv.TLS.Certificates
	srv.Close()
	s := ftptest.New(t)
	s.TLS = &tls.Config{Certificates: certs}
	s.Dirs = map[string]string{
		"/":    "-rw-r--r-- 1 u u 3 Nov 07 12:00 top.txt\r\ndrwxr-xr-x 1 u u 0 Nov 07 12:00 sub\r\n",
		"/sub": "-rw-r--r-- 1 u u 3 Nov 07 12:00 a.txt\r\n",
	}
	s.CutData, s.CutDir = "LIST", "/sub"
	tg := s.Target()
	tg.Secure, tg.TLS = true, "skip-verify"
	b, err := storex.OpenFTP(context.Background(), tg, "p", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	dst := t.TempDir()
	writeTree(t, dst, map[string]string{"top.txt": "top", "sub/a.txt": "aaa"})
	tcl.flags.dryRun = false
	r, err := runSync(tcl, context.Background(), bucketSide{b: b}, localSide{tcl, dst}, "files-ftps:", "dst", syncOpts{delete: true})
	if err == nil {
		t.Errorf("sync went on: %+v; want an error", r)
	}
	if _, serr := os.Stat(filepath.Join(dst, "sub/a.txt")); serr != nil {
		t.Errorf("sub/a.txt was deleted: %v", serr)
	}
}
