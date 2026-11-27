package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/testhome"
)

// C213: an upload hashes the bytes as they are sent. When the window
// approved other bytes (the file changed after it was shown), the send
// stops, the file on the server stays as it was, and the refusal is in
// the audit log.
func uploadSwapped(t *testing.T) (string, error) {
	setHome(t, t.TempDir())
	setCallerEnv(t, "CLAUDECODE", "1")
	sc := localSFTP(t)
	src := filepath.Join(t.TempDir(), "app.conf")
	if err := os.WriteFile(src, []byte("listen 8080\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	setBody(tcl, newBody("the file "+src, []byte("listen 8080\n"), true)) // what the window showed
	t.Cleanup(func() { tcl.body = nil; tcl.out.Reset() })
	if err := os.WriteFile(src, []byte("listen 9999\n"), 0o644); err != nil { // swapped after the yes
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "app.conf")
	if err := os.WriteFile(dst, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := upload(tcl, context.Background(), nil, sc, src, dst, cpOpts{})
	return dst, err
}

func TestUploadChangedFileStops(t *testing.T) {
	_, err := uploadSwapped(t)
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "FILE_CHANGED" {
		t.Fatalf("want FILE_CHANGED, got %v", err)
	}
}

func TestUploadChangedFileLeavesTheServerFile(t *testing.T) {
	dst, _ := uploadSwapped(t)
	if got := read(t, dst); got != "old\n" {
		t.Errorf("server file: %q, want it unchanged", got)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(dst), ".komando-*"))
	if len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestUploadChangedFileIsAudited(t *testing.T) {
	uploadSwapped(t)
	a := auditText(t)
	if !strings.Contains(a, `"command":"upload"`) || !strings.Contains(a, `"blocked":"FILE_CHANGED"`) {
		t.Errorf("audit: %s", a)
	}
}

// Every upload, a person's too, records the hash of the bytes it sent.
func TestUploadRecordsTheSentHash(t *testing.T) {
	setHome(t, t.TempDir())
	sc := localSFTP(t)
	src := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(src, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcl.body = nil; tcl.out.Reset() })
	if _, err := upload(tcl, context.Background(), nil, sc, src, filepath.Join(t.TempDir(), "a.txt"), cpOpts{}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hello\n"))
	if tcl.body == nil || tcl.body.sha256() != hex.EncodeToString(sum[:]) {
		t.Errorf("recorded body: %+v", tcl.body)
	}
}

// The window's record of the file is matched on the file, not on how the
// path was spelled: whatever spelling the agent gives (~, ./, a symlink,
// extra slashes), a file that changed after the window stops; the check
// is never skipped.
func TestUploadCheckDoesNotDependOnSpelling(t *testing.T) {
	setHome(t, t.TempDir())
	home := filepath.Dir(inventory.ExpandHome("~/x.sh"))
	if err := os.MkdirAll(testhome.Path(t, home), 0o755); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	sc := localSFTP(t)
	src := filepath.Join(home, "x.sh")
	link := filepath.Join(t.TempDir(), "link.sh")
	if err := os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(wd); tcl.body = nil; tcl.out.Reset() })
	if err := os.Chdir(home); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, shown, sent string }{
		{"tilde", "~/x.sh", src},
		{"dot-relative", "./x.sh", src},
		{"symlink", link, src},
		{"extra slashes", home + "//./x.sh", src},
		{"trailing slash", src, src + "/"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(testhome.Path(t, src), []byte("echo shown\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			tcl.body = nil
			if err := noteUpload(tcl, c.shown, nil); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(testhome.Path(t, src), []byte("echo swapped\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(t.TempDir(), "x.sh")
			if _, err := upload(tcl, context.Background(), nil, sc, c.sent, dst, cpOpts{}); err == nil {
				t.Fatalf("the swapped file was sent: %q", read(t, dst))
			}
		})
	}
}

// An agent's one-file upload with no window record is refused, not sent
// unchecked.
func TestUploadAgentWithoutWindowRecordRefuses(t *testing.T) {
	setHome(t, t.TempDir())
	setCallerEnv(t, "CLAUDECODE", "1")
	sc := localSFTP(t)
	t.Cleanup(func() { tcl.body = nil; tcl.out.Reset() })
	src := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(src, []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tcl.body = nil
	_, err := upload(tcl, context.Background(), nil, sc, src, filepath.Join(t.TempDir(), "a.txt"), cpOpts{})
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "FILE_CHANGED" {
		t.Fatalf("want FILE_CHANGED, got %v", err)
	}
}
