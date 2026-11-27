package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// What body_sha256 covers, as docs/features/safety.md says, for the
// commands that do not send the hashed bytes as they are.

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fs write: the content before {{credential:NAME}} values are filled in (a
// hash of the filled-in bytes would describe the secret).
func TestBodySHA256FsWriteIsBeforeSecrets(t *testing.T) {
	setHome(t, t.TempDir())
	t.Cleanup(func() { tcl.body = nil; tcl.out.Reset() })
	b := []byte("DB_PASSWORD={{credential:db}}\n")
	p := filepath.Join(t.TempDir(), "app.env")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fsWriteInput(tcl, false, "", p); err != nil {
		t.Fatal(err)
	}
	if tcl.body == nil || tcl.body.sha256() != sumHex(b) {
		t.Errorf("body_sha256 is not of the file as written on disk: %+v", tcl.body)
	}
}

// upload of a folder: a hash of the list of its files (name, size and
// SHA-256 of each), not of any one file's bytes.
func TestBodySHA256UploadFolderIsTheList(t *testing.T) {
	setHome(t, t.TempDir())
	setCallerEnv(t, "CLAUDECODE", "1")
	t.Cleanup(func() { tcl.body = nil; tcl.out.Reset() })
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := noteUpload(tcl, dir, nil); err != nil {
		t.Fatal(err)
	}
	list := fmt.Sprintf("a.txt  3 bytes  %s\n", sumHex([]byte("hi\n")))
	if tcl.body == nil || tcl.body.sha256() != sumHex([]byte(list)) {
		t.Errorf("body_sha256 is not of the file list %q: %+v", list, tcl.body)
	}
}

// cluster apply on Kubernetes: a hash of the YAML file, comments and all,
// though each object is sent as JSON.
func TestBodySHA256ClusterApplyIsTheYAML(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "kube", "kubernetes://127.0.0.1:2")
	y := []byte("# the app\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n")
	p := filepath.Join(t.TempDir(), "app.yaml")
	if err := os.WriteFile(p, y, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcl.body = nil })
	invRun(t, "cluster", "apply", "kube", "--file", p, "--dry-run")
	if tcl.body == nil || tcl.body.sha256() != sumHex(y) {
		t.Errorf("body_sha256 is not of the YAML file: %+v", tcl.body)
	}
}
