package cli

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/vault"
)

// O16: `cluster run TARGET -- cp POD:PATH DST` wrote a pod's files here as
// they were, for an AI agent too: no secret-file guard, no masking, and
// the whole tar stream in memory with no limit. It now follows the SFTP
// download's rules, checked before anything is written.
func TestPodCopyAsADownload(t *testing.T) {
	invHome(t)
	saved := tcl.out
	tcl.out = &out.Printer{Format: "json", W: tcl.out.W, Start: time.Now()} // the vault values are read once per printer
	t.Cleanup(func() { tcl.out = saved })
	const v = "pod-db-password-90210"
	if err := vault.Set("db", v); err != nil {
		t.Fatal(err)
	}
	tcl.out.Secrets = vaultValues
	mk := func(files map[string]string) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		tw.WriteHeader(&tar.Header{Name: "app/", Typeflag: tar.TypeDir, Mode: 0o755})
		for n, body := range files {
			tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
			tw.Write([]byte(body))
		}
		tw.Close()
		return b.Bytes()
	}
	stopCode := func(err error) string {
		var ke *kctlError
		if errors.As(err, &ke) && ke.stop != nil {
			return ke.stop.Code
		}
		return ""
	}
	empty := func(dir string) {
		t.Helper()
		if ents, _ := os.ReadDir(dir); len(ents) > 0 {
			t.Errorf("a refused copy wrote %s", ents[0].Name())
		}
	}

	asAgent(t, false, false)
	tcl.out.Mask = true
	t.Cleanup(func() { tcl.out.Mask = false })

	dst := t.TempDir()
	if err := untarTo(tcl, mk(map[string]string{"app/a.txt": "ok", "app/.env": "DB=" + v}), dst, "app"); stopCode(err) != "SENSITIVE_FILE" {
		t.Errorf("a secret file by name: %v", err)
	}
	empty(dst)
	bin := "\x00\x01ELF" + v
	if err := untarTo(tcl, mk(map[string]string{"app/a.txt": "ok", "app/tool.bin": bin}), dst, "app"); stopCode(err) != "SENSITIVE_FILE" {
		t.Errorf("a binary file with a vault value: %v", err)
	}
	empty(dst)
	if err := untarTo(tcl, mk(map[string]string{"app/config.yml": "password: " + v + "\n"}), dst, "app"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "config.yml")); strings.Contains(string(b), v) || !strings.Contains(string(b), "[secret:db]") {
		t.Errorf("an agent's copy is not masked: %q", b)
	}

	// a person gets the file as it is
	noAgent(t)
	tcl.out.Mask = false
	pdst := t.TempDir()
	if err := untarTo(tcl, mk(map[string]string{"app/.env": "DB=" + v}), pdst, "app"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(pdst, ".env")); string(b) != "DB="+v {
		t.Errorf("a person's copy changed: %q", b)
	}

	// memory: the stream stops at the limit
	cb := &capBuffer{max: 8}
	if n, err := cb.Write([]byte("12345")); n != 5 || err != nil {
		t.Fatal(n, err)
	}
	if _, err := cb.Write([]byte("6789")); err == nil || !cb.over || cb.Len() != 5 {
		t.Errorf("past the limit: %v over=%v len=%d", err, cb.over, cb.Len())
	}
}
