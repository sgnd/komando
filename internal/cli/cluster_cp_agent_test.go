package cli

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// podTar is a tar stream as tar in a container writes it: name -> body
// (a name ending in / is a folder).
func podTar(es ...[2]string) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		if strings.HasSuffix(e[0], "/") {
			tw.WriteHeader(&tar.Header{Name: e[0], Typeflag: tar.TypeDir, Mode: 0o755})
			continue
		}
		tw.WriteHeader(&tar.Header{Name: e[0], Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e[1]))})
		tw.Write([]byte(e[1]))
	}
	tw.Close()
	return b.Bytes()
}

// A copy from a pod reaches an AI agent the way download does: a file
// named like a secret is left out, a text file is saved with secret
// values as [hidden], and nothing is left half written.
func TestPodCopyForAgents(t *testing.T) {
	asAgent(t, false, false)
	saved := out.P.Mask
	t.Cleanup(func() { out.P.Mask = saved })
	out.P.Mask = true
	dst := filepath.Join(t.TempDir(), "app")
	tarball := podTar([2]string{"app/", ""}, [2]string{"app/redis.conf", "bind 0.0.0.0\nrequirepass hunter2pass\n"},
		[2]string{"app/.env", "DB_PASSWORD=hunter2pass\n"}, [2]string{"app/readme.txt", "hello\n"})
	if err := untarTo(tarball, dst, "app"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "redis.conf")); strings.Contains(string(b), "hunter2pass") || !strings.Contains(string(b), "requirepass [hidden]") {
		t.Errorf("redis.conf: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dst, ".env")); err == nil {
		t.Error(".env was copied for an agent")
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "readme.txt")); string(b) != "hello\n" {
		t.Errorf("readme.txt: %q", b)
	}
	if l := leftovers(t, dst); len(l) > 0 {
		t.Errorf("temporary files left: %v", l)
	}
	// one file named like a secret stops before anything is read
	if err := sensitiveCopyOK("/srv/app/.env"); err == nil || !strings.Contains(err.Error(), "holds secrets") {
		t.Errorf("name guard: %v", err)
	}
}

// A person gets the files as they are.
func TestPodCopyForAPerson(t *testing.T) {
	resetApproval() // who runs komando is read again: a person here
	t.Cleanup(resetApproval)
	saved := out.P.Mask
	t.Cleanup(func() { out.P.Mask = saved })
	out.P.Mask = false
	dst := filepath.Join(t.TempDir(), "app")
	if err := untarTo(podTar([2]string{"app/", ""}, [2]string{"app/.env", "DB_PASSWORD=hunter2pass\n"}), dst, "app"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, ".env")); string(b) != "DB_PASSWORD=hunter2pass\n" {
		t.Errorf(".env: %q", b)
	}
}

// The tar from a pod is read through memory, so it is capped.
func TestPodCopyIsCapped(t *testing.T) {
	w := &capWriter{max: 10}
	if _, err := w.Write(make([]byte, 11)); err == nil || !w.capped {
		t.Errorf("err %v capped %v", err, w.capped)
	}
}
