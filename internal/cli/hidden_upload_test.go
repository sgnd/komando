package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// A masked copy saved from fs cat is never uploaded over the real file.
func TestUploadRefusesHiddenValues(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.conf")
	_ = os.WriteFile(clean, []byte("bind 0.0.0.0\n"), 0o600)
	if err := hiddenInLocal(clean); err != nil {
		t.Fatalf("clean file refused: %v", err)
	}
	masked := filepath.Join(dir, "sub", "redis.conf")
	_ = os.MkdirAll(filepath.Dir(masked), 0o755)
	_ = os.WriteFile(masked, []byte("requirepass [hidden]\n"), 0o600)
	for _, p := range []string{masked, dir} {
		if err := hiddenInLocal(p); err == nil {
			t.Errorf("%s: masked file not refused", p)
		}
	}
	ref := filepath.Join(dir, "app.env.tmpl")
	_ = os.WriteFile(ref, []byte("DB=[secret:db_pass]\n"), 0o600)
	if err := hiddenInLocal(ref); err == nil {
		t.Error("[secret:NAME] label not refused")
	}
}

// An AI agent's download is saved the way fs cat shows it; a person's is
// saved as it is.
func TestDownloadMasksSecretsForAgents(t *testing.T) {
	saved := out.P.Mask
	t.Cleanup(func() { out.P.Mask = saved })
	dir := t.TempDir()
	conf := "bind 0.0.0.0\nrequirepass hunter2pass\n"
	bin := "\x00\x01requirepass hunter2pass"

	out.P.Mask = true
	dst := filepath.Join(dir, "agent.conf")
	_, sum, masked, err := fetchFile(context.Background(), strings.NewReader(conf), dst, 0o644, time.Time{}, false, nil)
	got, _ := os.ReadFile(dst)
	if err != nil || !masked || sum != "" || strings.Contains(string(got), "hunter2pass") || !strings.Contains(string(got), "requirepass [hidden]") {
		t.Fatalf("agent download: masked=%v sum=%q err=%v file=%q", masked, sum, err, got)
	}
	if err := hiddenInLocal(dst); err == nil {
		t.Error("the masked copy could be uploaded back")
	}
	dst = filepath.Join(dir, "agent.bin")
	if _, _, masked, _ := fetchFile(context.Background(), strings.NewReader(bin), dst, 0o644, time.Time{}, false, nil); masked {
		t.Error("a binary file was rewritten")
	}
	// sync down: the same masking
	if err := (localSide{root: dir}).write(context.Background(), "sync.conf", strings.NewReader(conf), syncFile{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "sync.conf")); strings.Contains(string(got), "hunter2pass") {
		t.Errorf("sync down kept the password: %q", got)
	}
	if _, err := (agentLocalSide{localSide: localSide{root: dir}}).open(context.Background(), "sync.conf"); err == nil {
		t.Error("sync up would send the masked copy")
	}

	out.P.Mask = false
	dst = filepath.Join(dir, "person.conf")
	_, sum, masked, err = fetchFile(context.Background(), strings.NewReader(conf), dst, 0o644, time.Time{}, false, nil)
	if got, _ := os.ReadFile(dst); err != nil || masked || sum == "" || string(got) != conf {
		t.Fatalf("person download changed: masked=%v err=%v file=%q", masked, err, got)
	}
}

// tmpPeek gives data, then before saying it is done looks at what the
// download's temporary files in dir hold so far.
type tmpPeek struct {
	data []byte
	dir  string
	seen []byte
}

func (r *tmpPeek) Read(b []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(b, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	tmps, _ := filepath.Glob(filepath.Join(r.dir, ".komando-download-*"))
	for _, f := range tmps {
		got, _ := os.ReadFile(f)
		r.seen = append(r.seen, got...)
	}
	return 0, io.EOF
}

// For an AI agent the real text never reaches the disk, not even in the
// download's temporary file; a binary file that holds a vault value is
// stopped, not saved.
func TestAgentDownloadNeverOnDiskUnmasked(t *testing.T) {
	saved := out.P
	t.Cleanup(func() { out.P = saved })
	out.P = &out.Printer{Format: "json", W: io.Discard, Mask: true,
		Secrets: func() map[string]string { return map[string]string{"db": "vault-value-77"} }}
	dir := t.TempDir()
	r := &tmpPeek{data: []byte("requirepass hunter2pass\nDB=vault-value-77\n"), dir: dir}
	if _, _, _, err := fetchFile(context.Background(), r, filepath.Join(dir, "a.conf"), 0o644, time.Time{}, false, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.seen), "hunter2pass") || strings.Contains(string(r.seen), "vault-value-77") {
		t.Fatalf("the real text was on disk during the download: %q", r.seen)
	}
	dst := filepath.Join(dir, "a.bin")
	_, _, _, err := fetchFile(context.Background(), strings.NewReader("\x00\x01DB=vault-value-77"), dst, 0o644, time.Time{}, false, nil)
	if toErr(err).Code != "SENSITIVE_FILE" {
		t.Fatalf("a binary file with a vault value: %v", err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("it was saved")
	}
	if tmps, _ := filepath.Glob(filepath.Join(dir, ".komando-download-*")); len(tmps) > 0 {
		t.Fatalf("left over: %v", tmps)
	}
}
