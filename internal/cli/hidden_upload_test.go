package cli

import (
	"context"
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
