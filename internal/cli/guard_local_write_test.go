package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// agentWriteHome makes home the account's home folder (komando's data in
// home/.komando, made by a person's command) and the caller an AI agent.
// It returns the destinations an agent's command must never write.
func agentWriteHome(t *testing.T) (home string, protected []string) {
	t.Helper()
	unixOnly(t, "symbolic links")
	home = t.TempDir()
	accountHomeAt(t, home)
	mustRun(t, "host", "add", "web1", "u@10.0.0.9") // a person: makes ~/.komando
	db := filepath.Join(t.TempDir(), "app.db")
	mustRun(t, "conn", "add", "lite", "sqlite://"+db)
	mustRun(t, "db", "query", "lite", "--write", "create table t (id int)")
	for _, d := range []string{".ssh", ".aws", ".kube", ".config/gcloud"} {
		os.MkdirAll(filepath.Join(home, d), 0o700)
	}
	link := filepath.Join(t.TempDir(), "k")
	if err := os.Symlink(filepath.Join(home, ".komando"), link); err != nil {
		t.Fatal(err)
	}
	sshLink := filepath.Join(t.TempDir(), "s")
	if err := os.Symlink(filepath.Join(home, ".ssh"), sshLink); err != nil {
		t.Fatal(err)
	}
	windowText(t, false)
	return home, []string{
		filepath.Join(home, ".komando", "store.db"),
		filepath.Join(home, ".komando", "new.txt"),
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".kube", "config"),
		filepath.Join(home, ".config", "gcloud", "x.json"),
		filepath.Join(link, "store.db"),           // through a link to ~/.komando
		filepath.Join(sshLink, "authorized_keys"), // through a link to ~/.ssh
	}
}

func wantSensitiveWrite(t *testing.T, what, p string, err error) {
	t.Helper()
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "SENSITIVE_FILE" {
		t.Errorf("%s to %s: want SENSITIVE_FILE, got %v", what, p, err)
	}
}

// The commands that save a file on this computer refuse, for an AI agent,
// komando's folder, ~/.ssh and the credential stores, also through a
// link, before they connect anywhere.
func TestAgentLocalWriteCommands(t *testing.T) {
	home, protected := agentWriteHome(t)
	before, _ := os.ReadFile(filepath.Join(home, ".komando", "store.db"))
	for _, p := range protected {
		for _, args := range [][]string{
			{"download", "web1", "/etc/hosts", "--to", p},
			{"cp", "web1:/etc/hosts", p},
			{"db", "dump", "lite", "--to", p},
			{"export", "--to", p},
			{"sync", "web1:/srv/app", p},
		} {
			_, e := invRun(t, args...)
			if e == nil || e.Code != "SENSITIVE_FILE" {
				t.Errorf("%v: want SENSITIVE_FILE, got %+v", args, e)
			}
		}
		wantSensitiveWrite(t, "storage download", p, storageDownloadTo(tcl, context.Background(), "storage.download", "bk", "a.txt", p, true))
	}
	if after, _ := os.ReadFile(filepath.Join(home, ".komando", "store.db")); !bytes.Equal(before, after) && len(before) > 0 {
		t.Error("komando's store changed")
	}
	// another folder is fine
	to := filepath.Join(t.TempDir(), "lite.db")
	mustRun(t, "db", "dump", "lite", "--to", to)
}

// Each writer checks its destination itself, so a command that reaches it
// another way is stopped too.
func TestAgentLocalWriters(t *testing.T) {
	_, protected := agentWriteHome(t)
	ctx := context.Background()
	fill := func(tmp string) error { return os.WriteFile(tmp, []byte("x"), 0o600) }
	for _, p := range protected {
		_, _, _, err := fetchFile(tcl, ctx, strings.NewReader("x"), p, 0o600, time.Time{}, true, nil)
		wantSensitiveWrite(t, "fetchFile", p, err)
		wantSensitiveWrite(t, "writeAtomic", p, writeAtomic(tcl, p, fill))
		wantSensitiveWrite(t, "writeReplacing", p, writeReplacing(tcl, p, fill))
		wantSensitiveWrite(t, "writeExport", p, writeExport(tcl, p, []byte("x"), true))
		dir, base := filepath.Dir(p), filepath.Base(p)
		wantSensitiveWrite(t, "sync write", p, localSide{cl: tcl, root: dir}.write(ctx, base, strings.NewReader("x"), syncFile{}))
		wantSensitiveWrite(t, "sync --delete", p, localSide{cl: tcl, root: dir}.remove(ctx, base))
		var tb bytes.Buffer
		tw := tar.NewWriter(&tb)
		tw.WriteHeader(&tar.Header{Name: "notes.txt", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
		tw.Write([]byte("x"))
		tw.Close()
		notes := filepath.Join(dir, "notes.txt") // a plain name: only the folder stops it
		wantSensitiveWrite(t, "cluster cp", notes, untarTo(tcl, tb.Bytes(), notes, "notes.txt"))
	}
	// a person is not stopped
	noAgent(t)
	ok := filepath.Join(t.TempDir(), "f")
	if err := writeAtomic(tcl, ok, fill); err != nil {
		t.Fatal(err)
	}
}
