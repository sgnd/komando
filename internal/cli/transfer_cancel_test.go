package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// leftovers lists komando's temporary files in dir (none may stay behind).
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	var l []string
	_ = filepath.Walk(dir, func(p string, _ os.FileInfo, _ error) error {
		if strings.HasPrefix(filepath.Base(p), ".komando-") {
			l = append(l, p)
		}
		return nil
	})
	return l
}

// Ctrl-C cancels the command's context. A copy used to ignore it and run
// to the last byte (a 600 MB upload, download or sync went on for 20 s
// after SIGINT). Now each copy stops, says CANCELLED, and leaves neither
// half a file nor a temporary one.
func TestTransferStopsOnCancel(t *testing.T) {
	sc := localSFTP(t)
	here, there := t.TempDir(), t.TempDir()
	big := filepath.Join(here, "big.bin")
	if err := os.WriteFile(big, make([]byte, 4<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(there, "big.bin")
	if err := os.WriteFile(old, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s: err %v, want context.Canceled", what, err)
		} else if e := toErr(err); e.Code != "CANCELLED" {
			t.Errorf("%s: code %s", what, e.Code)
		}
	}

	_, err := upload(ctx, nil, sc, big, old, cpOpts{})
	cancelled("upload", err)
	if read(t, old) != "old" {
		t.Error("upload: the file on the server was changed")
	}

	// one file of a folder upload: written to a temporary name first
	info, _ := os.Stat(big)
	_, err = putFile(ctx, sc, big, old, info)
	cancelled("folder upload file", err)
	if read(t, old) != "old" {
		t.Error("folder upload: the file on the server was cut")
	}

	dir := filepath.Join(here, "site")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644)
	_, err = upload(ctx, nil, sc, dir, filepath.Join(there, "site"), cpOpts{recursive: true})
	cancelled("folder upload", err)

	_, err = download(ctx, nil, sc, old, filepath.Join(here, "got.bin"), cpOpts{})
	cancelled("download", err)
	if _, err := os.Stat(filepath.Join(here, "got.bin")); err == nil {
		t.Error("download: a file was left on this computer")
	}

	_, err = runSync(ctx, localSide{root: dir}, sftpSide{sc: sc, root: filepath.Join(there, "synced")}, "src", "dst", syncOpts{})
	cancelled("sync", err)
	if _, err := os.Stat(filepath.Join(there, "synced", "a.txt")); err == nil {
		t.Error("sync: copied after Ctrl-C")
	}

	for _, d := range []string{here, there} {
		if l := leftovers(t, d); len(l) > 0 {
			t.Errorf("temporary files left: %v", l)
		}
	}
}

// A download that stops at a file already here saved nothing: the text
// said "downloaded 1 file (0 B)" above the FILE_EXISTS error.
func TestDownloadExistingCountsNothing(t *testing.T) {
	sc := localSFTP(t)
	src := filepath.Join(t.TempDir(), "a.txt")
	_ = os.WriteFile(src, []byte("new"), 0o644)
	dst := filepath.Join(t.TempDir(), "a.txt")
	_ = os.WriteFile(dst, []byte("mine"), 0o644)
	st, err := download(context.Background(), nil, sc, src, dst, cpOpts{})
	if e := toErr(err); err == nil || e.Code != "FILE_EXISTS" {
		t.Fatalf("err %v", err)
	}
	if st.Files != 0 || st.Dest != "" {
		t.Errorf("stats %+v, want none", st)
	}
	if got := (xferData{Results: []xferStats{{Host: "web1", Error: toErr(err)}}}).Text(); strings.Contains(got, "downloaded") {
		t.Errorf("text %q", got)
	}
	if read(t, dst) != "mine" {
		t.Error("the file here was replaced")
	}
}
