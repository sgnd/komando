package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/storex"
)

func sumOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// payload is test content that is not all the same byte, so a part in
// the wrong place shows.
func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readBytes(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --continue over SFTP, both ways: a missing file is copied whole, a cut
// one is finished, a whole one is left as it is; each ends with the
// file's sha256, checked against the source.
func TestContinueOverSFTP(t *testing.T) {
	sc := localSFTP(t)
	ctx := context.Background()
	here, there := t.TempDir(), t.TempDir()
	data := payload(300_000)
	src := filepath.Join(here, "db.sql.gz")
	writeFile(t, src, data)
	dst := filepath.Join(there, "db.sql.gz")

	for _, c := range []struct {
		name     string
		before   []byte // at the destination first; nil: nothing
		wantFrom int64
	}{
		{"new file", nil, 0},
		{"cut off", data[:123_457], 123_457},
		{"empty", []byte{}, 0},
		{"complete", data, int64(len(data))},
	} {
		os.Remove(dst)
		if c.before != nil {
			writeFile(t, dst, c.before)
		}
		st, err := upload(tcl, ctx, nil, sc, src, dst, cpOpts{resume: true})
		if err != nil {
			t.Fatalf("upload, %s: %v", c.name, err)
		}
		if st.ContinuedFrom != c.wantFrom || st.SHA256 != sumOf(data) || st.Bytes != int64(len(data)) || !bytes.Equal(readBytes(t, dst), data) {
			t.Errorf("upload, %s: %+v", c.name, st)
		}

		got := filepath.Join(here, "got", "db.sql.gz")
		os.Remove(got)
		if c.before != nil {
			writeFile(t, got, c.before)
		}
		st, err = download(tcl, ctx, nil, sc, dst, got, cpOpts{resume: true})
		if err != nil {
			t.Fatalf("download, %s: %v", c.name, err)
		}
		if st.ContinuedFrom != c.wantFrom || st.SHA256 != sumOf(data) || !bytes.Equal(readBytes(t, got), data) {
			t.Errorf("download, %s: %+v", c.name, st)
		}
	}
	if l := leftovers(t, there); len(l) > 0 {
		t.Errorf("temporary files left: %v", l)
	}
}

// A destination that is longer than the source, or differs from it in the
// part that is there, is never added to: RESUME_CONFLICT, file unchanged.
func TestContinueRefusesAnotherFile(t *testing.T) {
	sc := localSFTP(t)
	ctx := context.Background()
	here, there := t.TempDir(), t.TempDir()
	data := payload(50_000)
	src := filepath.Join(here, "a.bin")
	writeFile(t, src, data)
	dst := filepath.Join(there, "a.bin")
	other := append([]byte("X"), data[1:20_000]...)
	for name, before := range map[string][]byte{
		"longer":  append(append([]byte{}, data...), 'x'),
		"differs": other,
	} {
		writeFile(t, dst, before)
		_, err := upload(tcl, ctx, nil, sc, src, dst, cpOpts{resume: true})
		if e := toErr(err); e.Code != "RESUME_CONFLICT" || e.Exit != out.ExitConflict {
			t.Errorf("upload, %s: %v", name, err)
		}
		if !bytes.Equal(readBytes(t, dst), before) {
			t.Errorf("upload, %s: the file on the server was changed", name)
		}
		local := filepath.Join(here, "got.bin")
		writeFile(t, local, before)
		_, err = download(tcl, ctx, nil, sc, src, local, cpOpts{resume: true})
		if e := toErr(err); e.Code != "RESUME_CONFLICT" {
			t.Errorf("download, %s: %v", name, err)
		}
		if !bytes.Equal(readBytes(t, local), before) {
			t.Errorf("download, %s: the file here was changed", name)
		}
	}
}

// On a server with a shell, the sums are worked out there (sha256sum), so
// the part already copied does not travel again.
func TestContinueSumsOnTheServer(t *testing.T) {
	sc := localSFTP(t)
	here, there := t.TempDir(), t.TempDir()
	data := payload(80_000)
	src := filepath.Join(here, "a.bin")
	writeFile(t, src, data)
	dst := filepath.Join(there, "a.bin")
	writeFile(t, dst, data[:30_000])
	var asked []int64
	saved := remoteSum
	t.Cleanup(func() { remoteSum = saved })
	remoteSum = func(_ context.Context, _ *sshx.Client, p string, n int64) (string, bool) {
		asked = append(asked, n)
		b := readBytes(t, p) // the "server" is this computer
		if n >= 0 {
			b = b[:n]
		}
		return sumOf(b), true
	}
	st, err := upload(tcl, context.Background(), nil, sc, src, dst, cpOpts{resume: true})
	if err != nil || st.ContinuedFrom != 30_000 || !bytes.Equal(readBytes(t, dst), data) {
		t.Fatalf("%+v %v", st, err)
	}
	if len(asked) != 2 || asked[0] != 30_000 || asked[1] != -1 {
		t.Errorf("sums asked of the server: %v", asked)
	}
	// a sum that does not match stops it
	writeFile(t, dst, data[:30_000])
	remoteSum = func(context.Context, *sshx.Client, string, int64) (string, bool) {
		return strings.Repeat("0", 64), true
	}
	if _, err := upload(tcl, context.Background(), nil, sc, src, dst, cpOpts{resume: true}); toErr(err).Code != "RESUME_CONFLICT" {
		t.Errorf("a server sum that differs: %v", err)
	}
	if got := sumScript("/tmp/it's", 10); !strings.Contains(got, `head -c 10 -- "$f"`) || !strings.Contains(got, sshx.Q("/tmp/it's")) {
		t.Errorf("sum script: %s", got)
	}
	// the script itself, run by this computer's shell
	for _, n := range []int64{30_000, -1} {
		b, err := exec.Command("sh", "-c", sumScript(src, n)).Output()
		want := data
		if n >= 0 {
			want = data[:n]
		}
		if m := sumLine.FindStringSubmatch(string(b)); err != nil || m == nil || m[1] != sumOf(want) {
			t.Errorf("sum script, %d bytes: %q %v", n, b, err)
		}
	}
}

// A file that ends up different from the source after the copy is
// reported, never called a success.
func TestContinueChecksTheWholeFile(t *testing.T) {
	data := payload(10_000)
	src := &memEnd{name: "src", b: data}
	dst := &memEnd{name: "dst", b: append([]byte{}, data[:4000]...), corrupt: true}
	_, err := resumeCopy(context.Background(), src, dst, "a")
	if e := toErr(err); e.Code != "RESUME_FAILED" || e.Exit != out.ExitRemote {
		t.Fatalf("got %v", err)
	}
}

// memEnd is a resume end in memory; corrupt flips a byte of what it adds.
type memEnd struct {
	name    string
	b       []byte
	corrupt bool
}

func (m *memEnd) where() string { return m.name }
func (m *memEnd) size(context.Context) (int64, bool, error) {
	return int64(len(m.b)), m.b != nil, nil
}
func (*memEnd) sumThere(context.Context, int64) (string, bool) { return "", false }
func (m *memEnd) openAt(_ context.Context, off int64) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.b[off:])), nil
}
func (*memEnd) canAppend() bool { return true }
func (m *memEnd) appendAt(_ context.Context, _, _ int64, r io.Reader) error {
	b, err := io.ReadAll(r)
	if m.corrupt && len(b) > 0 {
		b[0] ^= 0xff
	}
	m.b = append(m.b, b...)
	return err
}

// Storage: S3-like storage cannot add to an object, so a cut object stops
// with RESUME_UNSUPPORTED (a missing one is uploaded whole, a whole one is
// checked); a download from storage reads on from where the file here
// stops. A file server conn (SFTP) adds to the file.
func TestContinueStorage(t *testing.T) {
	m := &memBucket{objs: map[string]string{}}
	withMemBucket(t, m)
	data := payload(5000)
	f := filepath.Join(t.TempDir(), "db.sql")
	writeFile(t, f, data)

	d := mustRun(t, "upload", "bk", f, "a/db.sql", "--continue")
	if m.objs["a/db.sql"] != string(data) || d["sha256"] != sumOf(data) || d["continued_from_bytes"] != nil {
		t.Fatalf("new object: %v", d)
	}
	d = mustRun(t, "storage", "upload", "bk", f, "a/db.sql", "--continue")
	if d["continued_from_bytes"].(float64) != 5000 || d["replaced"] != false {
		t.Errorf("whole object: %v", d)
	}
	m.objs["a/db.sql"] = string(data[:100])
	if e := wantCode(t, "RESUME_UNSUPPORTED", "cp", f, "bk:a/db.sql", "--continue"); e.Exit != out.ExitUsage {
		t.Errorf("exit %d", e.Exit)
	}
	if m.objs["a/db.sql"] != string(data[:100]) {
		t.Error("the object was changed")
	}

	m.objs["a/db.sql"] = string(data)
	to := filepath.Join(t.TempDir(), "got.sql")
	writeFile(t, to, data[:1234])
	d = mustRun(t, "download", "bk", "a/db.sql", "--to", to, "--continue")
	if d["continued_from_bytes"].(float64) != 1234 || d["sha256"] != sumOf(data) || !bytes.Equal(readBytes(t, to), data) {
		t.Errorf("storage download: %v", d)
	}
	writeFile(t, to, []byte("other"))
	wantCode(t, "RESUME_CONFLICT", "storage", "download", "bk", "a/db.sql", "--to", to, "--continue")
	if string(readBytes(t, to)) != "other" {
		t.Error("the file here was changed")
	}

	// an SFTP conn adds to the file
	sc := localSFTP(t)
	root := t.TempDir()
	b := storex.NewSFTP(sc, strings.TrimPrefix(filepath.ToSlash(root), "/")+"/", nil)
	writeFile(t, filepath.Join(root, "up", "db.sql"), data[:777])
	r, err := resumeCopy(context.Background(), localEnd{path: f}, bucketEnd{conn: "files", b: b, key: "up/db.sql"}, "db.sql")
	if err != nil || r.from != 777 || r.sum != sumOf(data) || !bytes.Equal(readBytes(t, filepath.Join(root, "up", "db.sql")), data) {
		t.Fatalf("sftp conn: %+v %v", r, err)
	}
	r, err = resumeCopy(context.Background(), bucketEnd{conn: "files", b: b, key: "up/db.sql"}, bucketEnd{conn: "files", b: b, key: "new/db.sql"}, "db.sql")
	if err != nil || r.from != 0 || !bytes.Equal(readBytes(t, filepath.Join(root, "new", "db.sql")), data) {
		t.Fatalf("sftp conn, new file: %+v %v", r, err)
	}
	// reading on from an offset: ranged (SFTP) and by skipping (others)
	var got bytes.Buffer
	if _, err := storex.GetFrom(context.Background(), b, "up/db.sql", 4000, &got); err != nil || !bytes.Equal(got.Bytes(), data[4000:]) {
		t.Errorf("sftp GetFrom: %d bytes, %v", got.Len(), err)
	}
	got.Reset()
	if _, err := storex.GetFrom(context.Background(), m, "a/db.sql", 4000, &got); err != nil || !bytes.Equal(got.Bytes(), data[4000:]) {
		t.Errorf("GetFrom by skipping: %d bytes, %v", got.Len(), err)
	}
}

// Flags that do not go with --continue are refused before anything runs.
func TestContinueFlags(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	f := filepath.Join(t.TempDir(), "a.txt")
	writeFile(t, f, []byte("a"))
	for _, args := range [][]string{
		{"upload", "web1", f, "/tmp/a.txt", "--continue", "-r"},
		{"upload", "web1", f, "/tmp/a.txt", "--continue", "--sudo"},
		{"download", "web1", "/tmp/a.txt", "--continue", "--overwrite"},
		{"cp", "web1:/tmp/a.txt", t.TempDir(), "--continue", "--sudo"},
		{"cp", "-r", "web1:/tmp/a", "web1:/tmp/b", "--continue"},
		{"download", "web1", "/tmp/a.txt", "--to", "-", "--continue"},
	} {
		wantCode(t, "USAGE", args...)
	}
	// a dry run of a download that continues does not stop at the file here
	d := mustRun(t, "--dry-run", "cp", "web1:/tmp/a.txt", f, "--continue")
	if d["direction"] != "download" {
		t.Errorf("dry run: %v", d)
	}
	for _, p := range [][]string{{"upload"}, {"download"}, {"cp"}, {"storage", "upload"}, {"storage", "download"}} {
		c, _, err := newRoot(tcl).Find(p)
		if err != nil || c.Flags().Lookup("continue") == nil {
			t.Errorf("%v has no --continue", p)
		}
	}
}

// An AI agent gets small text files with secret values as [hidden], which
// cannot be continued; a larger file that turns out to hold a vault value
// loses what this run added, as a whole download never saves it.
func TestContinueForAgents(t *testing.T) {
	saved := tcl.out
	t.Cleanup(func() { tcl.out = saved })
	tcl.out = &out.Printer{Format: "json", W: io.Discard, Mask: true,
		Secrets: func() map[string]string { return map[string]string{"db": "vault-value-77"} }}
	dir := t.TempDir()
	ctx := context.Background()

	small := &memEnd{name: "web1:/etc/app.conf", b: []byte("DB=vault-value-77\n")}
	if _, err := continueDownload(tcl, ctx, small, filepath.Join(dir, "app.conf"), 0o644, "app.conf"); toErr(err).Code != "RESUME_UNSUPPORTED" {
		t.Fatalf("small file: %v", err)
	}

	big := make([]byte, hiddenScanMax+10)
	copy(big[len(big)-20:], "DB=vault-value-77")
	dst := filepath.Join(dir, "dump.bin")
	writeFile(t, dst, big[:1000])
	_, err := continueDownload(tcl, ctx, &memEnd{name: "web1:/dump.bin", b: big}, dst, 0o644, "dump.bin")
	if toErr(err).Code != "SENSITIVE_FILE" {
		t.Fatalf("large file with a vault value: %v", err)
	}
	if got := readBytes(t, dst); len(got) != 1000 {
		t.Errorf("the part this run added stayed: %d bytes", len(got))
	}
	clean := make([]byte, hiddenScanMax+10)
	if _, err := continueDownload(tcl, ctx, &memEnd{name: "web1:/clean.bin", b: clean}, dst, 0o644, "dump.bin"); err != nil {
		t.Fatalf("large clean file: %v", err)
	}
}
