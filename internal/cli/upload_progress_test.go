package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// fakeClock stands in for progressClock: it moves only when step says.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time       { return c.t }
func (c *fakeClock) step(d time.Duration) { c.t = c.t.Add(d) }
func useFakeClock(t *testing.T) *fakeClock {
	t.Helper()
	c := &fakeClock{t: time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)}
	saved := progressClock
	progressClock = c.now
	t.Cleanup(func() { progressClock = saved })
	return c
}

// progressLines reads NDJSON progress lines; any other line fails the test.
func progressLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var evs []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not a JSON line: %q", l)
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		want := []string{"bytes_done", "bytes_total", "event", "file", "files_done", "files_total"}
		if m["event"] == "done" {
			want = []string{"bytes_done", "bytes_total", "event", "file", "files_done", "files_total", "ok"}
		}
		if !reflect.DeepEqual(keys, want) {
			t.Errorf("line %s: keys %v, want %v", l, keys, want)
		}
		evs = append(evs, m)
	}
	return evs
}

// lastDone checks that the run ends with exactly one done line and
// returns it.
func lastDone(t *testing.T, evs []map[string]any) map[string]any {
	t.Helper()
	if len(evs) == 0 {
		t.Fatal("no progress lines")
	}
	for _, e := range evs[:len(evs)-1] {
		if e["event"] != "progress" {
			t.Errorf("before the end: %v", e)
		}
	}
	d := evs[len(evs)-1]
	if d["event"] != "done" {
		t.Fatalf("the last line is not done: %v", d)
	}
	return d
}

func wantCounts(t *testing.T, what string, e map[string]any, bytesDone, bytesTotal, filesDone, filesTotal any) {
	t.Helper()
	num := func(v any) any {
		if i, ok := v.(int); ok {
			return float64(i)
		}
		return v
	}
	if e["bytes_done"] != num(bytesDone) || e["bytes_total"] != num(bytesTotal) || e["files_done"] != num(filesDone) || e["files_total"] != num(filesTotal) {
		t.Errorf("%s: %v, want bytes %v/%v files %v/%v", what, e, bytesDone, bytesTotal, filesDone, filesTotal)
	}
}

// At most one line per 250 ms, whatever the reads; the done line always.
func TestProgressThrottle(t *testing.T) {
	clock := useFakeClock(t)
	var buf bytes.Buffer
	ctx, p := withProgress(context.Background(), &buf)
	pp := progressFrom(ctx)
	pp.total(2, 400)
	pp.start("a.txt")
	r := pp.reader(bytes.NewReader(make([]byte, 400)))
	chunk := make([]byte, 10)
	for i := 0; i < 40; i++ { // 40 reads, 10 ms apart: 400 ms
		if _, err := r.Read(chunk); err != nil {
			t.Fatal(err)
		}
		clock.step(10 * time.Millisecond)
	}
	pp.fileDone()
	p.done(true)
	evs := progressLines(t, buf.String())
	// the start at 0 ms, the read at 250 ms, then the done line
	if len(evs) != 3 {
		t.Fatalf("%d lines, want 3:\n%s", len(evs), buf.String())
	}
	wantCounts(t, "start", evs[0], 0, 400, 0, 2)
	wantCounts(t, "at 250 ms", evs[1], 260, 400, 0, 2)
	d := lastDone(t, evs)
	wantCounts(t, "done", d, 400, 400, 1, 2)
	if d["ok"] != true || d["file"] != "a.txt" {
		t.Errorf("done: %v", d)
	}
	p.done(false)
	if n := len(progressLines(t, buf.String())); n != 3 {
		t.Errorf("a second done wrote a line (%d lines)", n)
	}
}

// Totals are null until every server has given its own; a server that
// fails first counts as moving nothing. One part that cannot know keeps
// them null.
func TestProgressTotalsAcrossServers(t *testing.T) {
	clock := useFakeClock(t)
	var buf bytes.Buffer
	ctx, p := withProgress(context.Background(), &buf)
	progressFrom(ctx).eachServer(2)
	ctxA, settleA := progressServer(ctx)
	ctxB, settleB := progressServer(ctx)
	progressFrom(ctxA).total(1, 5)
	progressFrom(ctxA).start("x")
	clock.step(time.Second)
	settleB() // web2 could not connect
	progressFrom(ctxB).total(9, 99)
	progressFrom(ctxA).fileDone()
	settleA()
	p.done(false)
	evs := progressLines(t, buf.String())
	if len(evs) != 3 {
		t.Fatalf("%d lines:\n%s", len(evs), buf.String())
	}
	wantCounts(t, "one server's total", evs[0], 0, nil, 0, nil)
	wantCounts(t, "both", evs[1], 0, 5, 1, 1)
	if d := lastDone(t, evs); d["ok"] != false {
		t.Errorf("done: %v", d)
	}

	buf.Reset()
	ctx, p = withProgress(context.Background(), &buf)
	progressFrom(ctx).unknown()
	progressFrom(ctx).start("logs/a.log")
	p.done(true)
	wantCounts(t, "unknown", lastDone(t, progressLines(t, buf.String())), 0, nil, 0, nil)
}

// A reader that seeks back (an FTP upload after a reconnect) is counted
// from where it is, and stays a Seeker.
func TestProgressReaderSeeks(t *testing.T) {
	useFakeClock(t)
	var buf bytes.Buffer
	ctx, p := withProgress(context.Background(), &buf)
	r := progressFrom(ctx).reader(bytes.NewReader([]byte("0123456789")))
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	s, ok := r.(io.Seeker)
	if !ok {
		t.Fatal("the counting reader lost Seek")
	}
	if _, err := s.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	p.done(true)
	if d := lastDone(t, progressLines(t, buf.String())); d["bytes_done"] != float64(10) {
		t.Errorf("after a seek back: %v", d)
	}
	if _, ok := progressFrom(ctx).reader(strings.NewReader("x")).(io.Seeker); !ok {
		t.Error("strings.Reader lost Seek")
	}
	if _, ok := progressFrom(ctx).reader(io.MultiReader()).(io.Seeker); ok {
		t.Error("a plain reader became a Seeker")
	}
}

// A file name never shows a vault value.
func TestProgressHidesSecretsInNames(t *testing.T) {
	useFakeClock(t)
	saved := out.P
	out.P = &out.Printer{Format: "json", W: io.Discard, Secrets: func() map[string]string { return map[string]string{"tok": "s3cr3t-v4lue-42"} }}
	t.Cleanup(func() { out.P = saved })
	var buf bytes.Buffer
	ctx, p := withProgress(context.Background(), &buf)
	progressFrom(ctx).start("dump-s3cr3t-v4lue-42.sql")
	p.done(true)
	if strings.Contains(buf.String(), "s3cr3t-v4lue-42") || !strings.Contains(buf.String(), "[secret:tok]") {
		t.Errorf("progress line: %s", buf.String())
	}
}

// sync counts every file it copies, with totals from its plan.
func TestProgressSync(t *testing.T) {
	useFakeClock(t)
	g.dryRun = false
	src, dst := t.TempDir(), t.TempDir()
	writeTree(t, src, map[string]string{"a.txt": "12345", "dir/b.txt": "123", "same.txt": "s"})
	writeTree(t, dst, map[string]string{"same.txt": "s"})
	old := time.Now().Add(-time.Hour)
	os.Chtimes(filepath.Join(dst, "same.txt"), time.Now(), time.Now())
	os.Chtimes(filepath.Join(src, "same.txt"), old, old)
	var buf bytes.Buffer
	ctx, p := withProgress(context.Background(), &buf)
	r, err := runSync(ctx, localSide{src}, localSide{dst}, "src", "dst", syncOpts{})
	if err != nil || r.Copied != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	p.done(true)
	evs := progressLines(t, buf.String())
	wantCounts(t, "done", lastDone(t, evs), 8, 8, 2, 2)
	if evs[0]["file"] != "a.txt" {
		t.Errorf("the first file is named by its path in the folder: %v", evs[0])
	}
}

// Over SFTP: a folder upload knows its total from this computer; a
// single-file download from the server's size; a folder download does not
// know it (null) but still counts.
func TestProgressSFTP(t *testing.T) {
	sc := localSFTP(t)
	useFakeClock(t)
	local := filepath.Join(t.TempDir(), "site")
	writeTree(t, local, map[string]string{"index.html": "hello", "css/a.css": "body{}"})
	remote := t.TempDir()

	var buf bytes.Buffer
	ctx, p := withProgress(context.Background(), &buf)
	files, size := localTotal(local, true)
	progressFrom(ctx).total(files, size)
	st, err := upload(ctx, nil, sc, local, filepath.Join(remote, "site"), cpOpts{recursive: true})
	if err != nil || st.Files != 2 {
		t.Fatalf("upload: %+v %v", st, err)
	}
	p.done(true)
	wantCounts(t, "folder upload", lastDone(t, progressLines(t, buf.String())), 11, 11, 2, 2)

	buf.Reset()
	ctx, p = withProgress(context.Background(), &buf)
	progressFrom(ctx).eachServer(1)
	sctx, settle := progressServer(ctx)
	if _, err := download(sctx, nil, sc, filepath.Join(remote, "site", "index.html"), t.TempDir()+"/", cpOpts{}); err != nil {
		t.Fatal(err)
	}
	settle()
	p.done(true)
	evs := progressLines(t, buf.String())
	d := lastDone(t, evs)
	wantCounts(t, "file download", d, 5, 5, 1, 1)
	if !strings.HasSuffix(d["file"].(string), "/site/index.html") {
		t.Errorf("file: %v", d["file"])
	}

	buf.Reset()
	ctx, p = withProgress(context.Background(), &buf)
	if _, err := download(ctx, nil, sc, filepath.Join(remote, "site"), t.TempDir(), cpOpts{recursive: true}); err != nil {
		t.Fatal(err)
	}
	p.done(true)
	wantCounts(t, "folder download", lastDone(t, progressLines(t, buf.String())), 11, nil, 2, nil)

	// cp to two servers: an upload's totals count each server; a download
	// knows them once both servers have told their size
	buf.Reset()
	ctx, p = withProgress(context.Background(), &buf)
	one := filepath.Join(local, "index.html")
	up := cpProgress(ctx, one, true, 2, func(ctx context.Context, _ *sshx.Client) (any, error) {
		return upload(ctx, nil, sc, one, remote+"/", cpOpts{})
	})
	for i := 0; i < 2; i++ {
		if _, err := up(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	p.done(true)
	wantCounts(t, "file upload to two servers", lastDone(t, progressLines(t, buf.String())), 10, 10, 2, 2)

	buf.Reset()
	ctx, p = withProgress(context.Background(), &buf)
	n := 0
	down := cpProgress(ctx, "", false, 2, func(ctx context.Context, _ *sshx.Client) (any, error) {
		if n++; n == 1 {
			return nil, errors.New("web1 could not connect")
		}
		return download(ctx, nil, sc, filepath.Join(remote, "index.html"), t.TempDir()+"/", cpOpts{})
	})
	_, _ = down(ctx, nil)
	if _, err := down(ctx, nil); err != nil {
		t.Fatal(err)
	}
	p.done(false)
	wantCounts(t, "file download from two servers, one down", lastDone(t, progressLines(t, buf.String())), 5, 5, 1, 1)
}

// The commands: --progress with -o json writes the lines on stderr and
// leaves the stdout envelope as it is; without --progress, or in text,
// stderr holds no JSON line.
func TestProgressStorageCommands(t *testing.T) {
	useFakeClock(t)
	m := &memBucket{objs: map[string]string{}}
	withMemBucket(t, m)
	f := filepath.Join(t.TempDir(), "db.sql")
	if err := os.WriteFile(f, bytes.Repeat([]byte("x"), 3000), 0o600); err != nil {
		t.Fatal(err)
	}
	var with, without map[string]any
	said := stderrOf(t, func() { with = mustRun(t, "storage", "upload", "bk", f, "a/db.sql", "--progress") })
	d := lastDone(t, progressLines(t, said))
	wantCounts(t, "storage upload", d, 3000, 3000, 1, 1)
	if d["ok"] != true || d["file"] != f {
		t.Errorf("done: %v", d)
	}
	if len(m.objs["a/db.sql"]) != 3000 {
		t.Fatal("the upload did not arrive whole")
	}
	if said := stderrOf(t, func() { without = mustRun(t, "upload", "bk", f, "a/db.sql") }); strings.Contains(said, `"event"`) {
		t.Errorf("without --progress: %s", said)
	}
	for _, d := range []map[string]any{with, without} {
		delete(d, "replaced") // the second upload replaced the first
		delete(d["_meta"].(map[string]any), "duration_ms")
	}
	if !reflect.DeepEqual(with, without) {
		t.Errorf("the envelope changed:\n%v\n%v", with, without)
	}

	to := filepath.Join(t.TempDir(), "got.sql")
	said = stderrOf(t, func() { mustRun(t, "download", "bk", "a/db.sql", "--to", to, "--progress") })
	wantCounts(t, "storage download", lastDone(t, progressLines(t, said)), 3000, 3000, 1, 1)

	m.objs["logs/a.log"], m.objs["logs/b.log"] = "aaaa", "bb"
	said = stderrOf(t, func() { mustRun(t, "storage", "download", "bk", "logs/", "-r", "--to", t.TempDir(), "--progress") })
	wantCounts(t, "storage download -r", lastDone(t, progressLines(t, said)), 6, 6, 2, 2)

	said = stderrOf(t, func() { _, _ = invRun(t, "download", "bk", "nope.sql", "--to", t.TempDir()+"/", "--progress") })
	if d := lastDone(t, progressLines(t, said)); d["ok"] != false {
		t.Errorf("a failed download: %v", d)
	}

	said = stderrOf(t, func() { mustRun(t, "sync", filepath.Dir(f), "bk:sync/", "--progress", "--dry-run") })
	if strings.Contains(said, `"event"`) {
		t.Errorf("a dry run moves nothing, so it writes no progress: %s", said)
	}
	said = stderrOf(t, func() { _, _ = invRun(t, "-o", "text", "upload", "bk", f, "t.sql", "--progress") })
	if strings.Contains(said, `"event"`) {
		t.Errorf("-o text: %s", said)
	}
	for _, path := range [][]string{{"upload"}, {"download"}, {"cp"}, {"sync"}, {"storage", "upload"}, {"storage", "download"}} {
		c, _, err := newRoot().Find(path)
		if err != nil || c.Flags().Lookup("progress") == nil {
			t.Errorf("%v has no --progress", path)
		}
	}
}
