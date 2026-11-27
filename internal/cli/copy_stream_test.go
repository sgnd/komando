package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// streamRun runs komando as the program does, with stdin as its input,
// and returns stdout, stderr and the exit code.
func streamRun(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	var o, e bytes.Buffer
	savedW, savedE, savedIn := tcl.out.W, tcl.out.Err, tcl.stdin
	tcl.out.W, tcl.out.Err, tcl.stdin = &o, &e, strings.NewReader(stdin)
	defer func() { tcl.out.W, tcl.out.Err, tcl.stdin = savedW, savedE, savedIn }()
	code := executeArgs(append([]string{"-o", "json"}, args...))
	return o.String(), e.String(), code
}

// envelopeOf reads the one JSON envelope in s.
func envelopeOf(t *testing.T, s string) (data map[string]any, e *out.Error) {
	t.Helper()
	var env struct {
		Data  map[string]any `json:"data"`
		Error *out.Error     `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &env); err != nil {
		t.Fatalf("not one JSON envelope: %v\n%q", err, s)
	}
	return env.Data, env.Error
}

// binaryPayload is every byte value, a NUL and bytes that are no UTF-8,
// so any change on the way shows.
func binaryPayload() string {
	var b strings.Builder
	for i := 0; i < 3; i++ {
		for c := 0; c < 256; c++ {
			b.WriteByte(byte(c))
		}
	}
	b.WriteString("\r\n\x00\xff\xfe")
	return b.String()
}

// download --to - from storage: stdout carries the file's bytes and
// nothing else, also with -o json; the result (bytes, sha256) is one JSON
// envelope on stderr, and so is an error.
func TestStreamStorageDownload(t *testing.T) {
	data := binaryPayload()
	withMemBucket(t, &memBucket{objs: map[string]string{"img/a.bin": data}})
	for _, args := range [][]string{
		{"copy", "bk:img/a.bin", "-"},
	} {
		stdout, stderr, code := streamRun(t, "", args...)
		if code != 0 || stdout != data {
			t.Fatalf("%v: exit %d, %d bytes on stdout (want %d)\n%s", args, code, len(stdout), len(data), stderr)
		}
		d, e := envelopeOf(t, stderr)
		if e != nil || d["to"] != "stdout" || d["bytes"] != float64(len(data)) || d["sha256"] != sumOf([]byte(data)) || d["conn"] != "bk" || d["key"] != "img/a.bin" {
			t.Errorf("%v: the result on stderr: %v %v", args, d, e)
		}
	}
	stdout, stderr, code := streamRun(t, "", "copy", "bk:nope.bin", "-")
	if _, e := envelopeOf(t, stderr); code != out.ExitNotFound || stdout != "" || e == nil || e.Code != "OBJECT_NOT_FOUND" {
		t.Errorf("a missing object: exit %d, stdout %q, stderr %s", code, stdout, stderr)
	}
	// a usage error found before anything is read: on stderr too
	stdout, stderr, code = streamRun(t, "", "copy", "bk:img/a.bin", "-", "--continue")
	if _, e := envelopeOf(t, stderr); code != out.ExitUsage || stdout != "" || e == nil || e.Code != "USAGE" {
		t.Errorf("--continue: exit %d, stdout %q, stderr %s", code, stdout, stderr)
	}
	// a dry run reads nothing and answers on stdout, as every dry run does
	stdout, _, code = streamRun(t, "", "copy", "bk:img/a.bin", "-", "--dry-run")
	if d, e := envelopeOf(t, stdout); code != 0 || e != nil || d["file"] != "stdout" {
		t.Errorf("dry run: exit %d, %s", code, stdout)
	}
}

// For an AI agent a stream keeps what a download to a file keeps: a text
// file shows secret values as [hidden], a binary one that holds a vault
// value is refused before a byte is written, and anything larger than
// komando reads whole is refused (it could not be taken back).
func TestStreamForAgents(t *testing.T) {
	saved := tcl.out
	t.Cleanup(func() { tcl.out = saved })
	var w bytes.Buffer
	tcl.out = &out.Printer{Format: "json", W: &w, Mask: true,
		Secrets: func() map[string]string { return map[string]string{"db": "vault-value-77"} }}
	ctx := context.Background()
	get := func(b string) func(io.Writer) (int64, error) {
		return func(w2 io.Writer) (int64, error) { n, err := w2.Write([]byte(b)); return int64(n), err }
	}
	r, err := streamTo(tcl, ctx, &w, get("DB=vault-value-77\n"))
	if err != nil || !strings.Contains(w.String(), "[credential:db]") || strings.Contains(w.String(), "vault-value-77") || !r.masked || r.sum != "" {
		t.Errorf("text: %q %+v %v", w.String(), r, err)
	}
	w.Reset()
	if _, err := streamTo(tcl, ctx, &w, get("\x00bin DB=vault-value-77")); toErr(err).Code != "SENSITIVE_FILE" || w.Len() != 0 {
		t.Errorf("binary with a vault value: %v, %d bytes written", err, w.Len())
	}
	if r, err := streamTo(tcl, ctx, &w, get("\x00clean\xff")); err != nil || w.String() != "\x00clean\xff" || r.sum != sumOf([]byte("\x00clean\xff")) {
		t.Errorf("clean binary: %q %+v %v", w.String(), r, err)
	}
	w.Reset()
	big := strings.Repeat("a", hiddenScanMax+1)
	if _, err := streamTo(tcl, ctx, &w, get(big)); toErr(err).Code != "FILE_TOO_LARGE" || w.Len() != 0 {
		t.Errorf("too large: %v, %d bytes written", err, w.Len())
	}
}

// download --to - from a server reads the file over SFTP as it is.
func TestStreamServerFile(t *testing.T) {
	sc := localSFTP(t)
	data := binaryPayload()
	p := filepath.Join(t.TempDir(), "a.bin")
	writeFile(t, p, []byte(data))
	var w bytes.Buffer
	r, err := streamTo(tcl, context.Background(), &w, serverReader(tcl, context.Background(), sc, p))
	if err != nil || w.String() != data || r.bytes != int64(len(data)) || r.sum != sumOf([]byte(data)) {
		t.Fatalf("stream: %d bytes, %+v %v", w.Len(), r, err)
	}
	w.Reset()
	if _, err := streamTo(tcl, context.Background(), &w, serverReader(tcl, context.Background(), sc, filepath.Dir(p))); toErr(err).Code != "USAGE" {
		t.Errorf("a folder: %v", err)
	}
	if _, err := streamTo(tcl, context.Background(), &w, serverReader(tcl, context.Background(), sc, p+".nope")); toErr(err).Exit != out.ExitNotFound {
		t.Errorf("a missing file: %v", err)
	}
}

// upload - DEST and storage upload - KEY read the content from stdin,
// stream it, and report its size and sha256. --size N makes a stream that
// ends early (or runs long) fail without replacing anything; a dry run
// reads nothing.
func TestStreamUploadFromStdin(t *testing.T) {
	data := binaryPayload()
	m := &memBucket{objs: map[string]string{"keep.bin": "old"}}
	withMemBucket(t, m)
	for _, args := range [][]string{
		{"copy", "-", "bk:in/a.bin"},
		{"copy", "-", "bk:in/c.bin"},
	} {
		stdout, stderr, code := streamRun(t, data, args...)
		d, e := envelopeOf(t, stdout)
		key := strings.TrimPrefix(args[len(args)-1], "bk:")
		if code != 0 || e != nil || m.objs[key] != data || d["bytes"] != float64(len(data)) || d["sha256"] != sumOf([]byte(data)) || d["file"] != "-" {
			t.Errorf("%v: exit %d, %v %v, stored %d bytes\n%s", args, code, d, e, len(m.objs[key]), stderr)
		}
	}
	stdout, _, code := streamRun(t, data, "copy", "-", "bk:sized.bin", "--size", "10")
	if _, e := envelopeOf(t, stdout); code != out.ExitConflict || e == nil || e.Code != "SIZE_CONFLICT" {
		t.Errorf("--size too small: exit %d %s", code, stdout)
	}
	stdout, _, code = streamRun(t, "abc", "copy", "-", "bk:keep.bin", "--size", "10")
	if _, e := envelopeOf(t, stdout); code != out.ExitConflict || e == nil || e.Code != "SIZE_CONFLICT" || m.objs["keep.bin"] != "old" {
		t.Errorf("stdin ended early: exit %d %s, keep.bin %q", code, stdout, m.objs["keep.bin"])
	}
	if d := mustRun(t, "copy", "-", "bk:sized.bin", "--size", "3", "--dry-run"); d["file"] != "-" || d["dry_run"] != true {
		t.Errorf("dry run: %v", d)
	}
	stdin := strings.NewReader("not read")
	tcl.stdin = stdin
	mustRun(t, "copy", "-", "bk:dry.bin", "--dry-run")
	if stdin.Len() != len("not read") {
		t.Error("a dry run read stdin")
	}
	tcl.stdin = nil
	// a masked copy (a [hidden] value) never replaces a real file
	stdout, _, code = streamRun(t, "DB=[hidden]\n", "copy", "-", "bk:keep.bin")
	if _, e := envelopeOf(t, stdout); code != out.ExitUsage || e == nil || e.Code != "HIDDEN_VALUE" || m.objs["keep.bin"] != "old" {
		t.Errorf("hidden value: exit %d %s", code, stdout)
	}
	for _, args := range [][]string{
		{"copy", "-", "bk:"},                           // no name to give it
		{"copy", "-", "bk:dir/"},                       // a folder
		{"copy", "-", "bk:a.bin", "--continue"},        // cannot be read again
		{"copy", "-", "bk:a.bin", "-r"},                // one stream, one file
		{"copy", "./a.bin", "bk:a.bin", "--size", "3"}, // --size is for stdin
	} {
		wantCode(t, "USAGE", args...)
	}
}

// Upload from stdin to a server: a temporary file, moved into place only
// when all of it arrived; a short stream leaves the old file and no
// temporary file behind.
func TestStreamUploadToServer(t *testing.T) {
	sc := localSFTP(t)
	ctx := context.Background()
	dir := t.TempDir()
	data := binaryPayload()
	dst := filepath.Join(dir, "a.bin")
	saved := tcl.stdin
	t.Cleanup(func() { tcl.stdin = saved })
	tcl.stdin = strings.NewReader(data)
	st, err := upload(tcl, ctx, nil, sc, "-", dst, cpOpts{})
	if err != nil || st.SHA256 != sumOf([]byte(data)) || string(readBytes(t, dst)) != data {
		t.Fatalf("upload: %+v %v", st, err)
	}
	tcl.stdin = strings.NewReader("short")
	if _, err := upload(tcl, ctx, nil, sc, "-", dst, cpOpts{size: 100, sized: true}); toErr(err).Code != "SIZE_CONFLICT" {
		t.Errorf("short: %v", err)
	}
	if string(readBytes(t, dst)) != data {
		t.Error("a short stream replaced the file")
	}
	tcl.stdin = strings.NewReader("x")
	if _, err := upload(tcl, ctx, nil, sc, "-", dir, cpOpts{}); toErr(err).Code != "USAGE" {
		t.Errorf("to a folder: %v", err)
	}
	if l := leftovers(t, dir); len(l) > 0 {
		t.Errorf("temporary files left: %v", l)
	}
}

// Several servers cannot share one stdin; a Windows server is refused
// before anything is read.
func TestStreamUploadChecks(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1", "--group", "web")
	mustRun(t, "host", "ssh", "add", "web2", "u@10.0.0.2", "--group", "web")
	wantCode(t, "USAGE", "copy", "-", "@web:/tmp/a")
	wantCode(t, "USAGE", "copy", "@web:/tmp/a", "-")
	wantCode(t, "USAGE", "copy", "web1:/var/www", "-", "-r")
	d := mustRun(t, "copy", "-", "web1:/tmp/a", "--dry-run")
	if d["src"] != "-" {
		t.Errorf("dry run: %v", d)
	}
}

// cutStdin sends its bytes, then the command is cancelled (Ctrl-C, a
// dropped link) and stdin closes, as when the program feeding it dies of
// the same signal.
type cutStdin struct {
	data   string
	cancel context.CancelFunc
}

func (c *cutStdin) Read(p []byte) (int, error) {
	if c.data == "" {
		c.cancel()
		return 0, io.EOF
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}

// A cancelled upload from stdin replaces nothing: stdin closing after the
// cancel is not the end of the file.
func TestStreamUploadCancelledReplacesNothing(t *testing.T) {
	saved := tcl.stdin
	t.Cleanup(func() { tcl.stdin = saved })
	sc := localSFTP(t)
	dst := filepath.Join(t.TempDir(), "app.conf")
	writeFile(t, dst, []byte("old"))
	ctx, cancel := context.WithCancel(context.Background())
	tcl.stdin = &cutStdin{data: "partial", cancel: cancel}
	if _, err := upload(tcl, ctx, nil, sc, "-", dst, cpOpts{}); err == nil {
		t.Error("server: a cancelled upload said it worked")
	}
	if got := string(readBytes(t, dst)); got != "old" {
		t.Errorf("server: the file is now %q", got)
	}
	m := &memBucket{objs: map[string]string{"keep.bin": "old"}}
	withMemBucket(t, m)
	ctx, cancel = context.WithCancel(context.Background())
	tcl.stdin = &cutStdin{data: "partial", cancel: cancel}
	if err := storageUploadStdin(tcl, ctx, "storage.upload", "bk", "keep.bin", cpOpts{}); err == nil || m.objs["keep.bin"] != "old" {
		t.Errorf("storage: %v, keep.bin %q", err, m.objs["keep.bin"])
	}
}

// --progress counts files and bytes saved; a stream to stdout has its one
// answer on stderr and nothing else there.
func TestStreamRefusesProgress(t *testing.T) {
	withMemBucket(t, &memBucket{objs: map[string]string{"a.bin": "abc"}})
	wantCode(t, "USAGE", "copy", "bk:a.bin", "-", "--progress")
}

// For an AI agent a binary stream is refused when it holds anything komando
// hides from agents, not only a vault value: here personal data on a
// target that hides it (as agentStdout on main does for storage).
func TestStreamBinaryHiddenForAgents(t *testing.T) {
	saved := tcl.out
	t.Cleanup(func() { tcl.out = saved })
	tcl.out = &out.Printer{Format: "json", W: io.Discard, Mask: true, Personal: true}
	bin := "\x00\x01bin\x00"
	_, err := streamTo(tcl, context.Background(), io.Discard, func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, bin+"alice@example.com")
		return int64(n), err
	})
	if e := toErr(err); e == nil || e.Code != "SENSITIVE_FILE" {
		t.Fatalf("binary with personal data: %v", err)
	}
	var got bytes.Buffer
	if _, err := streamTo(tcl, context.Background(), &got, func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, bin+"nothing here")
		return int64(n), err
	}); err != nil || got.String() != bin+"nothing here" {
		t.Fatalf("plain binary: %q %v", got.String(), err)
	}
}
