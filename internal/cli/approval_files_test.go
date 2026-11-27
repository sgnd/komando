package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What an upload, a restore or a kubectl -f sends from a file is in the
// approval window, as the content of fs write --from is (C111): the window
// a person allows names the file's SHA-256 and shows it when it can.
func TestApprovalWindowShowsSentFiles(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web", "root@127.0.0.1", "--port", "2", "--protected")
	mustRun(t, "conn", "add", "kube", "kubernetes://127.0.0.1:2", "--protected")
	conf := writeTemp(t, "app.conf", "listen 8080\nmarker_upload on\n")
	dir := filepath.Join(t.TempDir(), "site")
	if err := os.MkdirAll(filepath.Join(dir, "css"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"index.html": "<p>marker_index</p>\n", "css/app.css": "p{}\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	yaml := writeTemp(t, "app.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: marker-run-cm}\n")
	texts := windowText(t, false)
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"cp", conf, "web:/etc/app.conf", "--yes"}, []string{"marker_upload on", "SHA-256"}},
		{[]string{"cp", "-r", dir, "web:/srv/", "--yes"}, []string{"index.html", "css/app.css", "SHA-256"}},
		{[]string{"sync", dir, "web:/srv/site", "--yes"}, []string{"index.html", "css/app.css", "SHA-256"}},
		{[]string{"cluster", "kubernetes", "raw", "kube", "--write", "--yes", "--", "apply", "-f", yaml}, []string{"metadata: {name: marker-run-cm}", "SHA-256"}},
	} {
		*texts = nil
		resetApproval()
		if _, e := invRun(t, c.args...); e == nil {
			t.Errorf("%v: the person said no, but it ran", c.args)
		}
		if len(*texts) != 1 {
			t.Errorf("%v: windows %q", c.args, *texts)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains((*texts)[0], w) {
				t.Errorf("%v: the window lacks %q:\n%s", c.args, w, (*texts)[0])
			}
		}
	}
}

// A file that is not text (an archive, an image) and too big to show with
// escapes cannot be shown: the window names its size and SHA-256 and says
// it is not shown, as for a named file too long to show.
func TestApprovalWindowNamesBinaryFile(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web", "root@127.0.0.1", "--port", "2", "--protected")
	bin := writeTemp(t, "app.tar", strings.Repeat("PK\x00\x01binary\x00data", 400))
	texts := windowText(t, false)
	invRun(t, "cp", bin, "web:/srv/app.tar", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "SHA-256") || !strings.Contains((*texts)[0], "it is not text") {
		t.Errorf("a binary file: %q", *texts)
	}
}

// db restore of plain SQL sends code: shown whole, or no window at all,
// as db query --file. A 60-line file is no way around that rule.
func TestRestoreWindowShowsTheSQL(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "pg", "postgres://app@127.0.0.1:2/app", "--protected")
	short := writeTemp(t, "fix.sql", "create table marker_restore (id int);\n")
	long := writeTemp(t, "long.sql", strings.Repeat("insert into t values (1);\n", 60))
	texts := windowText(t, false)
	invRun(t, "database", "postgres", "restore", "pg", "--from", short, "--allow-dangerous", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "create table marker_restore") || !strings.Contains((*texts)[0], "SHA-256") {
		t.Errorf("a short SQL file: %q", *texts)
	}
	*texts = nil
	resetApproval()
	if _, e := invRun(t, "database", "postgres", "restore", "pg", "--from", long, "--allow-dangerous", "--yes"); e == nil || len(*texts) != 0 {
		t.Errorf("a 60-line SQL file: %v, %q", e, *texts)
	}
}

// A file too big for the window's byte cap is named by its size and the
// SHA-256 of all of it; a folder whose list of files does not fit gets no
// window, as a script that does not fit; a pg_dump archive is named.
func TestApprovalWindowBigUploads(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web", "root@127.0.0.1", "--port", "2", "--protected")
	mustRun(t, "conn", "add", "pg", "postgres://app@127.0.0.1:2/app", "--protected")
	big := writeTemp(t, "big.conf", strings.Repeat("a line of config text\n", bodyMaxBytes/10))
	dir := t.TempDir()
	for i := range bodyMaxLines + 1 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%02d.txt", i)), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := writeTemp(t, "app.dump", testPGArchive(t))
	texts := windowText(t, false)
	invRun(t, "cp", big, "web:/etc/big.conf", "--yes")
	b, _ := os.ReadFile(big)
	sum := sha256.Sum256(b)
	if len(*texts) != 1 || !strings.Contains((*texts)[0], hex.EncodeToString(sum[:])) || !strings.Contains((*texts)[0], "it is too long") {
		t.Errorf("a big file: %q", *texts)
	}
	*texts = nil
	resetApproval()
	if _, e := invRun(t, "cp", "-r", dir, "web:/srv/", "--yes"); e == nil || len(*texts) != 0 {
		t.Errorf("a folder of %d files: %v, %q", bodyMaxLines+1, e, *texts)
	}
	*texts = nil
	resetApproval()
	invRun(t, "database", "postgres", "restore", "pg", "--from", archive, "--run-on", "web", "--allow-dangerous", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "the archive "+archive) || !strings.Contains((*texts)[0], "SHA-256") {
		t.Errorf("a pg_dump archive: %q", *texts)
	}
}

// Deep indentation keeps its nesting in the window (C111): past the
// longest run of spaces the window shows, the line says how many more.
func TestBodyKeepsDeepIndent(t *testing.T) {
	a := bodyLine(tcl, strings.Repeat(" ", maxSpaces)+"key: a")
	b := bodyLine(tcl, strings.Repeat(" ", maxSpaces+4)+"key: b")
	if len(a) != 1 || len(b) != 1 || strings.TrimSpace(a[0]) == "key: a" && strings.TrimSpace(b[0]) == "key: b" && len(a[0])-len("key: a") == len(b[0])-len("key: b") {
		t.Errorf("16 and 20 spaces look the same: %q %q", a, b)
	}
	if !strings.Contains(b[0], "+4") {
		t.Errorf("the extra indent is not named: %q", b)
	}
}
