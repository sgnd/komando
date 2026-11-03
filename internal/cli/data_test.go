package cli

import (
	"bytes"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/out"
)

func TestDisplayWidth(t *testing.T) {
	for s, want := range map[string]int{"abc": 3, "日本": 4, "🎉": 2, "é": 1, "é": 1, "Ünïcødé 日本 🎉": 15} {
		if got := displayWidth(s); got != want {
			t.Errorf("%q: %d, want %d", s, got, want)
		}
	}
	if got := truncateWidth("日本語のテキスト", 9); got != "日本語..." {
		t.Errorf("truncate: %q", got)
	}
}

// Columns line up by terminal width, also next to wide characters.
func TestLayoutTableWide(t *testing.T) {
	tab := layoutTable([]string{"name", "n"}, [][]string{{"日本", "1"}, {"abcdef", "2"}})
	lines := strings.Split(strings.TrimSpace(tab), "\n")
	col := -1
	for _, l := range lines {
		idx := strings.LastIndex(l, " ") + 1
		w := displayWidth(l[:idx])
		if col >= 0 && w != col {
			t.Fatalf("misaligned:\n%s", tab)
		}
		col = w
	}
}

func TestCellText(t *testing.T) {
	if got := cellText(map[string]string{"base64": "AP8="}, false); got != `\x00ff` {
		t.Errorf("binary: %q", got)
	}
	if got := cellText(map[string]string{"base64": ""}, false); got != `\x` {
		t.Errorf("empty binary: %q", got)
	}
	if got := cellText("a\tb\nc", false); got != `a\tb\nc` {
		t.Errorf("text: %q", got)
	}
}

func TestQueryTruncationHint(t *testing.T) {
	d := queryData{Result: &dbx.Result{Results: []dbx.StatementResult{{Columns: []dbx.Column{{Name: "n"}}, Rows: [][]any{{int64(1)}}, RowCount: 1, Truncated: "bytes"}}}}
	if s := d.Text(); !strings.Contains(s, "--max-output") || strings.Contains(s, "--limit") {
		t.Errorf("bytes cap:\n%s", s)
	}
	d.Results[0].Truncated = "rows"
	if s := d.Text(); !strings.Contains(s, "--limit") {
		t.Errorf("row cap:\n%s", s)
	}
}

func TestWriteDelimited(t *testing.T) {
	res := &dbx.Result{Results: []dbx.StatementResult{{Columns: []dbx.Column{{Name: "a"}, {Name: "b"}},
		Rows: [][]any{{int64(1), nil}, {"x,y", "tab\there"}}}}}
	var b bytes.Buffer
	if err := writeDelimited(&b, res, false); err != nil || b.String() != "a,b\n1,\n\"x,y\",tab\there\n" {
		t.Errorf("csv %v: %q", err, b.String())
	}
	b.Reset()
	if err := writeDelimited(&b, res, true); err != nil || b.String() != "a\tb\n1\t\nx,y\ttab\\there\n" {
		t.Errorf("tsv %v: %q", err, b.String())
	}
}

func TestSQLFlagError(t *testing.T) {
	e, ok := sqlFlagError(nil, errors.New("unknown flag: -- note\nselect 1")).(*out.Error)
	if !ok || e.Exit != out.ExitUsage || !strings.Contains(e.Hint, "-f -") {
		t.Errorf("got %v", e)
	}
	plain := errors.New("unknown flag: --nope")
	if sqlFlagError(nil, plain) != plain {
		t.Error("a real unknown flag must stay as it is")
	}
}

func TestParseTTL(t *testing.T) {
	for in, want := range map[string]int64{"": 0, "0": 0, "30m": 1800, "2d": 172800} {
		d, err := parseTTL(in)
		if err != nil || int64(d.Seconds()) != want {
			t.Errorf("%q: %v %v", in, d, err)
		}
	}
	for _, bad := range []string{"-5s", "-1d", "soon"} {
		if _, err := parseTTL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUploadKeyAndDownloadDest(t *testing.T) {
	if got := uploadKey("/tmp/a.txt", "dir/"); got != "dir/a.txt" {
		t.Errorf("folder key: %s", got)
	}
	if got := uploadKey("/tmp/a.txt", ""); got != "a.txt" {
		t.Errorf("no key: %s", got)
	}
	if got := uploadKey("/tmp/a.txt", "b.txt"); got != "b.txt" {
		t.Errorf("key: %s", got)
	}
	dir := t.TempDir()
	if got := downloadDest(dir, "x/report.pdf"); got != filepath.Join(dir, "report.pdf") {
		t.Errorf("existing folder: %s", got)
	}
	if got := downloadDest("new/", "x/report.pdf"); got != filepath.Join("new", "report.pdf") {
		t.Errorf("trailing slash: %s", got)
	}
	if got := downloadDest("", "x/report.pdf"); got != "report.pdf" {
		t.Errorf("default: %s", got)
	}
	if got := downloadDest(filepath.Join(dir, "f.pdf"), "x/report.pdf"); got != filepath.Join(dir, "f.pdf") {
		t.Errorf("file: %s", got)
	}
}

func TestWriteReplacing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeReplacing(p, func(tmp string) error { return os.WriteFile(tmp, []byte("new"), 0o600) })
	if b, _ := os.ReadFile(p); err != nil || string(b) != "new" {
		t.Errorf("%v %q", err, b)
	}
	// a failed download leaves the old file alone
	_ = writeReplacing(p, func(string) error { return errors.New("cut") })
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("after failure: %q", b)
	}
}

func TestClientInstallHint(t *testing.T) {
	cases := []struct{ goos, distro, client, want string }{
		{"darwin", "", "psql", "brew install libpq"},
		{"darwin", "", "mysql", "brew install mysql-client"},
		{"darwin", "", "sqlite3", "brew install sqlite"},
		{"linux", "ubuntu debian", "psql", "sudo apt install postgresql-client"},
		{"linux", "debian", "mysql", "sudo apt install default-mysql-client"},
		{"linux", "rocky rhel centos fedora", "psql", "sudo dnf install postgresql"},
		{"linux", "fedora", "mysql", "sudo dnf install mysql"},
		{"linux", "", "sqlite3", "with your package manager"},
		{"windows", "", "psql", "with your package manager"},
	}
	for _, c := range cases {
		h := clientInstallHint(c.goos, c.distro, c.client, "pg")
		if !strings.Contains(h, c.want) || !strings.Contains(h, "komando db query pg 'select 1'") {
			t.Errorf("%s %s %s: %s", c.goos, c.distro, c.client, h)
		}
	}
}

func TestToolFailedCodes(t *testing.T) {
	for stderr, code := range map[string]string{
		`pg_dump: error: FATAL:  password authentication failed for user "app"`: "DB_AUTH",
		`mysqldump: Got error: 1045: Access denied for user 'shop'@'%'`:         "DB_AUTH",
		`pg_dump: error: FATAL:  database "nodb" does not exist`:                "DB_NOT_FOUND",
		`mysqldump: Got error: 1049: Unknown database 'nodb' when selecting`:    "DB_NOT_FOUND",
		`psql:x.sql:3: ERROR:  relation "t" does not exist`:                     "TOOL_FAILED",
	} {
		e := toolFailed("tool", "local", 1, stderr, "c").(*out.Error)
		if e.Code != code {
			t.Errorf("%q: %s", stderr, e.Code)
		}
		if code == "DB_AUTH" && e.Exit != out.ExitConnect || code == "DB_NOT_FOUND" && e.Exit != out.ExitNotFound {
			t.Errorf("%q: exit %d", stderr, e.Exit)
		}
	}
}

func TestLinkWarning(t *testing.T) {
	u, _ := url.Parse("http://s3:3900/b/k?sig=1")
	if w := linkWarning(u, "bastion"); !strings.Contains(w, "s3:3900") || !strings.Contains(w, "bastion") {
		t.Errorf("warning: %s", w)
	}
	if linkWarning(u, "") != "" {
		t.Error("direct conn warned")
	}
}

func TestDBTextViews(t *testing.T) {
	info := dbInfoData{"version": "17", "size_bytes": int64(8 << 20), "uptime_seconds": int64(7200), "connections": int64(3), "max_connections": int64(100)}
	s := info.Text()
	if !strings.Contains(s, "8.0 MiB") || !strings.Contains(s, "2h") || !strings.Contains(s, "3 of 100") {
		t.Errorf("info:\n%s", s)
	}
	a := activityData{Sessions: []map[string]any{{"pid": int64(42), "user": "app", "database": "app", "running_seconds": int64(90), "state": "active", "query": "select\n  pg_sleep(30)"}}}
	if s := a.Text(); !strings.Contains(s, "PID") || !strings.Contains(s, "1m") || !strings.Contains(s, "select pg_sleep(30)") {
		t.Errorf("activity:\n%s", s)
	}
	sz := sizesData{"tables": []map[string]any{{"name": "t", "rows": int64(2), "total_bytes": int64(32768), "index_bytes": int64(16384)}}}
	if s := sz.Text(); !strings.Contains(s, "32.0 KiB") || !strings.Contains(s, "TOTAL") {
		t.Errorf("sizes:\n%s", s)
	}
}
