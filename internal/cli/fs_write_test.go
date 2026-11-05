package cli

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/sgnd/komando/internal/out"
)

// localSFTP is an SFTP server in this process, over pipes, serving the
// local file system: writeRemote runs against it as against a server.
func localSFTP(t *testing.T) *sftp.Client {
	t.Helper()
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	srv, err := sftp.NewServer(struct {
		io.Reader
		io.WriteCloser
	}{sr, sw})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	sc, err := sftp.NewClientPipe(cr, cw)
	if err != nil {
		t.Fatal(err)
	}
	// the pipes first: the client waits for its reader to stop
	t.Cleanup(func() { cw.Close(); sw.Close(); sc.Close(); srv.Close() })
	return sc
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// peekReader looks at the staged temporary file while its content goes in.
type peekReader struct {
	dir   string
	parts []string
	modes []os.FileMode
}

func (r *peekReader) Read(b []byte) (int, error) {
	ms, _ := filepath.Glob(filepath.Join(r.dir, ".komando-*"))
	for _, m := range ms {
		if fi, err := os.Stat(m); err == nil {
			r.modes = append(r.modes, fi.Mode().Perm())
		}
	}
	if len(r.parts) == 0 {
		return 0, io.EOF
	}
	n := copy(b, r.parts[0])
	r.parts = r.parts[1:]
	return n, nil
}

// The staged file holds secrets ({{secret:NAME}} already filled in): only
// the SSH user may read it while it is written, whatever the final mode.
func TestWriteStagesPrivately(t *testing.T) {
	sc := localSFTP(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &peekReader{dir: dir, parts: []string{"DB_PASSWORD=", "s3cret\n"}}
	res, err := writeRemoteFrom(context.Background(), nil, sc, p, r, writeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.modes) == 0 {
		t.Fatal("the staged file was not seen")
	}
	for _, m := range r.modes {
		if m != 0o600 {
			t.Fatalf("staged file was %04o while the content went in", m)
		}
	}
	if got := read(t, p); got != "DB_PASSWORD=s3cret\n" || mode(t, p) != 0o644 || res["mode"] != "0644" {
		t.Fatalf("file %q mode %04o result %v", got, mode(t, p), res)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".komando-*")); left != nil {
		t.Fatalf("staged file left: %v", left)
	}
}

// noModeSFTP is OpenSSH's sftp-server with setting modes forbidden, as on
// storage boxes and SFTP-only accounts; it creates files with umask.
func noModeSFTP(t *testing.T, umask string) *sftp.Client {
	t.Helper()
	var bin string
	for _, b := range []string{"/usr/libexec/sftp-server", "/usr/lib/openssh/sftp-server", "/usr/lib/ssh/sftp-server"} {
		if _, err := os.Stat(b); err == nil {
			bin = b
		}
	}
	if bin == "" {
		t.Skip("no OpenSSH sftp-server here")
	}
	cmd := exec.Command(bin, "-u", umask, "-e", "-l", "QUIET", "-P", "setstat,fsetstat,lsetstat")
	w, _ := cmd.StdinPipe()
	r, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc, err := sftp.NewClientPipe(r, w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sc.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return sc
}

// A server that refuses to set modes must not leave a 0600 file at its
// default 0644 while komando reports 0600: the write fails, nothing changes.
func TestWriteFailsWhenModeIsRefused(t *testing.T) {
	sc := noModeSFTP(t, "022")
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte("DB_PASSWORD=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := writeRemote(context.Background(), nil, sc, p, []byte("DB_PASSWORD=new\n"), writeOpts{backup: true})
	if e, ok := err.(*out.Error); !ok || e.Code != "CHMOD_FAILED" || !strings.Contains(e.Hint, "does not allow setting file modes") {
		t.Fatalf("got %v, want CHMOD_FAILED", err)
	}
	if read(t, p) != "DB_PASSWORD=old\n" || mode(t, p) != 0o600 {
		t.Fatal("the file changed")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*.*")); len(left) != 0 {
		t.Fatalf("files left: %v", left)
	}
}

// The same server creating files 0600: nothing is more open than asked,
// so writes (and backups) work, and the result says the mode it got.
func TestWriteWorksWhenModesCannotBeSetButFilesArePrivate(t *testing.T) {
	sc := noModeSFTP(t, "077")
	dir := t.TempDir()
	for _, c := range []struct {
		name string
		was  os.FileMode
		note bool
	}{{".env", 0o600, false}, {"site.conf", 0o644, true}} {
		p := filepath.Join(dir, c.name)
		if err := os.WriteFile(p, []byte("old\n"), c.was); err != nil {
			t.Fatal(err)
		}
		res, err := writeRemote(context.Background(), nil, sc, p, []byte("new\n"), writeOpts{backup: true})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if read(t, p) != "new\n" || mode(t, p) != 0o600 || res["mode"] != "0600" || (res["note"] != nil) != c.note {
			t.Fatalf("%s: mode %04o result %v", c.name, mode(t, p), res)
		}
		if b, _ := res["backup"].(string); read(t, b) != "old\n" {
			t.Fatalf("%s: backup %v", c.name, res["backup"])
		}
	}
}

// --backup never overwrites a backup (an earlier one, or one a person made)
// and never writes through a link planted under the backup's name.
func TestBackupNeverOverwrites(t *testing.T) {
	sc := localSFTP(t)
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte("v0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(content string) map[string]any {
		t.Helper()
		res, err := writeRemote(context.Background(), nil, sc, p, []byte(content), writeOpts{backup: true})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	r1 := write("v1\n")
	if r1["backup"] != p+".bak" || read(t, p+".bak") != "v0\n" || mode(t, p+".bak") != 0o600 {
		t.Fatalf("first backup: %v %q", r1["backup"], read(t, p+".bak"))
	}
	r2 := write("v2\n")
	b2, _ := r2["backup"].(string)
	if !regexp.MustCompile(`\.env\.bak\.\d{8}T\d{6}Z$`).MatchString(b2) {
		t.Fatalf("second backup at %q", b2)
	}
	if read(t, p+".bak") != "v0\n" || read(t, b2) != "v1\n" || read(t, p) != "v2\n" {
		t.Fatalf("after two edits: .bak %q, %s %q, file %q", read(t, p+".bak"), b2, read(t, b2), read(t, p))
	}

	// a link someone planted where the backup goes
	q := filepath.Join(dir, "app.conf")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(q, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, q+".bak"); err != nil {
		t.Fatal(err)
	}
	res, err := writeRemote(context.Background(), nil, sc, q, []byte("new\n"), writeOpts{backup: true})
	if err != nil {
		t.Fatal(err)
	}
	if read(t, victim) != "keep me\n" || mode(t, victim) != 0o644 {
		t.Fatalf("the backup wrote through the link: victim %q %04o", read(t, victim), mode(t, victim))
	}
	if b, _ := res["backup"].(string); b == q+".bak" || read(t, b) != "old\n" {
		t.Fatalf("backup at %v", res["backup"])
	}
}

func TestBackupName(t *testing.T) {
	now := time.Date(2026, 11, 5, 10, 15, 0, 0, time.FixedZone("WIB", 7*3600))
	cases := []struct {
		taken []string
		want  string
	}{
		{nil, "/etc/x.bak"},
		{[]string{"/etc/x.bak"}, "/etc/x.bak.20261105T031500Z"},
		{[]string{"/etc/x.bak", "/etc/x.bak.20261105T031500Z"}, "/etc/x.bak.20261105T031500Z-2"},
		{[]string{"/etc/x.bak", "/etc/x.bak.20261105T031500Z", "/etc/x.bak.20261105T031500Z-2"}, "/etc/x.bak.20261105T031500Z-3"},
	}
	for _, c := range cases {
		got := backupName("/etc/x", now, func(n string) bool {
			for _, t := range c.taken {
				if t == n {
					return true
				}
			}
			return false
		})
		if got != c.want {
			t.Errorf("taken %v: %s, want %s", c.taken, got, c.want)
		}
	}
}

// The --sudo backup runs as root on the server; here it runs as the test
// user in a plain shell, which is enough to check what it writes where.
func TestSudoBackupScript(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "nginx.conf")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(p, []byte("orig\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 5, 3, 15, 0, 0, time.UTC)
	run := func() string {
		t.Helper()
		script := "set -e; p='" + p + "'; k=-; " + sudoBackupScript("/nonexistent-tmp", now) + `printf '%s' "$k"`
		b, err := exec.Command("sh", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, b)
		}
		return string(b)
	}
	if k := run(); k != "bak" || read(t, p+".bak") != "orig\n" || mode(t, p+".bak") != 0o600 {
		t.Fatalf("first: k=%q", k)
	}
	if k := run(); k != "bak.20261105T031500Z" {
		t.Fatalf("second: k=%q", k)
	}
	if k := run(); k != "bak.20261105T031500Z-2" {
		t.Fatalf("third: k=%q", k)
	}
	// a planted link is never written through
	q := filepath.Join(dir, "sites.conf")
	if err := os.WriteFile(q, []byte("site\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, q+".bak"); err != nil {
		t.Fatal(err)
	}
	p = q
	if k := run(); k != "bak.20261105T031500Z" || read(t, victim) != "keep me\n" || read(t, q+"."+k) != "site\n" {
		t.Fatalf("with a planted link: k=%q victim %q", k, read(t, victim))
	}
	// no file yet: no backup
	p = filepath.Join(dir, "new.conf")
	if k := run(); k != "-" {
		t.Fatalf("new file: k=%q", k)
	}
}

// An AI agent edits the file as it saw it: a value komando hid is never
// copied into the diff or uncovered in the file, and whether --old matches
// never depends on it.
func TestReplaceWorksOnTheMaskedView(t *testing.T) {
	src := "A=1\nDB_PASSWORD=Sup3rS3cretValue\nSTRIPE_KEY=VaultedTok3n99\nnote VaultedTok3n99\nB=2\n" +
		"DSN=postgres://u:S3cretPw@db/x\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
	tail := "DSN=postgres://u:S3cretPw@db/x\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
	p := &out.Printer{Mask: true, Secrets: func() map[string]string { return map[string]string{"stripe": "VaultedTok3n99"} }}
	cases := []struct {
		name, old, new string
		regex          bool
		want           string // the file afterwards; "" for an error
		code           string
	}{
		{"capture copies a hidden value", `(?m)^DB_PASSWORD=(.*)$`, "X=$1", true, "", "HIDDEN_VALUE"},
		{"capture copies a vault value", `(?m)^note (.*)$`, "X=$1", true, "", "HIDDEN_VALUE"},
		{"guessing the first letter", `(?m)^DB_PASSWORD=S`, "zz", true, "", "NO_MATCH"},
		{"guessing a wrong letter", `(?m)^DB_PASSWORD=A`, "zz", true, "", "NO_MATCH"},
		{"exact text guessing", "DB_PASSWORD=Sup3r", "zz", false, "", "NO_MATCH"},
		{"cuts into a hidden value", "den]\nSTRIPE", "x", false, "", "HIDDEN_VALUE"},
		{"rename the key of a hidden value", "DB_PASSWORD=", "X=", false, "", "HIDDEN_VALUE"},
		{"strip the scheme of a URL password", "postgres://", "", false, "", "HIDDEN_VALUE"},
		{"strip Bearer from a token", "Authorization: Bearer ", "X: ", false, "", "HIDDEN_VALUE"},
		{"replace a hidden line by regex", `(?m)^DB_PASSWORD=.*$`, "DB_PASSWORD=n3w-value", true,
			"A=1\nDB_PASSWORD=n3w-value\nSTRIPE_KEY=VaultedTok3n99\nnote VaultedTok3n99\nB=2\n" + tail, ""},
		{"replace a hidden value by [hidden]", "STRIPE_KEY=[secret:stripe]", "STRIPE_KEY=rotated-key", false,
			"A=1\nDB_PASSWORD=Sup3rS3cretValue\nSTRIPE_KEY=rotated-key\nnote VaultedTok3n99\nB=2\n" + tail, ""},
		{"[hidden] in --old", "DB_PASSWORD=[hidden]", "DB_PASSWORD={{x}}", false,
			"A=1\nDB_PASSWORD={{x}}\nSTRIPE_KEY=VaultedTok3n99\nnote VaultedTok3n99\nB=2\n" + tail, ""},
		{"rename the key and replace the value", "DB_PASSWORD=[hidden]", "X=plain", false,
			"A=1\nX=plain\nSTRIPE_KEY=VaultedTok3n99\nnote VaultedTok3n99\nB=2\n" + tail, ""},
		{"edit next to a hidden value", `(?m)^B=(\d)$`, "B=$1$1", true,
			"A=1\nDB_PASSWORD=Sup3rS3cretValue\nSTRIPE_KEY=VaultedTok3n99\nnote VaultedTok3n99\nB=22\n" + tail, ""},
		{"change the host of a URL", "@db/x", "@db2/x", false,
			"A=1\nDB_PASSWORD=Sup3rS3cretValue\nSTRIPE_KEY=VaultedTok3n99\nnote VaultedTok3n99\nB=2\n" +
				"DSN=postgres://u:S3cretPw@db2/x\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz\n", ""},
	}
	for _, c := range cases {
		var re *regexp.Regexp
		if c.regex {
			re = regexp.MustCompile(c.old)
		}
		pl, err := planReplace(p, src, c.old, c.new, re, false, "f")
		if c.code != "" {
			if e, ok := err.(*out.Error); !ok || e.Code != c.code {
				t.Errorf("%s: %v, want %s", c.name, err, c.code)
			}
			continue
		}
		if err != nil || pl.updated != c.want || !pl.changed {
			t.Errorf("%s: %q, changed %v, %v", c.name, pl.updated, pl.changed, err)
			continue
		}
		diff := unifiedDiff(pl.view, pl.shown, 3)
		for _, v := range []string{"Sup3rS3cretValue", "VaultedTok3n99", "S3cretPw", "abcdefghijklmnop"} {
			if strings.Contains(diff, v) {
				t.Errorf("%s: the diff shows a hidden value:\n%s", c.name, diff)
			}
		}
	}
}

// Whether --new happens to equal a hidden value must not show: a right
// and a wrong guess give the same answer.
func TestReplaceAnswersTheSameForAnyGuess(t *testing.T) {
	src := "DB_PASSWORD=hunter2xyz\n"
	p := &out.Printer{Mask: true}
	right, err1 := planReplace(p, src, "DB_PASSWORD=[hidden]", "DB_PASSWORD=hunter2xyz", nil, false, "f")
	wrong, err2 := planReplace(p, src, "DB_PASSWORD=[hidden]", "DB_PASSWORD=wrongguess", nil, false, "f")
	if err1 != nil || err2 != nil || !right.changed || !wrong.changed || right.n != wrong.n ||
		unifiedDiff(right.view, right.shown, 3) != strings.ReplaceAll(unifiedDiff(wrong.view, wrong.shown, 3), "wrongguess", "hunter2xyz") {
		t.Fatalf("right guess %+v (%v), wrong guess %+v (%v)", right, err1, wrong, err2)
	}
	// "already applied?" never confirms a guess either
	for _, guess := range []string{"DB_PASSWORD=hunter2xyz", "DB_PASSWORD=wrongguess"} {
		if _, err := planReplace(p, src, "DB_PASSWORD=nothere", guess, nil, false, "f"); err == nil {
			t.Errorf("%s: reported as already there", guess)
		}
	}
	// a person sees what the server sent: the same bytes are no change
	pl, err := planReplace(&out.Printer{}, src, "DB_PASSWORD=hunter2xyz", "DB_PASSWORD=hunter2xyz", nil, false, "f")
	if err != nil || pl.changed {
		t.Fatalf("person: %+v %v", pl, err)
	}
}

// AGENTS.md rule 9 rotates a secret into the vault with
// --old 'NAME=[hidden]' --new 'NAME={{secret:VAULT}}'. Run again (a retry,
// or a rollout to a host already done) it is no change, not NO_MATCH.
// --new arrives here with the vault value filled in, as fs replace has it.
func TestReplaceRotationRunsTwice(t *testing.T) {
	p := &out.Printer{Mask: true, Secrets: func() map[string]string { return map[string]string{"db": "VaultedPw4242"} }}
	newS := "DB_PASSWORD=VaultedPw4242"
	pl, err := planReplace(p, "DB_PASSWORD=oldplainpw\n", "DB_PASSWORD=[hidden]", newS, nil, false, "f")
	if err != nil || !pl.changed || pl.updated != newS+"\n" {
		t.Fatalf("first run: %+v %v", pl, err)
	}
	pl, err = planReplace(p, pl.updated, "DB_PASSWORD=[hidden]", newS, nil, false, "f")
	if err != nil || pl.changed || pl.note == "" {
		t.Fatalf("second run: %+v %v", pl, err)
	}
}

// fs write: for an AI agent, a file with a hidden value always counts as
// changed, so --if-changed and would_change never confirm a guessed file.
func TestSameForAgent(t *testing.T) {
	saved := out.P.Mask
	defer func() { out.P.Mask = saved }()
	old := []byte("DB_PASSWORD=hunter2xyz\n")
	out.P.Mask = false
	if !sameForAgent(old, old) || sameForAgent(old, []byte("x")) {
		t.Fatal("a person compares bytes")
	}
	out.P.Mask = true
	if sameForAgent(old, old) || sameForAgent(old, []byte("DB_PASSWORD=wrongguess\n")) {
		t.Fatal("an agent learned whether its guess was right")
	}
	if !sameForAgent([]byte("PORT=8080\n"), []byte("PORT=8080\n")) {
		t.Fatal("a file with nothing hidden compares as before")
	}
}

// fs cat for an AI agent: the whole file is masked before --head/--tail
// cut it, and the hash of a file with a hidden value is left out.
func TestCatMasksBeforeCutting(t *testing.T) {
	saved := out.P.Mask
	defer func() { out.P.Mask = saved }()
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nQUJDREVGR0hJSktMTU5PUFFS\n-----END OPENSSH PRIVATE KEY-----\n"
	out.P.Mask = true
	for _, c := range []struct {
		head, tail int
		numbered   bool
	}{{0, 2, false}, {0, 2, true}, {3, 0, false}, {3, 1, true}} {
		r, err := catContent("web1", "/k", []byte("x\n"+key), false, c.head, c.tail, c.numbered)
		if err != nil || strings.Contains(r.Content, "b3Bl") || strings.Contains(r.Content, "QUJD") || r.SHA256 != "" {
			t.Errorf("head %d tail %d: %+v %v", c.head, c.tail, r, err)
		}
	}
	r, _ := catContent("web1", "/k", []byte("x\n"+key), false, 0, 0, false)
	if r.Content != "x\n[hidden: private key]\n" || r.Note == "" {
		t.Errorf("whole file: %+v", r)
	}
	if r, _ := catContent("web1", "/c", []byte("PORT=8080\n"), false, 0, 0, false); r.SHA256 == "" {
		t.Error("nothing hidden: the hash stays")
	}
	out.P.Mask = false
	if r, _ := catContent("web1", "/k", []byte(key), false, 0, 2, false); r.SHA256 == "" || !strings.Contains(r.Content, "QUJD") {
		t.Errorf("a person reads the file as it is: %+v", r)
	}
}
