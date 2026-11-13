package cli

import (
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// libpq refuses komando's ca= option: it leaves the URL, and the tool
// checks the certificate fully against the CA's file instead. The other
// options stay as written (libpq reads %20, not +, as a space).
func TestLibpqCAURL(t *testing.T) {
	const file = "/tmp/komando-ca-x/ca.crt"
	for raw, want := range map[string]string{
		"postgres://app@db.internal/app?ca=secret:pg-ca": "postgres://app@db.internal/app?sslmode=verify-full&sslrootcert=/tmp/komando-ca-x/ca.crt",
		"postgres://app@db.internal:5432/app?sslmode=require&ca=secret:pg-ca&options=-c%20search_path%3Dapp&application_name=a+b": "postgres://app@db.internal:5432/app?options=-c%20search_path%3Dapp&application_name=a+b&sslmode=verify-full&sslrootcert=/tmp/komando-ca-x/ca.crt",
		// the CA named by ca= is the one komando checks against: a path
		// from this computer, or a weaker mode, does not go along
		"postgresql://app@db.internal/app?sslrootcert=/etc/ssl/db.pem&sslmode=verify-ca&ca=secret:pg-ca&": "postgresql://app@db.internal/app?sslmode=verify-full&sslrootcert=/tmp/komando-ca-x/ca.crt",
		"postgres://app@h1:5432,h2:5432/app?target_session_attrs=read-write&%63a=secret:pg-ca":            "postgres://app@h1:5432,h2:5432/app?target_session_attrs=read-write&sslmode=verify-full&sslrootcert=/tmp/komando-ca-x/ca.crt",
	} {
		if got := libpqCAURL(raw, file); got != want {
			t.Errorf("%s\n got %s\nwant %s", raw, got, want)
		}
	}
	// a temporary folder here may hold any character
	got := libpqCAURL("postgres://app@db/app?ca=secret:x", `/Users/A B/tmp&x=1/ca.crt`)
	u, err := url.Parse(got)
	if err != nil || u.Query().Get("sslrootcert") != `/Users/A B/tmp&x=1/ca.crt` || strings.Contains(got, "+") {
		t.Errorf("escaped path: %s (%v)", got, err)
	}
}

// The script itself, run by sh with a stand-in pg_dump: the CA lands in
// a private folder the tool reads, the rest of stdin (an archive to
// restore) reaches the tool untouched, and the folder is gone once the
// tool has ended. A folder that is already there is never used.
func TestToolScriptCA(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the tool script runs in a POSIX shell")
	}
	bin := t.TempDir()
	fake := `#!/bin/sh
echo "pw=$PGPASSWORD"
for a; do case $a in *sslrootcert=*) f=${a##*sslrootcert=};; esac; done
echo "dir=$(ls -ld "${f%/*}" | cut -c1-10)"
printf 'ca<<%s>>\n' "$(cat "$f")"
printf 'stdin<<%s>>\n' "$(cat)"
`
	if err := os.WriteFile(filepath.Join(bin, "pg_dump"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	caPEM, _ := testRegistryCert(t, "db.internal")
	dir := filepath.Join(t.TempDir(), "komando-ca-test")
	argv := []string{"pg_dump", "--dbname", libpqCAURL("postgres://app@db.internal/app?ca=secret:pg-ca", dir+"/ca.crt"), "--format=custom"}
	run := func() (string, error) {
		cmd := exec.Command("sh", "-c", toolScript(argv, "PGPASSWORD", dir, true))
		cmd.Stdin = strings.NewReader("s3cret\n" + string(caPEM) + "\nPGDMP archive\nbytes")
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	got, err := run()
	if err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	for _, want := range []string{"pw=s3cret\n", "dir=drwx------\n", "ca<<" + strings.TrimSpace(string(caPEM)) + ">>\n", "stdin<<PGDMP archive\nbytes>>\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the CA's folder is still there after pg_dump ended")
		}
	}

	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("someone else's CA"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = run()
	if err == nil || !strings.Contains(got, "cannot make") || strings.Contains(got, "pw=") {
		t.Errorf("a folder that was there: %v\n%s", err, got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ca.crt")); string(b) != "someone else's CA" {
		t.Errorf("the folder that was there changed: %q", b)
	}
}

// When the tool runs on this computer, komando writes the CA's file
// itself and removes it afterwards.
func TestToolWithCALocal(t *testing.T) {
	invHome(t)
	caPEM, _ := testRegistryCert(t, "db.internal")
	if err := vault.Set("db-ca", string(caPEM)); err != nil {
		t.Fatal(err)
	}
	c := &store.Conn{Name: "pg", URL: "postgres://app@db.internal/app?ca=secret:db-ca"}
	tool := dumpTool{dump: []string{"pg_dump"}, passwordEnv: "PGPASSWORD"}
	_, argv, ca, err := toolWithCA(c, nil, tool, []string{"pg_dump", "--dbname", c.URL})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(ca.file()); string(b) != string(caPEM) {
		t.Errorf("CA file holds %q", b)
	}
	if dir, lines := ca.onServer(); dir != "" || lines != "" {
		t.Errorf("a local CA goes to no server: %q %q", dir, lines)
	}
	if u, _ := url.Parse(argv[2]); u.Query().Get("sslrootcert") != ca.file() || u.Query().Has("ca") {
		t.Errorf("argv: %q", argv)
	}
	ca.remove()
	if _, err := os.Stat(ca.dir); !os.IsNotExist(err) {
		t.Errorf("CA folder left: %v", err)
	}
	// the --version probe connects nowhere: no CA for it
	if _, _, ca, err := toolWithCA(c, nil, dumpTool{passwordEnv: "PGPASSWORD"}, []string{"pg_dump", "--version"}); ca != nil || err != nil {
		t.Errorf("version probe: %v %v", ca, err)
	}
}

// TestDumpOnHostCA: a conn with ?ca=secret:NAME dumps and restores with
// the tools on a server. The CA follows the password line on stdin (never
// on the command line), libpq gets sslrootcert= and verify-full instead of
// ca=, and mysqldump --ssl-ca with a checked TLS connection.
func TestDumpOnHostCA(t *testing.T) {
	invHome(t)
	srv := startFakeServer(t)
	const pw = "s3cret-Pa55"
	t.Setenv("KOMANDO_TEST_DB_PW", pw)
	caPEM, _ := testRegistryCert(t, "db.internal")
	ca := string(caPEM)
	if err := vault.Set("db-ca", "Our CA, from the cloud console\n\n"+ca); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "conn", "add", "pg", "postgres://app@db.internal:5432/app?ca=secret:db-ca&application_name=nightly%20backup", "--password-ref", "env:KOMANDO_TEST_DB_PW")
	mustRun(t, "conn", "add", "shop", "mysql://shop@db.internal:3306/shop?ca=secret:db-ca", "--password-ref", "env:KOMANDO_TEST_DB_PW")
	mustRun(t, "conn", "add", "lost", "postgres://app@db.internal:5432/app?ca=secret:no-such-ca", "--password-ref", "env:KOMANDO_TEST_DB_PW")
	dir := t.TempDir()
	run := func(args ...string) (map[string]any, *out.Error) {
		return invRun(t, append([]string{"--host-key-policy", "accept-new"}, args...)...)
	}
	caDir := regexp.MustCompile(`/tmp/komando-ca-[a-z2-7]{26}\b`).FindString

	srv.reply("PGDMP archive bytes")
	to := filepath.Join(dir, "app.dump")
	if _, e := run("db", "dump", "pg", "--to", to, "--format", "custom", "--run-on", "dev"); e != nil {
		t.Fatal(e)
	}
	ex := srv.take()
	if len(ex) != 1 {
		t.Fatalf("execs: %+v", ex)
	}
	if ex[0].stdin != pw+"\n"+ca+"\n" {
		t.Errorf("stdin is not the password line, the CA and an empty line: %q", ex[0].stdin)
	}
	d := caDir(ex[0].cmd)
	if d == "" || strings.Count(ex[0].cmd, d) != 2 { // KOMANDO_CA= and sslrootcert=
		t.Errorf("CA folder %q in:\n%s", d, ex[0].cmd)
	}
	for _, want := range []string{"sslmode=verify-full", "sslrootcert=" + d + "/ca.crt", "application_name=nightly%20backup", `mkdir -m 700 "$KOMANDO_CA"`, `exec "$@"`} {
		if !strings.Contains(ex[0].cmd, want) {
			t.Errorf("command lacks %q:\n%s", want, ex[0].cmd)
		}
	}
	if strings.Contains(ex[0].cmd, "ca=secret") || strings.Contains(ex[0].cmd, "BEGIN CERTIFICATE") || strings.Contains(ex[0].cmd, pw) {
		t.Errorf("command line:\n%s", ex[0].cmd)
	}

	// an archive restore sends the CA ahead of the archive
	srv.reply()
	if _, e := run("db", "restore", "pg", "--from", to, "--run-on", "dev", "--allow-dangerous"); e != nil {
		t.Fatal(e)
	}
	ex = srv.take()
	if len(ex) != 1 || ex[0].stdin != pw+"\n"+ca+"\nPGDMP archive bytes" || !strings.Contains(ex[0].cmd, "pg_restore") {
		t.Fatalf("restore execs: %+v", ex)
	}
	if caDir(ex[0].cmd) == d {
		t.Error("each run gets a new CA folder")
	}

	// mysqldump: --ssl-ca, and ca= alone asks for a checked connection;
	// the version probe before it gets no CA
	for version, flag := range map[string]string{
		"mysqldump  Ver 8.0.36 for Linux on x86_64 (MySQL Community Server - GPL)\n":  "--ssl-mode=VERIFY_IDENTITY",
		"mysqldump from 11.4.2-MariaDB, client 10.19 for debian-linux-gnu (x86_64)\n": "--ssl-verify-server-cert",
	} {
		srv.reply(version)
		if _, e := run("db", "dump", "shop", "--to", filepath.Join(dir, "shop"+flag[6:9]+".sql"), "--run-on", "dev"); e != nil {
			t.Fatal(e)
		}
		ex = srv.take()
		if len(ex) != 2 || !strings.Contains(ex[0].cmd, "--version") || strings.Contains(ex[0].cmd, "KOMANDO_CA") || ex[0].stdin != pw+"\n" {
			t.Fatalf("mysqldump probe: %+v", ex)
		}
		d := caDir(ex[1].cmd)
		for _, want := range []string{flag, "--ssl-ca=" + d + "/ca.crt"} {
			if !strings.Contains(ex[1].cmd, want) {
				t.Errorf("mysqldump command lacks %q:\n%s", want, ex[1].cmd)
			}
		}
		if ex[1].stdin != pw+"\n"+ca+"\n" {
			t.Errorf("mysqldump stdin: %q", ex[1].stdin)
		}
	}

	// a CA that is not in the vault stops before the server is reached
	if _, e := run("db", "dump", "lost", "--to", filepath.Join(dir, "lost.dump"), "--format", "custom", "--run-on", "dev"); e == nil || e.Code != "SECRET_NOT_FOUND" {
		t.Errorf("missing CA: %+v", e)
	}
	if ex := srv.take(); len(ex) != 0 {
		t.Errorf("reached the server: %+v", ex)
	}
}
