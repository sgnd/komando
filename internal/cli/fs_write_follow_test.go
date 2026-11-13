//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/sshx"
)

// fakeStat is a stat stand-in for the root scripts: every path is root's
// (0 0 755) but those in $TABLE ("PATH|uid gid mode user group" lines).
// %d:%i comes from ls -i; $SWAP names a path whose %d:%i is made up, as if
// another file had been put there.
const fakeStat = `#!/bin/sh
L=; fmt=; f=
while [ $# -gt 0 ]; do case $1 in -L) L=1;; -c) shift; fmt=$1;; --) ;; *) f=$1;; esac; shift; done
if [ "$fmt" = %d:%i ]; then
  if [ -n "$SWAP" ] && [ "$f" = "$SWAP" ]; then echo 1:999999999; exit 0; fi
  if [ -n "$L" ]; then set -- $(ls -Lid "$f"); else set -- $(ls -id "$f"); fi
  echo "1:$1"; exit 0
fi
e=$(printf '%s\n' "$TABLE" | awk -F'|' -v f="$f" '$1==f {print $2}')
[ -n "$e" ] || e="0 0 755 root root"
set -- $e
case $fmt in %u) echo "$1";; '%u %g %a') echo "$1 $2 $3";; '%U %G') echo "$4 $5";; esac
`

// fakeGetfacl is a getfacl -cn stand-in: the base entries, and for a path
// in $FACL ("PATH|entry" lines) its extended entries.
const fakeGetfacl = `#!/bin/sh
for f; do :; done
printf 'user::rwx\ngroup::r-x\nother::r-x\n'
printf '%s\n' "$FACL" | awk -F'|' -v f="$f" '$1==f {print $2}'
`

// runAsRoot runs script as root would, with fakeStat, the SSH user as uid
// 1000 and table as $TABLE. It returns stdout, stderr and the exit code.
func runAsRoot(t *testing.T, script string, table map[string]string, env ...string) (string, string, int) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "stat"), []byte(fakeStat), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "getfacl"), []byte(fakeGetfacl), 0o700); err != nil {
		t.Fatal(err)
	}
	var tb []string
	for p, v := range table {
		tb = append(tb, p+"|"+v)
	}
	c := exec.Command("/bin/sh", "-c", script)
	c.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "SUDO_UID=1000", "TABLE=" + strings.Join(tb, "\n")}, env...)
	var so, se strings.Builder
	c.Stdout, c.Stderr = &so, &se
	err := c.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(so.String()), se.String(), code
}

// runFollow runs sudoWriteScript for p. It prints the path root would
// write, or exits.
func runFollow(t *testing.T, p string, table map[string]string) (string, string, int) {
	t.Helper()
	return runAsRoot(t, "p='"+p+"'; "+sudoWriteScript("/nonexistent", false)+`echo "$p"`, table)
}

func notRoot(paths ...string) map[string]string {
	m := map[string]string{}
	for _, p := range paths {
		m[p] = "33 33 755 www-data www-data"
	}
	return m
}

func TestSudoFollowOnlyRootsLinks(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	target := filepath.Join(d, "sites-available", "app")
	_ = os.MkdirAll(filepath.Dir(target), 0o755)
	_ = os.WriteFile(target, []byte("x"), 0o644)
	link := filepath.Join(d, "app.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// root's link into root's folder: followed
	if got, _, code := runFollow(t, link, nil); code != 0 || got != target {
		t.Fatalf("root's link: %q %d", got, code)
	}
	// a link another user made (an app's .env -> /etc/sudoers.d/x): stop
	if got, _, code := runFollow(t, link, notRoot(link)); code != sudoExitLink {
		t.Fatalf("another user's link followed: %q %d", got, code)
	}
	// root's link into a folder another user owns: stop
	if got, _, code := runFollow(t, link, notRoot(filepath.Dir(target))); code != sudoExitLink {
		t.Fatalf("followed into another user's folder: %q %d", got, code)
	}
	// no link: unchanged
	if got, _, code := runFollow(t, target, nil); code != 0 || got != target {
		t.Fatalf("plain file: %q %d", got, code)
	}
	// another user's link to a folder on the way (app/conf -> /etc): stop
	dl := filepath.Join(d, "conf")
	if err := os.Symlink(filepath.Dir(target), dl); err != nil {
		t.Fatal(err)
	}
	if got, _, code := runFollow(t, filepath.Join(dl, "app"), notRoot(dl)); code != sudoExitLink {
		t.Fatalf("another user's folder link followed: %q %d", got, code)
	}
	if got, _, code := runFollow(t, filepath.Join(dl, "app"), nil); code != 0 || got != target {
		t.Fatalf("root's folder link: %q %d", got, code)
	}
	// root's link to a folder that --mkdirs makes: the nearest folder
	// there is root's, so it goes on
	nl := filepath.Join(d, "new")
	if err := os.Symlink(filepath.Join(d, "sites-available", "a", "b"), nl); err != nil {
		t.Fatal(err)
	}
	if got, _, code := runFollow(t, filepath.Join(nl, "x"), nil); code != 0 || got != filepath.Join(d, "sites-available", "a", "b", "x") {
		t.Fatalf("root's link to a new folder: %q %d", got, code)
	}
	if got, _, code := runFollow(t, filepath.Join(nl, "x"), notRoot(filepath.Dir(target))); code != sudoExitLink {
		t.Fatalf("followed toward another user's folder: %q %d", got, code)
	}
	// --no-follow: a link at the path stops before anything else
	if _, _, code := runAsRoot(t, "p='"+link+"'; "+sudoWriteScript("/nonexistent", true), nil); code != 95 {
		t.Fatalf("--no-follow: %d", code)
	}
}

// O5: as root, komando writes into a folder only when no user but root and
// the SSH user can change it or a folder above it.
func TestSudoWriteRefusesSharedFolder(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	app := filepath.Join(d, "srv", "app")
	_ = os.MkdirAll(filepath.Join(app, "conf"), 0o755)
	file := filepath.Join(app, "conf", ".env")
	cases := []struct {
		name  string
		p     string
		table map[string]string
		code  int
		who   string
	}{
		{"root's folders", file, nil, 0, ""},
		{"the SSH user's folder", file, map[string]string{filepath.Dir(file): "1000 1000 755 deploy deploy"}, 0, ""},
		{"another user's folder", file, notRoot(filepath.Dir(file)), sudoExitFolder, "user www-data www-data"},
		{"another user's folder above", file, notRoot(app), sudoExitFolder, "user www-data www-data"},
		{"a group's folder", file, map[string]string{filepath.Dir(file): "0 33 775 root www-data"}, sudoExitFolder, "group root www-data"},
		{"root's group may write", file, map[string]string{filepath.Dir(file): "0 0 775 root root"}, 0, ""},
		{"everyone's folder", file, map[string]string{filepath.Dir(file): "0 0 1777 root root"}, sudoExitFolder, "everyone root root"},
		{"everyone's sticky folder above", file, map[string]string{app: "0 0 1777 root root"}, 0, ""},
		{"everyone's folder above, not sticky", file, map[string]string{app: "0 0 777 root root"}, sudoExitFolder, "everyone root root"},
		{"a new folder in another user's", filepath.Join(app, "new", "x"), notRoot(app), sudoExitFolder, "user www-data www-data"},
		{"another user in the access list", file, nil, sudoExitFolder, "acl root root"},
		{"another user in the access list above", filepath.Join(app, "conf", "x"), nil, sudoExitFolder, "acl root root"},
	}
	acl := map[string]string{
		"another user in the access list":       filepath.Dir(file) + "|user:33:rwx",
		"another user in the access list above": app + "|group:33:rwx",
	}
	for _, tc := range cases {
		_, stderr, code := runAsRoot(t, "p='"+tc.p+"'; "+sudoWriteScript("/nonexistent", false)+`echo "$p"`, tc.table, "FACL="+acl[tc.name])
		if code != tc.code {
			t.Errorf("%s: exit %d, want %d (%s)", tc.name, code, tc.code, stderr)
			continue
		}
		if tc.who != "" && !strings.Contains(stderr, sudoFolderMark+tc.who+" ") {
			t.Errorf("%s: stderr %q does not name %q", tc.name, stderr, tc.who)
		}
	}
	for _, entry := range []string{"user:33:r-x", "user:1000:rwx", "user:0:rwx", "group:0:rwx", "default:user:33:rwx", "mask::rwx"} {
		if _, stderr, code := runAsRoot(t, "p='"+file+"'; "+sudoWriteScript("/nonexistent", false), nil, "FACL="+filepath.Dir(file)+"|"+entry); code != 0 {
			t.Errorf("access list entry %s: exit %d (%s)", entry, code, stderr)
		}
	}
	e := toErr(unsafeFolder(file, sudoFolderMark+"user www-data www-data "+app+"\n"))
	if e.Code != "SHARED_FOLDER_CONFLICT" || !strings.Contains(e.Message, app) || !strings.Contains(e.Hint, "--sudo-user www-data ") ||
		!strings.Contains(e.Hint, file) || strings.Contains(e.Hint, "PATH") {
		t.Fatalf("error: %+v", e)
	}
	if e := toErr(unsafeFolder(file, sudoFolderMark+"acl root root "+app+"\n")); !strings.Contains(e.Message, "access list (ACL)") {
		t.Fatalf("access list error: %+v", e)
	}
}

// O5: fs cat --sudo (and every read as root) does not read through a link
// another user made, nor a file swapped while root opens it.
func TestSudoReadFollowsNoOtherUsersLink(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	secret := filepath.Join(d, "shadow")
	_ = os.WriteFile(secret, []byte("root-only\n"), 0o600)
	app := filepath.Join(d, "app")
	_ = os.MkdirAll(app, 0o755)
	env := filepath.Join(app, ".env")
	if err := os.Symlink(secret, env); err != nil {
		t.Fatal(err)
	}
	read := func(table map[string]string, extra ...string) (string, int) {
		got, _, code := runAsRoot(t, sudoReadScript(env, "cat"), table, extra...)
		return got, code
	}
	if got, code := read(notRoot(env)); code != sudoExitLink || got != "" {
		t.Fatalf("another user's link read: %q %d", got, code)
	}
	if got, code := read(nil); code != 0 || got != "root-only" {
		t.Fatalf("root's link: %q %d", got, code)
	}
	if got, code := read(map[string]string{env: "1000 1000 777 deploy deploy"}); code != 0 || got != "root-only" {
		t.Fatalf("the SSH user's link: %q %d", got, code)
	}
	// the name now names another file than the one opened
	if got, code := read(nil, "SWAP=./shadow"); code != sudoExitLink || got != "" {
		t.Fatalf("swapped file read: %q %d", got, code)
	}
	if _, se, code := runAsRoot(t, sudoReadScript(filepath.Join(d, "none", "x"), "cat"), nil); code == 0 || !strings.Contains(se, "No such file") {
		t.Fatalf("missing file: %d %q", code, se)
	}
	if got, _, code := runAsRoot(t, sudoReadScript(secret, "tail -c 5"), nil); code != 0 || got != "only" {
		t.Fatalf("tail: %q %d", got, code)
	}
}

// O5: logs --file F --sudo reads F as root through the same check as
// fs cat --sudo: not through a link another server user made.
func TestLogsFileSudoFollowsNoOtherUsersLink(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	secret := filepath.Join(d, "shadow")
	_ = os.WriteFile(secret, []byte("a\nroot-only\n"), 0o600)
	log := filepath.Join(d, "app.log")
	if err := os.Symlink(secret, log); err != nil {
		t.Fatal(err)
	}
	for _, grep := range []string{"", "only"} {
		o := &logOpts{file: log, lines: 1, sudo: true, grep: grep}
		c, err := o.build()
		if err != nil {
			t.Fatal(err)
		}
		if got, _, code := runAsRoot(t, c, notRoot(log)); code != sudoExitLink || strings.Contains(got, "root-only") {
			t.Fatalf("grep %q: another user's link read: %q %d", grep, got, code)
		}
		if _, perr := o.result(&sshx.RunResult{ExitCode: sudoExitLink}); perr == nil || perr.Code != "IS_A_SYMLINK" {
			t.Fatalf("grep %q: error %+v", grep, perr)
		}
		if got, _, code := runAsRoot(t, c, nil); code != 0 || got != "root-only" {
			t.Fatalf("grep %q: root's link: %q %d", grep, got, code)
		}
	}
	// --follow keeps reading the file it opened, through the same check
	o := &logOpts{file: log, lines: 1, sudo: true, follow: true}
	if c, _ := o.build(); !strings.Contains(c, "exit 92") || !strings.Contains(c, "tail -n 1 -f <&3") || o.source() != "tail -n 1 -F -- '"+log+"'" {
		t.Fatalf("follow: %q, shown %q", c, o.source())
	}
}

// O5: fs chmod --sudo does not change, as root, the mode of what a link
// another server user planted names.
func TestSudoChmodFollowsNoOtherUsersLink(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	secret := filepath.Join(d, "shadow")
	_ = os.WriteFile(secret, []byte("x"), 0o600)
	link := filepath.Join(d, "app.log")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	mode := func() os.FileMode { fi, _ := os.Stat(secret); return fi.Mode().Perm() }
	_, stderr, code := runAsRoot(t, chmodScript("0644", []string{link}, false, true), notRoot(link))
	if code != sudoExitLink || mode() != 0o600 {
		t.Fatalf("another user's link followed: exit %d, mode %o", code, mode())
	}
	if e := fsExitMap(code, stderr); e == nil || e.Code != "IS_A_SYMLINK" || !strings.Contains(e.Message, link) {
		t.Fatalf("error: %+v", e)
	}
	// root's link, or the SSH user's: followed
	if got, _, code := runAsRoot(t, chmodScript("0640", []string{link}, false, true), nil); code != 0 || mode() != 0o640 || got != "mode 0640: "+link {
		t.Fatalf("root's link: %q exit %d, mode %o", got, code, mode())
	}
	if _, _, code := runAsRoot(t, chmodScript("0600", []string{link, secret}, false, true), map[string]string{link: "1000 1000 777 deploy deploy"}); code != 0 || mode() != 0o600 {
		t.Fatalf("the SSH user's link: exit %d, mode %o", code, mode())
	}
}

// O5: a write as root names `followed` only when a link was followed, not
// for a relative or non-canonical path the walk made absolute.
func TestSudoWriteFollowedOnlyForALink(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.MkdirAll(filepath.Join(d, "app"), 0o755)
	real := filepath.Join(d, "app", "notes.txt")
	_ = os.WriteFile(real, []byte("x"), 0o644)
	_ = os.Symlink(real, filepath.Join(d, "current"))
	if !strings.Contains(sudoInstallScript("x", "", "/tmp/t", writeOpts{}), `"${f:-0}" "$p"`) {
		t.Fatal("the install script does not say whether a link was followed")
	}
	for _, tc := range []struct{ p, followed string }{
		{"app/notes.txt", ""},
		{d + "//app/./notes.txt", ""},
		{d + "/app/../app/notes.txt", ""},
		{d + "/current", real},
	} {
		got, se, code := runAsRoot(t, "cd '"+d+"'; p='"+tc.p+"'; "+sudoWriteScript("/nonexistent", false)+`printf '644 1 bak %s %s\n' "${f:-0}" "$p"`, nil)
		if code != 0 {
			t.Fatalf("%s: exit %d %s", tc.p, code, se)
		}
		res := map[string]any{}
		mode := sudoInstallResult(got, "", writeOpts{backup: true}, res)
		f, _ := res["followed"].(string)
		if mode != "0644" || f != tc.followed || res["backup"] != real+".bak" {
			t.Errorf("%s: mode %q, %v", tc.p, mode, res)
		}
	}
}
