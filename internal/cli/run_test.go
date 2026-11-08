package cli

import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/storex"
)

func TestReadOnlyViolation(t *testing.T) {
	cases := map[string]string{
		"uptime":                                  "",
		"df -h / | tail -1":                       "",
		"ls -la 2>/dev/null":                      "",
		"cat /etc/hosts >&2":                      "",
		"journalctl -u nginx --since -1h":         "",
		"systemctl status nginx":                  "",
		"grep rm /var/log/syslog":                 "",
		"echo 'a > b'":                            "",
		"docker ps -a":                            "",
		"kubectl get pods":                        "",
		"apt list --upgradable":                   "",
		"sed -n 1,5p /etc/hosts":                  "",
		"psql -c 'select 1'":                      "",
		"ls 2>&1 | head":                          "",
		"ls >&2 2>&-":                             "",
		"echo x > /dev/stderr":                    "",
		"bash -c 'uptime; df -h'":                 "",
		"if [ -f /x ]; then cat /x; fi":           "",
		"for f in /etc/*.conf; do wc -l $f; done": "",
		"command -v rm":                           "",
		"python3 --version":                       "",
		"awk -F: '{print $1}' /etc/passwd":        "",
		"awk '$3 > 100' f":                        "",
		"sudo -u postgres psql -Atc 'select 1'":   "",
		"xargs -I{} cat {} < list":                "",
		"timeout 5s ls":                           "",
		"cat $(ls /etc/*.conf)":                   "",
		"grep -r 'rm -rf' /etc":                   "",
		"rm -rf /tmp/x":                           "rm",
		"echo hi > /tmp/f":                        "> /tmp/f",
		"echo hi >> /tmp/f":                       "> /tmp/f",
		"ls; mv a b":                              "mv",
		"cat x | tee /tmp/y":                      "tee",
		"sudo -u root rm /x":                      "rm",
		"FOO=1 truncate -s 0 /x":                  "truncate",
		"systemctl restart nginx":                 "systemctl restart",
		"service nginx stop":                      "service stop",
		"apt-get install -y curl":                 "apt-get install",
		"apk add curl":                            "apk add",
		"sed -i s/a/b/ /etc/x":                    "sed -i",
		"docker run --rm alpine true":             "docker run",
		"useradd bob":                             "useradd",
		"chmod 600 /x":                            "chmod",
		"kill -9 123":                             "kill",
		"find /tmp -name '*.log' -delete":         "find -delete",
		"sh -c 'rm -f /tmp/x'":                    "rm",
		"echo $(rm -f /x)":                        "rm",
		"timeout 10 rm /x":                        "rm",
		"cat /etc/hosts && /bin/rm /x":            "rm",
		"ls 2>err.log":                            "> err.log",
		"nice -n 5 cp a b":                        "cp",
		"xargs rm < list":                         "rm",
		"git -C /srv/app pull":                    "git pull",
		"crontab -r":                              "crontab -r",
		"ip addr add 10.0.0.1/24 dev eth0":        "ip add",
		"echo x >| /etc/cron.d/a":                 "> /etc/cron.d/a",
		"echo x >&/etc/cron.d/a":                  "> /etc/cron.d/a",
		"echo x >& /etc/cron.d/a":                 "> /etc/cron.d/a",
		"echo x 1>|/tmp/f":                        "> /tmp/f",
		"echo hi>/tmp/f":                          "> /tmp/f",
		"cat <>/tmp/f":                            "> /tmp/f",
		"{ rm F; }":                               "rm",
		"if :; then rm F; fi":                     "rm",
		"! rm F":                                  "rm",
		"for f in a; do rm $f; done":              "rm",
		"while read f; do rm $f; done < l":        "rm",
		"case x in a) rm F;; esac":                "rm",
		"eval rm F":                               "eval",
		". ./x.sh":                                ".",
		"source x.sh":                             "source",
		"exec rm F":                               "exec",
		"bash -ec 'rm F'":                         "rm",
		"bash -lc 'systemctl restart nginx'":      "systemctl restart",
		"sh -o pipefail -c 'touch x'":             "touch",
		"echo 'rm F' | sh":                        "sh running a script from a file or its input",
		"bash -s < x.sh":                          "bash running a script from a file or its input",
		"bash x.sh":                               "bash running a script from a file or its input",
		"su -c 'rm F' root":                       "rm",
		"sudo su":                                 "su running a script from a file or its input",
		"$X F":                                    "command name $X is only known when it runs",
		"${X} F":                                  "command name ${X} is only known when it runs",
		"`echo rm` F":                             "command name $(...) is only known when it runs",
		"$(echo rm) F":                            "command name $(...) is only known when it runs",
		"/bin/r? F":                               "command name /bin/r? is only known when it runs",
		"r\\m F":                                  "rm",
		"'r'm F":                                  "rm",
		"python3 -c 'import os'":                  "python3 running code",
		"echo x | python3":                        "python3 running code from its input",
		"perl -ne print x":                        "perl running code",
		"awk 'BEGIN{system(\"rm F\")}'":           "awk running commands or writing files",
		"awk '{print > \"/etc/x\"}' f":            "awk running commands or writing files",
		"awk -f prog.awk f":                       "awk -f",
		"timeout -s KILL 10 rm F":                 "rm",
		"sudo -uroot rm F":                        "rm",
		"sudo -nu root rm F":                      "rm",
		"sudo -s":                                 "a shell reading commands from its input",
		"sudo -e /etc/hosts":                      "sudo -e",
		"env -S 'rm F'":                           "env -S",
		"stdbuf -o L rm F":                        "rm",
		"busybox rm F":                            "rm",
		"find . -fprint /etc/x":                   "find -fprint",
		"time -o /tmp/t ls":                       "time -o",
		"systemd-run touch /x":                    "systemd-run",
	}
	for cmd, want := range cases {
		if got := readOnlyViolation(cmd); got != want {
			t.Errorf("%q: got %q, want %q", cmd, got, want)
		}
	}
	g.dryRun = false
	err := checkReadOnly("rm -rf /tmp/x")
	if e := toErr(err); e == nil || e.Code != "READ_ONLY_VIOLATION" || e.Exit != out.ExitPolicy {
		t.Errorf("checkReadOnly: %v", err)
	}
}

// The allowlist (readOnlyAllowlist) is stricter than the denylist: a
// command komando cannot confirm only reads is reported, so a protected
// target holds it to --yes. Commands komando knows read are not.
func TestReadOnlyAllowlist(t *testing.T) {
	allowed := []string{
		"cat /etc/hostname", "ls -la /var", "tail -n 50 /var/log/syslog", "head -5 f",
		"grep -r nginx /etc", "ps aux | grep nginx", "df -h", "du -sh /var", "free -m",
		"uptime", "stat /etc/hosts", "ss -tlnp", "netstat -an",
		"journalctl -u nginx --no-pager", "systemctl status nginx", "systemctl is-active nginx",
		"docker ps", "docker logs api", "docker inspect api",
		"kubectl get pods", "kubectl describe pod x", "kubectl logs api",
		"find /var/log -name '*.log'", "sudo cat /etc/shadow", "wc -l f",
		"for f in /proc/*/status; do cat $f; done",
		"set -eu\ndf -h /\ncat /etc/os-release",
		"sh -c 'ls /data | wc -l'",
	}
	for _, c := range allowed {
		if w := readOnlyAllowlist(c); w != "" {
			t.Errorf("%q: allowlist refused it (%s)", c, w)
		}
	}
	refused := []string{
		"mytool --status", "./deploy.sh", "cat /etc/hosts | mytool", "sh -c 'mytool'",
		"python3 -c 'print(1)'", "ssh host uptime", "eval ls", "node app.js",
		"custombin", "xargs mytool", "sudo mytool",
	}
	for _, c := range refused {
		if readOnlyAllowlist(c) == "" {
			t.Errorf("%q: allowlist let it skip --yes on a protected target", c)
		}
		// but none of these is a clear write, so the denylist stays quiet
		// for the ones that truly change nothing komando can see
	}
}

func TestScriptCommand(t *testing.T) {
	cases := []struct {
		interp string
		args   []string
		want   string
	}{
		{"sh", nil, "sh -s"},
		{"bash", []string{"v1"}, "bash -s -- 'v1'"},
		{"/bin/bash", []string{"a b"}, "/bin/bash -s -- 'a b'"},
		{"python3", []string{"x"}, "python3 - 'x'"},
		{"perl", []string{"x"}, "perl - 'x'"},
		{"ruby", nil, "ruby -"},
		{"node", []string{"x"}, "node - 'x'"},
		{"/usr/bin/env python3", []string{"x"}, "/usr/bin/env python3 - 'x'"},
	}
	for _, c := range cases {
		if got := scriptCommand(c.interp, c.args); got != c.want {
			t.Errorf("%s %v: got %q, want %q", c.interp, c.args, got, c.want)
		}
	}
}

func TestScriptCommandRunsLocally(t *testing.T) {
	for _, interp := range []string{"perl", "python3", "sh"} {
		if _, err := exec.LookPath(interp); err != nil {
			continue
		}
		body := map[string]string{"perl": `print "arg=$ARGV[0]\n";`, "python3": "import sys; print('arg=' + sys.argv[1])", "sh": `echo "arg=$1"`}[interp]
		cmd := exec.Command("sh", "-c", scriptCommand(interp, []string{"hello world"}))
		cmd.Stdin = strings.NewReader(body)
		o, err := cmd.Output()
		if err != nil || strings.TrimSpace(string(o)) != "arg=hello world" {
			t.Errorf("%s: %q %v", interp, o, err)
		}
	}
}

func TestExecDataText(t *testing.T) {
	d := execData{Results: []execHostResult{
		{Host: "web1", OK: true, RunResult: &sshx.RunResult{Stdout: "out1\n", Stderr: "warn1\n"}},
		{Host: "web2", RunResult: &sshx.RunResult{ExitCode: 3, Stdout: "out2"}},
		{Host: "web3", Error: &out.Error{Code: "CONNECTION_REFUSED", Message: "web3: refused", Hint: "check that sshd runs on the server and listens on this port: komando host show web3"}},
	}}
	got := d.Text()
	for _, want := range []string{"=== web1 [ok exit=0]\nout1\n[stderr] warn1\n", "=== web2 [FAILED exit=3]\nout2\n", "=== web3 [FAILED connection refused]\nerror [CONNECTION_REFUSED]: web3: refused\nhint: check that sshd runs"} {
		if !strings.Contains(got, want) {
			t.Errorf("text misses %q:\n%s", want, got)
		}
	}
	d.streamed = true
	if strings.Contains(d.Text(), "out1") {
		t.Error("streamed output must not be printed again")
	}
}

func TestFailReason(t *testing.T) {
	if r := failReason(3, nil); r != "exit 3" {
		t.Error(r)
	}
	if r := failReason(0, &out.Error{Code: "TIMEOUT"}); r != "timed out" {
		t.Error(r)
	}
}

// runSh runs a generated fs script in dir with the local sh.
func runSh(t *testing.T, dir, script string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = dir
	o, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return string(o), code
}

func TestFsScripts(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a": "A", "b": "B", "d/x": "X"})
	if _, code := runSh(t, dir, mvScript("a", "b", false)); code != fsExitDestExists {
		t.Errorf("mv over a file: exit %d", code)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "b")); string(b) != "B" {
		t.Error("mv replaced b without --overwrite")
	}
	if _, code := runSh(t, dir, mvScript("nope", "c", false)); code != fsExitNoSource {
		t.Errorf("mv missing: exit %d", code)
	}
	if o, code := runSh(t, dir, mvScript("a", "b", true)); code != 0 || !strings.Contains(o, "replaced") {
		t.Errorf("mv --overwrite: %d %s", code, o)
	}
	if _, code := runSh(t, dir, mvScript("b", "d", false)); code != 0 {
		t.Errorf("mv into a folder: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "d/b")); err != nil {
		t.Error("mv into a folder did not land in it")
	}
	if _, code := runSh(t, dir, mkdirScript([]string{"d/b"})); code != fsExitNotFolder {
		t.Errorf("mkdir on a file: exit %d", code)
	}
	if _, code := runSh(t, dir, rmScript([]string{"d"}, false)); code != fsExitIsFolder {
		t.Errorf("rm folder without -r: exit %d", code)
	}
	o, code := runSh(t, dir, rmScript([]string{"missing", "*.bin"}, false))
	if code != 0 || !strings.Contains(o, "not found: missing") || !strings.Contains(o, "globs are not expanded") {
		t.Errorf("rm missing: %d %s", code, o)
	}
	if _, code := runSh(t, dir, rmScript([]string{"d"}, true)); code != 0 {
		t.Errorf("rm -r: exit %d", code)
	}
	if _, code := runSh(t, dir, chmodScript("0600", []string{"zzz"}, false)); code != fsExitNoSource {
		t.Errorf("chmod missing: exit %d", code)
	}
	if e := fsExitMap(fsExitIsFolder, "d is a folder"); e == nil || e.Exit != out.ExitUsage || !strings.Contains(e.Hint, "--recursive") {
		t.Errorf("exit map: %+v", e)
	}
}

func TestValidMode(t *testing.T) {
	for m, ok := range map[string]bool{"644": true, "0755": true, "u+x": true, "go-w": true, "a=r,u+w": true, "/etc/x": false, "999": false, "": false, "+": true} {
		if validMode(m) != ok {
			t.Errorf("validMode(%q) = %v", m, !ok)
		}
	}
}

func TestRemotePathQuoting(t *testing.T) {
	if rq("~/x y") != `"$HOME"/'x y'` || rq("~") != `"$HOME"` || rq("/a") != "'/a'" {
		t.Errorf("rq: %s %s %s", rq("~/x y"), rq("~"), rq("/a"))
	}
}

func TestTreeDest(t *testing.T) {
	cases := []struct {
		dst, base            string
		contents, dir, slash bool
		want                 string
	}{
		{"/x/site", "site", false, false, false, "/x/site"}, // new: the copy
		{"/x/site", "site", false, true, false, "/x/site"},  // again: no site/site
		{"/x/www", "site", false, true, false, "/x/www/site"},
		{"/x/www", "site", true, true, false, "/x/www"}, // site/: contents
		{"/x", "site", false, true, true, "/x/site"},
		{"/x/new", "site", false, false, false, "/x/new"},
	}
	for _, c := range cases {
		if got := treeDest(c.dst, c.base, c.contents, c.dir, c.slash); got != c.want {
			t.Errorf("%+v: got %s", c, got)
		}
	}
}

func TestLsText(t *testing.T) {
	r := lsResult{Path: "/x", Entries: []fileInfo{
		{Name: "b", Path: "/x/b", Type: "file", Size: 2048, Mode: "0644"},
		{Name: "a", Path: "/x/a", Type: "dir", Mode: "0755"},
		{Name: "l", Path: "/x/l", Type: "symlink", Mode: "0777", Link: "b"},
	}}
	got := r.Text()
	if !strings.HasPrefix(got, "MODE") || !strings.Contains(got, "drwxr-xr-x") || !strings.Contains(got, "l -> b") || strings.Index(got, "a/") > strings.Index(got, " b\n") {
		t.Errorf("ls text:\n%s", got)
	}
}

func TestCheckVars(t *testing.T) {
	r := recipeRow{Name: "big-dirs", Command: "du {{path}} {{depth=2}}", Params: map[string]string{"path": "/"}}
	if err := checkVars(r, map[string]string{"path": "/srv"}); err != nil {
		t.Error(err)
	}
	if err := checkVars(r, map[string]string{"pth": "/srv"}); toErr(err).Code != "UNKNOWN_VAR" {
		t.Errorf("unknown var: %v", err)
	}
}

func TestSyncMissingSourceAndEmptyDelete(t *testing.T) {
	g.dryRun = false
	dst := t.TempDir()
	writeTree(t, dst, map[string]string{"keep.txt": "mine"})
	ctx := context.Background()
	_, err := runSync(ctx, localSide{filepath.Join(dst, "nope")}, localSide{dst}, "src", "dst", syncOpts{delete: true})
	if toErr(err).Code != "PATH_NOT_FOUND" {
		t.Fatalf("missing source: %v", err)
	}
	empty := t.TempDir()
	_, err = runSync(ctx, localSide{empty}, localSide{dst}, "src", "dst", syncOpts{delete: true})
	if toErr(err).Code != "SOURCE_EMPTY" {
		t.Fatalf("empty source with --delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "keep.txt")); err != nil {
		t.Fatal("the destination lost a file")
	}
	// a file as the source
	_, err = runSync(ctx, localSide{filepath.Join(dst, "keep.txt")}, localSide{empty}, "src", "dst", syncOpts{})
	if toErr(err).Code != "NOT_A_FOLDER" {
		t.Errorf("file source: %v", err)
	}
}

func TestSyncLinksModesAndNewFolder(t *testing.T) {
	g.dryRun = false
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "new")
	writeTree(t, src, map[string]string{"a.sh": "echo"})
	if err := os.Symlink("a.sh", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := runSync(ctx, localSide{src}, localSide{dst}, "src", "dst", syncOpts{})
	if err != nil || r.Copied != 1 || !r.NewFolder || len(r.Skipped) != 1 || r.Skipped[0] != "link" {
		t.Fatalf("first sync: %+v %v", r, err)
	}
	os.Chmod(filepath.Join(src, "a.sh"), 0o755)
	r, _ = runSync(ctx, localSide{src}, localSide{dst}, "src", "dst", syncOpts{})
	if r.Updated != 1 {
		t.Errorf("a mode change must be synced: %+v", r)
	}
	if fi, _ := os.Stat(filepath.Join(dst, "a.sh")); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode not applied: %v", fi.Mode())
	}
	g.dryRun = true
	defer func() { g.dryRun = false }()
	r, _ = runSync(ctx, localSide{src}, localSide{dst}, "src", "dst", syncOpts{})
	if !strings.Contains(r.Text(), "would copy 0, update 0, delete 0") {
		t.Errorf("dry-run grammar: %s", r.Text())
	}
}

// fakeBucket is a storage conn in memory.
type fakeBucket struct{ objs []storex.Object }

func (f *fakeBucket) List(context.Context, string, bool, int) ([]storex.Object, bool, error) {
	return f.objs, false, nil
}
func (f *fakeBucket) Get(_ context.Context, key string, w io.Writer) (int64, error) {
	n, err := io.WriteString(w, "data:"+key)
	return int64(n), err
}
func (f *fakeBucket) Exists(context.Context, string) (bool, error) { return true, nil }
func (f *fakeBucket) Stat(_ context.Context, key string) (storex.Object, error) {
	for _, o := range f.objs {
		if o.Key == key {
			return o, nil
		}
	}
	return storex.Object{}, errors.New("not found")
}
func (f *fakeBucket) Put(context.Context, string, io.Reader, int64, string) error {
	return nil
}
func (f *fakeBucket) Remove(context.Context, string) error { return nil }
func (f *fakeBucket) Link(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, nil
}
func (f *fakeBucket) Close() error { return nil }

func TestSyncSkipsFolderMarkers(t *testing.T) {
	g.dryRun = false
	b := &fakeBucket{objs: []storex.Object{{Key: "tree"}, {Key: "tree/"}, {Key: "tree/sub/"}, {Key: "tree/a.txt", Size: 11}}}
	dst := t.TempDir()
	r, err := runSync(context.Background(), bucketSide{b: b, prefix: "tree/"}, localSide{dst}, "b:tree", dst, syncOpts{})
	if err != nil || r.Copied != 1 {
		t.Fatalf("markers: %+v %v", r, err)
	}
	if body, _ := os.ReadFile(filepath.Join(dst, "a.txt")); string(body) != "data:tree/a.txt" {
		t.Errorf("a.txt = %q", body)
	}
}

func TestJobWaitRetriesOnlyBrokenConnections(t *testing.T) {
	for err, want := range map[error]bool{
		nil:                    false,
		errors.New("ssh: EOF"): true,
		errors.New("read tcp 1.2.3.4:22: connection reset by peer"): true,
		out.Errf(out.ExitConnect, "CONNECT_TIMEOUT", "", "x"):       true,
		out.Errf(out.ExitConnect, "AUTH_FAILED", "", "x"):           false,
		out.Errf(out.ExitConnect, "NO_AUTH", "", "x"):               false,
		out.Errf(out.ExitConnect, "HOSTKEY_MISMATCH", "", "x"):      false,
		out.Errf(out.ExitNotFound, "JOB_NOT_FOUND", "", "x"):        false,
		// seen when sessions are cut at random moments
		errors.New("ssh: unexpected packet in response to channel open: <nil>"): true,
		out.Errf(out.ExitConnect, "CONNECTION_LOST", "", "x"):                   true,
	} {
		if transient(err) != want {
			t.Errorf("transient(%v) = %v", err, !want)
		}
	}
}
