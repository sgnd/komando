package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// auditHome is a komando home with web1 (protected) and web2 (tag edge).
func auditHome(t *testing.T) string {
	t.Helper()
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	mustRun(t, "host", "add", "web2", "u@10.0.0.2", "-t", "edge")
	mustRun(t, "host", "edit", "web1", "--protected")
	return t.TempDir()
}

// rawRun runs komando and returns its last JSON line.
func rawRun(t *testing.T, args ...string) map[string]any {
	t.Helper()
	g.dryRun, g.yes = false, false
	root := newRoot()
	root.SetArgs(append([]string{"-o", "json"}, args...))
	var buf bytes.Buffer
	saved := out.P.W
	out.P.W = &buf
	defer func() { out.P.W = saved }()
	_ = root.Execute()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	var env map[string]any
	_ = json.Unmarshal(lines[len(lines)-1], &env)
	return env
}

func wouldRun(t *testing.T, d map[string]any) map[string]any {
	t.Helper()
	plans, _ := d["would_run"].([]any)
	if len(plans) == 0 {
		t.Fatalf("no plan: %v", d)
	}
	return plans[0].(map[string]any)
}

func TestCpSelectorsAndAdhocPort(t *testing.T) {
	dir := auditHome(t)
	f := filepath.Join(dir, "a.txt")
	_ = os.WriteFile(f, []byte("x\n"), 0o600)
	for _, c := range []struct{ dst, host string }{
		{"tag:edge:/tmp/x", "web2"},
		{"web2,!tag:none:/tmp/x", "web2"},
		{"root@192.0.2.50:2222:/tmp/x", "root@192.0.2.50:2222"},
		{"[2001:db8::1]:/tmp/x", "[2001:db8::1]"},
	} {
		d, e := invRun(t, "cp", f, c.dst, "--dry-run")
		if e != nil {
			t.Errorf("%s: %s %s", c.dst, e.Code, e.Message)
			continue
		}
		if hosts, _ := d["hosts"].([]any); len(hosts) != 1 || hosts[0] != c.host || !strings.HasSuffix(d["dst"].(string), ":/tmp/x") {
			t.Errorf("%s: got hosts %v dst %v", c.dst, d["hosts"], d["dst"])
		}
	}
}

func TestFlagsAfterDashRefused(t *testing.T) {
	auditHome(t)
	for _, args := range [][]string{
		{"exec", "web2", "--", "uptime", "-P", "2", "--dry-run", "-o", "json"},
		{"exec", "web2", "--", "apt-get", "upgrade", "--dry-run"},
		{"job", "start", "web2", "--", "sleep", "100", "--dry-run"},
		{"exec", "web2", "-c", "ls", "--", "uptime"},
		{"job", "start", "web2", "-c", "ls", "--", "uptime"},
	} {
		if _, e := invRun(t, args...); e == nil || e.Code != "USAGE" {
			t.Errorf("%v: want USAGE, got %+v", args, e)
		}
	}
	e := toErr(komandoFlagsAfterDash("exec web2", strings.Fields("uptime -P 2 --dry-run -o json")))
	if e == nil || !strings.Contains(e.Hint, "komando exec web2 -P 2 --dry-run -o json -- uptime") {
		t.Errorf("hint: %+v", e)
	}
	if e := toErr(komandoFlagsAfterDash("exec web2", strings.Fields("apt-get upgrade -y --dry-run"))); e == nil || !strings.Contains(e.Hint, "komando exec web2 --dry-run -- apt-get upgrade -y`") {
		t.Errorf("-y stays with the command: %+v", e)
	}
	for _, ok := range []string{"kubectl wait --timeout 60s", "rsync --dry-run -a src dst", "uptime", "yum update -y", "apt-get install nginx --yes"} {
		if err := komandoFlagsAfterDash("exec web2", strings.Fields(ok)); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	d := mustRun(t, "exec", "web2", "-c", "apt-get upgrade --dry-run", "--dry-run")
	if !strings.Contains(wouldRun(t, d)["remote_command"].(string), "apt-get upgrade --dry-run") {
		t.Errorf("-c keeps the words: %v", d)
	}
}

func TestEnvKeepsCommas(t *testing.T) {
	auditHome(t)
	d := mustRun(t, "exec", "web2", "-e", "HOSTS=a,b", "--dry-run", "--", "echo $HOSTS")
	if cmd := wouldRun(t, d)["remote_command"].(string); !strings.Contains(cmd, "HOSTS='a,b'") {
		t.Errorf("remote_command %q", cmd)
	}
	d = mustRun(t, "job", "start", "web2", "-e", "HOSTS=a,b", "--dry-run", "--", "echo $HOSTS")
	if d["command"] != "echo $HOSTS" {
		t.Errorf("job start: %v", d)
	}
}

func TestShebangInterpreter(t *testing.T) {
	for _, c := range []struct{ line, want, cmd string }{
		{"#!/usr/bin/env -S bash -e", "bash -e", "bash -e -s -- 'a b'"},
		{"#!/usr/bin/env -S python3 -u", "python3 -u", "python3 -u - 'a b'"},
		{"#!/usr/bin/env python3", "python3", "python3 - 'a b'"},
		{"#!/usr/bin/env -i LANG=C bash", "bash", "bash -s -- 'a b'"},
		{"#!/usr/bin/env -u HOME perl", "perl", "perl - 'a b'"},
		{"#!/bin/bash -e", "/bin/bash -e", "/bin/bash -e -s -- 'a b'"},
		{"#!/usr/bin/env", "sh", "sh -s -- 'a b'"},
		{"echo hi", "sh", "sh -s -- 'a b'"},
	} {
		got := shebangInterpreter(c.line + "\necho hi\n")
		if got != c.want {
			t.Errorf("%s: interpreter %q, want %q", c.line, got, c.want)
		}
		if cmd := scriptCommand(got, []string{"a b"}); cmd != c.cmd {
			t.Errorf("%s: command %q, want %q", c.line, cmd, c.cmd)
		}
	}
	if cmd := scriptCommand("/usr/bin/env -S bash -e", nil); cmd != "/usr/bin/env -S bash -e -s" {
		t.Errorf("--interpreter through env: %q", cmd)
	}
}

func TestScriptInputFlagsAndHiddenValues(t *testing.T) {
	dir := auditHome(t)
	s := filepath.Join(dir, "s.sh")
	_ = os.WriteFile(s, []byte("#!/usr/bin/env -S bash -e\necho hi\n"), 0o600)
	in := filepath.Join(dir, "in.txt")
	_ = os.WriteFile(in, []byte("data\n"), 0o600)
	masked := filepath.Join(dir, "masked.conf")
	_ = os.WriteFile(masked, []byte("requirepass [hidden]\n"), 0o600)

	d := mustRun(t, "script", "web2", s, "--dry-run", "--arg", "a b")
	if cmd := wouldRun(t, d)["remote_command"]; cmd != "bash -e -s -- 'a b'" {
		t.Errorf("remote_command %v", cmd)
	}
	for _, flag := range []string{"--stdin-file=" + in, "--pty"} {
		if _, e := invRun(t, "script", "web2", s, flag, "--dry-run"); e == nil {
			t.Errorf("script %s was taken", flag)
		}
	}
	for _, args := range [][]string{
		{"script", "web2", masked, "--dry-run"},
		{"exec", "web2", "--stdin-file", masked, "--dry-run", "--", "cat > /etc/redis.conf"},
	} {
		if _, e := invRun(t, args...); e == nil || e.Code != "HIDDEN_VALUE" {
			t.Errorf("%v: want HIDDEN_VALUE, got %+v", args, e)
		}
	}
	mustRun(t, "conn", "add", "bk", "s3://AKIAEXAMPLE@shop-dev/backups?region=eu-west-1")
	for _, args := range [][]string{
		{"upload", "bk", masked, "--dry-run"},
		{"storage", "upload", "bk", masked, "--dry-run"},
	} {
		if _, e := invRun(t, args...); e == nil || e.Code != "HIDDEN_VALUE" {
			t.Errorf("%v: want HIDDEN_VALUE, got %+v", args, e)
		}
	}
}

func TestStorageFolderDest(t *testing.T) {
	for _, c := range []struct{ dir, dest, want string }{
		{"./site", "", "site"},
		{"./site/", "", "site"},
		{"./site", "www/", "www/site"},
		{"./site/", "www/", "www/"},
		{"./site", "www", "www"},
		{".", "", ""},
	} {
		if got := storageFolderDest(c.dir, c.dest); got != c.want {
			t.Errorf("%s %q: got %q, want %q", c.dir, c.dest, got, c.want)
		}
	}
}

func TestSyncDeleteDryRunSaysBlocked(t *testing.T) {
	invHome(t)
	out.P.Reset()
	g.dryRun = true
	if err := guardDelete(syncOpts{delete: true}, "web1:/srv"); err != nil {
		t.Fatalf("a dry run goes on: %v", err)
	}
	if b := out.P.Blocked(); b == nil || b.Code != "POLICY_BLOCKED" {
		t.Errorf("would_be_blocked: %+v", b)
	}
	out.P.Reset()
}

func TestTunnelChecks(t *testing.T) {
	auditHome(t)
	d := mustRun(t, "tunnel", "start", "web1", "-R", "8080:localhost:80", "--dry-run")
	if m, _ := d["_meta"].(map[string]any); m["would_be_blocked"] == nil {
		t.Errorf("-R on a protected server: %v", d)
	}
	d = mustRun(t, "tunnel", "start", "web2", "-R", "8080:localhost:80", "--dry-run")
	if m, _ := d["_meta"].(map[string]any); m["would_be_blocked"] != nil {
		t.Errorf("-R on a plain server: %v", d)
	}
	for _, args := range [][]string{
		{"tunnel", "start", "web2", "-L", "99999:localhost:80", "--dry-run"},
		{"tunnel", "start", "web2", "-L", "8080:localhost:0", "--dry-run"},
		{"tunnel", "start", "web2", "-D", "x", "--dry-run"},
		{"tunnel", "start", "web2", "-D", "1080", "--port", "5", "--dry-run"},
	} {
		if _, e := invRun(t, args...); e == nil || e.Code != "USAGE" {
			t.Errorf("%v: want USAGE, got %+v", args, e)
		}
	}
	line, _ := json.Marshal(serveErr{Code: "HOSTKEY_MISMATCH", Message: "the key changed", Hint: "report it", Exit: out.ExitConnect})
	if e := toErr(tunnelErr(string(line), "local", "web2", "127.0.0.1:0")); e.Code != "HOSTKEY_MISMATCH" || e.Exit != out.ExitConnect || e.Hint != "report it" {
		t.Errorf("tunnel serve's error lost: %+v", e)
	}
	if e := toErr(tunnelErr("listen tcp: address already in use", "local", "web2", "127.0.0.1:80")); e.Code != "PORT_IN_USE" {
		t.Errorf("plain line: %+v", e)
	}
	line, _ = json.Marshal(serveErr{Code: "REMOTE_ERROR", Message: "ssh: rejected: administratively prohibited", Exit: 1})
	if e := toErr(tunnelErr(string(line), "local", "web2", "127.0.0.1:0")); e.Code != "TUNNEL_FAILED" {
		t.Errorf("forward refused: %+v", e)
	}
}

func TestFsChecks(t *testing.T) {
	dir := auditHome(t)
	if _, e := invRun(t, "fs", "write", "web2", "/tmp/x", "--content", "a", "--from", filepath.Join(dir, "x"), "--dry-run"); e == nil || e.Code != "USAGE" {
		t.Errorf("--content and --from: %+v", e)
	}
	for flag, want := range map[string]string{"": "mv -n -- '/a' '/b'", "--overwrite": "mv -f -- '/a' '/b'"} {
		args := []string{"fs", "mv", "web2", "/a", "/b", "--dry-run"}
		if flag != "" {
			args = append(args, flag)
		}
		if cmd := wouldRun(t, mustRun(t, args...))["remote_command"]; cmd != want {
			t.Errorf("fs mv %s: %v", flag, cmd)
		}
	}
}

func TestFsCatTailReadsTheEnd(t *testing.T) {
	sc := localSFTP(t)
	p := filepath.Join(t.TempDir(), "big.log")
	var b strings.Builder
	for i := 1; i <= 1000; i++ {
		b.WriteString("line " + strings.Repeat("x", i%7) + "\n")
	}
	b.WriteString("the last line\n")
	_ = os.WriteFile(p, []byte(b.String()), 0o600)
	got, trunc, err := readRemoteEnd(context.Background(), nil, sc, p, false, 200)
	if err != nil || !trunc {
		t.Fatalf("trunc %v err %v", trunc, err)
	}
	if !strings.HasSuffix(string(got), "the last line\n") || !strings.HasPrefix(string(got), "line ") || len(got) > 200 {
		t.Errorf("not the end, or a cut first line: %q", got)
	}
	r, _ := catContent("web1", p, got, trunc, 0, 1, false)
	if r.Content != "the last line\n" {
		t.Errorf("--tail 1: %q", r.Content)
	}
	small, trunc, _ := readRemoteEnd(context.Background(), nil, sc, p, false, 1<<20)
	if trunc || string(small) != b.String() {
		t.Errorf("a small file is read whole")
	}
}

func TestRecipeRunNameAndOrder(t *testing.T) {
	auditHome(t)
	env := rawRun(t, "recipe", "run", "disk", "web2", "--dry-run")
	if env["command"] != "recipe.run" {
		t.Errorf("command %v", env["command"])
	}
	if d, _ := env["data"].(map[string]any); d["recipe"] != "disk" {
		t.Errorf("data.recipe: %v", env["data"])
	}
	e := wantCode(t, "RECIPE_NOT_FOUND", "recipe", "run", "web2", "disk")
	if !strings.Contains(e.Hint, "komando recipe run disk web2") {
		t.Errorf("hint %q", e.Hint)
	}
}

func TestJobChecks(t *testing.T) {
	auditHome(t)
	if _, e := invRun(t, "job", "list", "--target", "nosuch"); e == nil {
		t.Error("job list --target nosuch was ok")
	}
	mustRun(t, "job", "list", "--target", "web2")
	w := jobWaitCmd()
	if f := w.Flags().Lookup("timeout"); f == nil || f.DefValue != (10*time.Minute).String() {
		t.Errorf("job wait --timeout: %+v", f)
	}
	if s := (jobStarted{}); strings.Contains(jsonStr(s), "next") {
		t.Errorf("next without a job: %s", jsonStr(s))
	}
}

func TestDryRunMissingSecretFails(t *testing.T) {
	auditHome(t)
	if d, e := invRun(t, "exec", "web2", "-e", "TOKEN=secret:nope", "--dry-run", "--", "echo ok"); e == nil || e.Code != "SECRET_NOT_FOUND" || e.Exit != out.ExitNotFound {
		t.Errorf("a missing secret: want SECRET_NOT_FOUND, got %+v %v", e, d)
	}
}

func TestDownloadChecks(t *testing.T) {
	dir := auditHome(t)
	if _, e := invRun(t, "download", "web2", "/etc/hosts", "--to", "-"); e == nil || e.Code != "USAGE" {
		t.Errorf("--to - for a server: %+v", e)
	}
	exists := filepath.Join(dir, "exists.txt")
	_ = os.WriteFile(exists, []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "hosts"), []byte("x"), 0o600)
	for _, to := range []string{exists, dir} {
		if _, e := invRun(t, "download", "web2", "/etc/hosts", "--to", to, "--dry-run"); e == nil || e.Code != "FILE_EXISTS" {
			t.Errorf("--to %s: want FILE_EXISTS, got %+v", to, e)
		}
	}
	mustRun(t, "download", "web2", "/etc/hosts", "--to", exists, "--overwrite", "--dry-run")
}
