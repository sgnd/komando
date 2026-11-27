package cli

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func TestSvcStatusFindsMissingUnitsAndNoSystemd(t *testing.T) {
	_, err := svcResult(&sshx.RunResult{Stdout: "#komando:no-systemd\n"})
	if err == nil || err.Code != "NO_SYSTEMD" || err.Exit != 3 {
		t.Fatalf("no systemd: %+v", err)
	}
	show := "Id=nginx.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\n\nId=nope.service\nLoadState=not-found\nActiveState=inactive\n"
	units, err := svcResult(&sshx.RunResult{Stdout: show})
	if err == nil || err.Code != "UNIT_NOT_FOUND" || err.Exit != 3 || !strings.Contains(err.Message, "nope.service") {
		t.Fatalf("missing unit: %+v", err)
	}
	if len(units) != 2 || units[0]["healthy"] != true || units[0]["main_pid"] != int64(42) {
		t.Fatalf("units: %v", units)
	}
}

func TestLogOptsCheck(t *testing.T) {
	bad := []logOpts{
		{unit: "a", file: "/b"},
		{file: "/b", container: "c"},
		{lines: -1},
		{file: "/b", since: "-1h"},
		{priority: "loud"},
		{priority: "err..loud"},
		{file: "/b", priority: "err"},
		{follow: true, until: "now"},
		{timestamps: true},                // the journal has its own times
		{unit: "nginx", timestamps: true}, // --timestamps is for containers
		{file: "/b", timestamps: true},
	}
	for _, o := range bad {
		if err := o.check(); err == nil || !strings.Contains(err.Error(), "USAGE") {
			t.Errorf("%+v must be a usage error, got %v", o, err)
		}
	}
	good := []logOpts{{unit: "nginx", priority: "err"}, {priority: "3"}, {priority: "err..warning"}, {container: "api", since: "10m", follow: true}, {lines: 0}}
	for _, o := range good {
		if err := o.check(); err != nil {
			t.Errorf("%+v: %v", o, err)
		}
	}
}

// docker logs only turns its second word into --container: the flags are
// the ones of logs, --sudo included.
func TestLogsAliases(t *testing.T) {
	invHome(t)
	run := func(args ...string) map[string]any {
		t.Helper()
		d := mustRun(t, append(args, "--dry-run")...)
		w, _ := d["would_run"].([]any)
		if len(w) != 1 {
			t.Fatalf("%v: %v", args, d)
		}
		return w[0].(map[string]any)
	}
	for _, c := range []struct {
		args []string
		cmd  string
		sudo bool
	}{
		{[]string{"docker", "logs", "u@10.9.9.9", "api", "--sudo", "-n", "5"}, "docker logs --tail 5 'api' 2>&1", true},
		{[]string{"logs", "u@10.9.9.9", "--container", "api", "--sudo", "-n", "5"}, "docker logs --tail 5 'api' 2>&1", true},
		{[]string{"docker", "logs", "u@10.9.9.9", "api", "--timestamps", "-n", "5"}, "docker logs --timestamps --tail 5 'api' 2>&1", false},
		{[]string{"logs", "u@10.9.9.9", "--unit", "nginx", "-p", "err"}, "journalctl --no-pager -o short-iso -u 'nginx' -p 'err' -n 200", false},
	} {
		w := run(c.args...)
		if !strings.HasSuffix(w["remote_command"].(string), c.cmd) || w["sudo"] != c.sudo {
			t.Errorf("%v: %v", c.args, w)
		}
	}
	wantCode(t, "USAGE", "docker", "logs", "u@10.9.9.9", "api", "-p", "err")
}

func TestLogsPreflightAndResult(t *testing.T) {
	o := &logOpts{file: "/var/log/x.log", lines: 5}
	c, err := o.build()
	if err != nil || !strings.HasPrefix(c, "[ -e '/var/log/x.log' ]") || !strings.Contains(c, "tail -n 5") {
		t.Fatalf("file command: %q %v", c, err)
	}
	for m, want := range map[string]string{"no-file": "FILE_NOT_FOUND", "no-read": "PERMISSION_DENIED", "no-systemd": "NO_SYSTEMD"} {
		if _, e := o.result(&sshx.RunResult{Stdout: "#komando:" + m + "\n"}); e == nil || e.Code != want {
			t.Errorf("%s: %v", m, e)
		}
	}
	j := &logOpts{unit: "ssh", lines: 10}
	if _, e := j.result(&sshx.RunResult{Stderr: "No journal files were found.\n"}); e == nil || e.Code != "NO_JOURNAL" || e.Exit != 3 {
		t.Fatalf("empty journal: %v", e)
	}
	d, e := j.result(&sshx.RunResult{Stdout: "line\n", Stderr: "Hint: You are currently not seeing messages from other users and the system."})
	if w, ok := d.(opsWarnings); e != nil || !ok || len(w.warnings) != 1 {
		t.Fatalf("journal without sudo must warn: %v %v", d, e)
	}
	f := &logOpts{unit: "ssh", lines: 10, follow: true, since: "-5m"}
	if c, _ := f.build(); !strings.Contains(c, "-f --since '-5m'") && !strings.Contains(c, "--since '-5m'") {
		t.Fatalf("--since with -f: %q", c)
	}
	if c, _ := f.build(); strings.Contains(c, "#komando:") {
		t.Fatalf("a followed stream is checked before, not inside: %q", c)
	}
}

func TestParseUpgrades(t *testing.T) {
	cases := []struct{ pm, in, name, from, to string }{
		{"apt", "tzdata/stable 2026f-0 all [upgradable from: 2026e-0]", "tzdata", "2026e-0", "2026f-0"},
		{"apt", "Inst tzdata [2026e-0] (2026f-0 Debian:13/stable [all])", "tzdata", "2026e-0", "2026f-0"},
		{"apk", "busybox-1.37.0-r20 x86_64 {busybox} (GPL-2.0-only) [upgradable from: busybox-1.37.0-r19]", "busybox", "1.37.0-r19", "1.37.0-r20"},
		{"apk", "(1/2) Upgrading musl (1.2.5-r10 -> 1.2.5-r13)", "musl", "1.2.5-r10", "1.2.5-r13"},
		{"dnf", "openssl.x86_64    1:3.0.7-28.el9    baseos", "openssl", "", "1:3.0.7-28.el9"},
		{"zypper", "v | Main | curl | 8.0-1 | 8.1-1 | x86_64", "curl", "8.0-1", "8.1-1"},
		{"pacman", "curl 8.0-1 -> 8.1-1", "curl", "8.0-1", "8.1-1"},
	}
	for _, c := range cases {
		r := parseUpgrades(c.pm, c.in)
		if len(r) != 1 || r[0].Name != c.name || r[0].From != c.from || r[0].Version != c.to {
			t.Errorf("%s %q: %+v", c.pm, c.in, r)
		}
	}
}

func TestPkgUpgradableIndexAge(t *testing.T) {
	d, e := pkgUpgradableResult(&sshx.RunResult{Stderr: "# package-manager: apt\n# index-age: 259200\n"}, false)
	w, ok := d.(opsWarnings)
	if e != nil || !ok || !strings.Contains(w.warnings[0], "--refresh") || w.data.(pkgUpgradable).IndexAge != "3d" {
		t.Fatalf("stale index: %+v %v", d, e)
	}
	if d, _ := pkgUpgradableResult(&sshx.RunResult{Stderr: "# index-age: 259200\n"}, true); func() bool { _, ok := d.(opsWarnings); return ok }() {
		t.Fatal("no warning right after --refresh")
	}
	if d, _ := pkgUpgradableResult(&sshx.RunResult{Stderr: "# index-age: never\n"}, false); func() bool { _, ok := d.(opsWarnings); return !ok }() {
		t.Fatal("a never refreshed index must warn")
	}
}

func TestPkgChangeResult(t *testing.T) {
	out := "#komando:before\ntree\t-\nbash\t5.2\n#komando:after\ntree\t2.1\nbash\t5.2\n"
	d, e := pkgChangeResult(tcl, "install", []string{"tree", "bash"}, &sshx.RunResult{Stdout: out})
	res := d.(pkgChange)
	if e != nil || !res.Changed || res.Packages[0].State != "installed" || res.Packages[1].State != "already installed" {
		t.Fatalf("install: %+v %v", res, e)
	}
	none := "#komando:before\nnope\t-\n#komando:after\nnope\t-\n"
	_, e = pkgChangeResult(tcl, "install", []string{"nope"}, &sshx.RunResult{Stdout: none, ExitCode: 100, Stderr: "E: Unable to locate package nope"})
	if e == nil || e.Code != "PACKAGE_NOT_FOUND" || e.Exit != 3 || !strings.Contains(e.Message, "nope") {
		t.Fatalf("unknown package: %v", e)
	}
	d, e = pkgChangeResult(tcl, "remove", []string{"nope"}, &sshx.RunResult{Stdout: none})
	if e != nil || d.(pkgChange).Changed || d.(pkgChange).Packages[0].State != "not installed" {
		t.Fatalf("removing a missing package is a no-op: %+v %v", d, e)
	}
	up := "#komando:before\na\t1\nb\t1\n#komando:after\na\t2\nb\t1\n"
	d, _ = pkgChangeResult(tcl, "upgrade", nil, &sshx.RunResult{Stdout: up})
	if p := d.(pkgChange).Packages; len(p) != 1 || p[0].Name != "a" || p[0].From != "1" || p[0].Version != "2" {
		t.Fatalf("upgrade diff: %+v", p)
	}
	if s := pkgChangeScript("remove", []string{"tree"}, true); !strings.Contains(s, `$2 != "-"`) || !strings.Contains(s, "#komando:after") {
		t.Fatalf("remove script: %s", s)
	}
}

func TestRunOpsTextBlocks(t *testing.T) {
	d := opsData{Results: []opsRow{{Host: "a", OK: true, text: "x\n"}, {Host: "b", Stderr: "boom"}}, Summary: fleetSummary{Total: 2, OK: 1, Failed: 1}}
	s := d.TextFor(realRun())
	if !strings.Contains(s, "● a  ok\n  x\n") || !strings.Contains(s, "● b  failed\n  | boom\n") {
		t.Fatalf("text:\n%s", s)
	}
	if strings.TrimSpace(sections("junk\n#komando:a\n1\n#komando:b\n2\n")["b"]) != "2" || marker("x\n#komando:no-user\n") != "no-user" {
		t.Fatal("sections/marker")
	}
}

func TestVpnReachableAndHelpers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := ln.Addr().String()
	if up, _ := vpnReachable(&store.Vpn{Kind: "socks", Address: addr}); !up {
		t.Fatal("a listening proxy is up")
	}
	ln.Close()
	if up, d := vpnReachable(&store.Vpn{Kind: "socks", Address: addr}); up || !strings.Contains(d, "does not answer") {
		t.Fatalf("a stopped proxy is down: %s", d)
	}
	if up, d := vpnReachable(&store.Vpn{Kind: "system"}); up || d == "" {
		t.Fatal("system without --check")
	}
	if !ovpnHasKeys("client\n<key>\nX\n</key>\n") || ovpnHasKeys("client\nauth-user-pass\n<ca>\nX\n</ca>\n") {
		t.Fatal("ovpnHasKeys")
	}
	st := &store.State{Tunnels: map[string]*store.Tunnel{"t1": {ID: "t1", Kind: "dynamic", Spec: "127.0.0.1:18180"}}}
	if socksTunnel(st, "127.0.0.1:18180") != "t1" || socksTunnel(st, "127.0.0.1:1") != "" {
		t.Fatal("socksTunnel")
	}
	t.Setenv("T_FIXOPS_SET", "x")
	if w := refWarnings("env:T_FIXOPS_SET", "env:T_FIXOPS_UNSET_VAR", "op://a/b/c"); len(w) != 1 || !strings.Contains(w[0], "T_FIXOPS_UNSET_VAR") {
		t.Fatalf("refWarnings: %v", w)
	}
}

func TestVpnStatusText(t *testing.T) {
	s := vpnStatusData{Vpns: []vpnStatusRow{{Name: "lab", Kind: "socks", Up: true, Detail: "SOCKS proxy x answers"}}}.Text()
	if !strings.Contains(s, "lab   socks  yes") {
		t.Fatal(s)
	}
}

func TestFlagUsageHasNoBackticks(t *testing.T) {
	// cobra reads a `word` in a flag's usage as its type placeholder
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if strings.Contains(f.Usage, "`") {
				t.Errorf("%s --%s: backtick in usage %q", c.CommandPath(), f.Name, f.Usage)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	for _, root := range []func() *cobra.Command{vpnCmd, pkgCmd, logsCmd} {
		walk(root())
	}
}

func TestJournalWithoutPermissionSaysSudo(t *testing.T) {
	j := &logOpts{unit: "t-svc"}
	_, e := j.result(&sshx.RunResult{ExitCode: 1, Stderr: "Hint: You are currently not seeing messages from other users and the system.\nNo journal files were opened due to insufficient permissions.\n"})
	if e == nil || e.Code != "JOURNAL_PERMISSION" || !strings.Contains(e.Hint, "--sudo") {
		t.Fatalf("got %+v", e)
	}
}

// Replacing a recipe with a read-only one needs --yes; for an AI agent the
// person is asked on the screen, and that happens while the state file is
// free, so other komando commands do not wait for the answer.
func TestRecipeReadOnlyAsksBeforeLocking(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	run := func(args ...string) error {
		root := newRoot(tcl)
		t.Cleanup(endCommand) // the next test starts with none of this command's flags
		root.SetArgs(append([]string{"-o", "json"}, args...))
		return root.Execute()
	}
	if err := run("recipe", "add", "du", "du -sh /srv"); err != nil {
		t.Fatal(err)
	}
	if e := toErr(run("recipe", "add", "du", "du -sh /srv", "--read-only", "--overwrite")); e == nil || e.Code != "SAFETY_SETTING" {
		t.Fatalf("read-only over a normal recipe without --yes: %v", e)
	}
	setCallerEnv(t, "CLAUDECODE", "1") // an agent: the approval window asks
	saved := askOnScreen
	defer func() { askOnScreen = saved; setGate(tcl, false, gateYes); resetApproval() }()
	lockFree := false
	askOnScreen = func(*call, string) (bool, bool) {
		done := make(chan error, 1)
		go func() { done <- store.Update(store.Save(), func(*store.State) error { return nil }) }()
		select {
		case <-done:
			lockFree = true
		case <-time.After(2 * time.Second):
		}
		return true, true
	}
	if err := run("recipe", "add", "du", "du -sh /srv", "--read-only", "--overwrite", "--yes"); err != nil {
		t.Fatal(err)
	}
	if !lockFree {
		t.Error("the approval window was shown while the state was locked")
	}
	st, _ := store.Load()
	if !st.Snippets["du"].ReadOnly {
		t.Error("the recipe was not replaced")
	}
}

// config set asks about a safety change before locking the state, too.
func TestConfigSetAsksBeforeLocking(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	setCallerEnv(t, "CLAUDECODE", "1")
	saved := askOnScreen
	defer func() { askOnScreen = saved; setGate(tcl, false, gateYes); resetApproval() }()
	lockFree := false
	askOnScreen = func(*call, string) (bool, bool) {
		done := make(chan error, 1)
		go func() { done <- store.Update(store.Save(), func(*store.State) error { return nil }) }()
		select {
		case <-done:
			lockFree = true
		case <-time.After(2 * time.Second):
		}
		return true, true
	}
	root := newRoot(tcl)
	t.Cleanup(endCommand) // the next test starts with none of this command's flags
	root.SetArgs([]string{"-o", "json", "config", "set", "audit_sql", "off", "--yes"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !lockFree {
		t.Error("the approval window was shown while the state was locked")
	}
	st, _ := store.Load()
	if st.Settings.AuditSQL != "off" {
		t.Errorf("audit_sql %q", st.Settings.AuditSQL)
	}
}

// An unknown recipe points to the list.
func TestRecipeNotFound(t *testing.T) {
	if e := recipeNotFound("t-nope"); !strings.Contains(e.Hint, "recipe list") {
		t.Errorf("unknown recipe: %+v", e)
	}
}

// When sudo refuses before the command runs, the error says why and what
// to run next, instead of a bare "exit code 1".
func TestSudoProblem(t *testing.T) {
	cases := []struct {
		stderr string
		exit   int
		code   string
		hint   string
	}{
		{"sudo: a password is required\n", 1, "PERMISSION_DENIED", "`komando host edit web1 --sudo-ref secret:web1-sudo`"},
		{"sudo: a terminal is required to read the password; either use the -S option", 1, "PERMISSION_DENIED", "`komando secret set web1-sudo`"},
		{"deploy is not in the sudoers file.  This incident will be reported.", 1, "PERMISSION_DENIED", "`komando host edit web1 --user OTHER`"},
		{"Sorry, user deploy may not run sudo on web1.", 1, "PERMISSION_DENIED", "wheel"},
		{"sh: 1: sudo: not found", 127, "TOOL_MISSING", "--no-sudo"},
		{"bash: sudo: command not found", 127, "TOOL_MISSING", "--no-sudo"},
		{"E: Unable to locate package nope", 100, "", ""},
		{"sudo: a password is required", 0, "", ""}, // it ran: not a sudo problem
	}
	for _, c := range cases {
		e := sudoProblem("web1", &sshx.RunResult{Stderr: c.stderr, ExitCode: c.exit})
		switch {
		case c.code == "" && e != nil:
			t.Errorf("%q: %v", c.stderr, e)
		case c.code != "" && (e == nil || e.Code != c.code || !strings.Contains(e.Hint, c.hint)):
			t.Errorf("%q: %+v", c.stderr, e)
		}
	}
	if e := sudoProblem("", &sshx.RunResult{Stderr: "sudo: a password is required", ExitCode: 1}); !strings.Contains(e.Hint, "--sudo-ref secret:NAME-sudo") {
		t.Errorf("a group names NAME: %q", e.Hint)
	}
}

// docker ps, stats and images (probes) and the other docker commands name a
// sudo refusal under --sudo like the modules do; as root, the fix is to
// leave out --sudo (docker has no --no-sudo). Without --sudo the same
// stderr is docker's own error.
func TestDockerSudoRefusal(t *testing.T) {
	refused := &sshx.RunResult{Stderr: "sudo: a password is required\n", ExitCode: 1}
	e := dockerExit("web1", true, refused)
	if e == nil || e.Code != "PERMISSION_DENIED" || !strings.Contains(e.Hint, "leave out --sudo") || strings.Contains(e.Hint, "--no-sudo") {
		t.Errorf("refused: %+v", e)
	}
	if e := dockerExit("web1", true, &sshx.RunResult{Stderr: "sh: 1: sudo: not found", ExitCode: 127}); e == nil || e.Code != "TOOL_MISSING" || !strings.Contains(e.Hint, "leave out --sudo") {
		t.Errorf("no sudo: %+v", e)
	}
	if e := dockerExit("web1", false, &sshx.RunResult{ExitCode: 127}); e == nil || e.Code != "DOCKER_MISSING" {
		t.Errorf("no docker: %+v", e)
	}
	if e := dockerExit("web1", true, &sshx.RunResult{Stderr: "Error: No such container: x", ExitCode: 1}); e == nil || e.Code != "DOCKER_OBJECT_NOT_FOUND" {
		t.Errorf("docker error under --sudo: %+v", e)
	}
	if e := dockerExit("web1", true, &sshx.RunResult{}); e != nil {
		t.Errorf("worked: %+v", e)
	}
}

// pkg rm is pkg.rm everywhere (envelope, audit, Windows refusal), not the
// package managers' "remove", and a missing package is the usual usage
// error that names the Use line.
func TestPkgRmIsPkgRm(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["web1"] = &store.Host{Name: "web1", Address: "10.255.255.1", User: "deploy"}
		st.Hosts["win1"] = &store.Host{Name: "win1", Address: "10.255.255.4", User: "admin", OS: "windows"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { setGate(tcl, false, gateDryRun) }()
	o := captureOutput(t, func() error { return runRoot(t, "-o", "json", "--dry-run", "pkg", "rm", "web1", "telnet") })
	if !strings.Contains(o, `"command":"pkg.rm"`) || !strings.Contains(o, `"remote_command":"pkg rm telnet"`) {
		t.Errorf("dry run: %s", o)
	}
	setGate(tcl, false, gateDryRun)
	if e := toErr(runRoot(t, "-o", "json", "pkg", "rm", "win1", "telnet")); e == nil || !strings.Contains(e.Message, "pkg rm does not work on Windows") {
		t.Errorf("windows: %v", e)
	}
	if e := toErr(runRoot(t, "-o", "json", "pkg", "install", "web1")); e == nil || e.Code != "USAGE" || !strings.Contains(e.Message, "usage: komando pkg install TARGET PACKAGE...") {
		t.Errorf("missing package: %v", e)
	}
}

// The Use lines name what each argument is, so help, usage errors and the
// prompter's pickers can tell a container from an image.
func TestDockerUseNamesTheArgument(t *testing.T) {
	root := newRoot(tcl)
	for path, word := range map[string]string{"start": "CONTAINER...", "stop": "CONTAINER...", "restart": "CONTAINER...",
		"rm": "CONTAINER...", "pull": "IMAGE...", "logs": "CONTAINER", "exec": "CONTAINER"} {
		c, _, err := root.Find([]string{"docker", path})
		if err != nil {
			t.Fatal(err)
		}
		if f := strings.Fields(c.Use); len(f) < 3 || f[2] != word {
			t.Errorf("docker %s: Use %q, want %s second", path, c.Use, word)
		}
	}
}

// A CONTAINER that starts with - would be an option of docker itself:
// docker exec --privileged gets the server's devices and capabilities,
// past the check of the command.
func TestDockerContainerIsNeverAnOption(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["web1"] = &store.Host{Name: "web1", Address: "10.255.255.1", User: "deploy"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { setGate(tcl, false, gateDryRun) }()
	for _, args := range [][]string{
		{"--dry-run", "docker", "exec", "web1", "--", "--privileged", "-u", "root", "api", "sh"},
		{"--dry-run", "docker", "exec", "web1", "--", "-e", "X=1", "api", "id"},
		{"--dry-run", "logs", "web1", "--container=--details"},
		{"--dry-run", "docker", "logs", "web1", "--", "--since=1h"},
	} {
		if e := toErr(runRoot(t, append([]string{"-o", "json"}, args...)...)); e == nil || e.Code != "USAGE" || !strings.Contains(e.Message, "is not a container name or ID") {
			t.Errorf("%v: %v", args, e)
		}
		setGate(tcl, false, gateDryRun)
	}
	o := captureOutput(t, func() error {
		return runRoot(t, "-o", "json", "--dry-run", "docker", "exec", "web1", "shop_api.1", "--", "id")
	})
	if !strings.Contains(o, `docker exec -i 'shop_api.1' 'id'`) {
		t.Errorf("a real name: %s", o)
	}
}

// Ctrl-C ends logs --follow: the lines so far are the result, exit 0,
// not CANCELLED (it is how a person stops a follow, like --timeout).
func TestFollowEndsCleanlyOnCtrlC(t *testing.T) {
	s := startFakeServer(t)
	lines := make([]string, 60)
	for i := range lines {
		lines[i] = "line\n"
	}
	s.reply(lines...)
	// a command's context carries its call (a new server's key is pinned
	// only for one)
	ctx, cancel := context.WithCancel(withCall(context.Background(), tcl))
	time.AfterFunc(400*time.Millisecond, cancel)
	defer cancel()
	err := runFleet(tcl, ctx, "logs", "dev", "tail -n 200 -F -- '/var/log/x'", nil, execOpts{stream: true, follow: true}, false)
	if err != nil {
		t.Fatalf("Ctrl-C on a follow: %v", err)
	}
}

// pkg upgradable reads the system's package index (as root when sudo needs
// no password), like facts and pkg security: dnf keeps a cache per user,
// and the login user's own listed 48 updates where root's listed 4.
func TestPkgUpgradableReadsAsRootWhenItCan(t *testing.T) {
	s := startFakeServer(t)
	s.reply("")
	_ = runRoot(t, "-o", "json", "pkg", "upgradable", "dev")
	ex := s.take()
	if len(ex) == 0 || !strings.Contains(ex[0].cmd, `sudo -n true 2>/dev/null; then exec sudo -n sh -c `) {
		t.Fatalf("upgradable: %v", ex)
	}
}

// A recipe category typo is a usage error, not an empty list.
func TestRecipeListCategoryTypo(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	if e := toErr(runRoot(t, "-o", "json", "recipe", "list", "--category", "secrity")); e == nil || e.Code != "USAGE" || !strings.Contains(e.Message, "security") {
		t.Errorf("unknown category: %v", e)
	}
}
