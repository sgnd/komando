package cli

import (
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
	if !strings.Contains(svcTable(units), "nginx.service  active") {
		t.Fatalf("table:\n%s", svcTable(units))
	}
}

func TestSvcActionResult(t *testing.T) {
	ok := "Id=web.service\nLoadState=loaded\nActiveState=active\n#komando:rc=0\n"
	if _, err := svcActionResult("restart", 5, &sshx.RunResult{Stdout: ok}); err != nil {
		t.Fatal(err)
	}
	failed := "Id=web.service\nLoadState=loaded\nActiveState=failed\n#komando:rc=0\n"
	if _, err := svcActionResult("restart", 5, &sshx.RunResult{Stdout: failed}); err == nil || err.Code != "UNIT_NOT_ACTIVE" {
		t.Fatalf("--wait must fail on a failed unit: %v", err)
	}
	if _, err := svcActionResult("restart", 0, &sshx.RunResult{Stdout: failed}); err != nil {
		t.Fatalf("without --wait only systemctl's exit counts: %v", err)
	}
	rc := "Id=web.service\nLoadState=loaded\nActiveState=failed\n#komando:rc=1\n"
	if _, err := svcActionResult("start", 0, &sshx.RunResult{Stdout: rc}); err == nil || err.Code != "SVC_FAILED" {
		t.Fatalf("systemctl failure: %v", err)
	}
	s := svcScript("enable", []string{"web"}, true, 0)
	if !strings.Contains(s, "systemctl enable --now -- 'web'") || !strings.HasPrefix(s, noSystemd) {
		t.Fatalf("script:\n%s", s)
	}
	if s := svcScript("restart", []string{"web"}, false, 7); !strings.Contains(s, "-lt 7") {
		t.Fatalf("wait loop missing:\n%s", s)
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
	d, e := pkgChangeResult("install", []string{"tree", "bash"}, &sshx.RunResult{Stdout: out})
	res := d.(pkgChange)
	if e != nil || !res.Changed || res.Packages[0].State != "installed" || res.Packages[1].State != "already installed" {
		t.Fatalf("install: %+v %v", res, e)
	}
	none := "#komando:before\nnope\t-\n#komando:after\nnope\t-\n"
	_, e = pkgChangeResult("install", []string{"nope"}, &sshx.RunResult{Stdout: none, ExitCode: 100, Stderr: "E: Unable to locate package nope"})
	if e == nil || e.Code != "PACKAGE_NOT_FOUND" || e.Exit != 3 || !strings.Contains(e.Message, "nope") {
		t.Fatalf("unknown package: %v", e)
	}
	d, e = pkgChangeResult("remove", []string{"nope"}, &sshx.RunResult{Stdout: none})
	if e != nil || d.(pkgChange).Changed || d.(pkgChange).Packages[0].State != "not installed" {
		t.Fatalf("removing a missing package is a no-op: %+v %v", d, e)
	}
	up := "#komando:before\na\t1\nb\t1\n#komando:after\na\t2\nb\t1\n"
	d, _ = pkgChangeResult("upgrade", nil, &sshx.RunResult{Stdout: up})
	if p := d.(pkgChange).Packages; len(p) != 1 || p[0].Name != "a" || p[0].From != "1" || p[0].Version != "2" {
		t.Fatalf("upgrade diff: %+v", p)
	}
	if s := pkgChangeScript("remove", []string{"tree"}, true); !strings.Contains(s, `$2 != "-"`) || !strings.Contains(s, "#komando:after") {
		t.Fatalf("remove script: %s", s)
	}
}

func TestParsePorts(t *testing.T) {
	ss := "#komando:ss\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=12,fd=3))\nudp UNCONN 0 0 [::]:68 [::]:*\n"
	rows, err := parsePorts(ss)
	if err != nil || len(rows) != 2 || rows[0]["process"] != "sshd" || rows[0]["pid"] != 12 || rows[0]["port"] != 22 || rows[1]["address"] != "::" {
		t.Fatalf("ss: %v %v", rows, err)
	}
	ns := "#komando:netstat\nActive Internet connections (only servers)\nProto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n" +
		"tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1/sshd\ntcp 0 0 :::2377 :::* LISTEN -\nudp 0 0 0.0.0.0:4789 0.0.0.0:* 34/dockerd\n"
	rows, err = parsePorts(ns)
	if err != nil || len(rows) != 3 {
		t.Fatalf("netstat: %v %v", rows, err)
	}
	if rows[0]["process"] != "sshd" || rows[0]["pid"] != 1 || rows[1]["address"] != "::" || rows[1]["port"] != 2377 || rows[1]["process"] != nil ||
		rows[2]["proto"] != "udp" || rows[2]["state"] != "UNCONN" || rows[2]["pid"] != 34 {
		t.Fatalf("netstat rows: %v", rows)
	}
	if !strings.Contains(netPortsText(rows), "PROTO  ADDRESS") {
		t.Fatal(netPortsText(rows))
	}
	if _, err := parsePorts("#komando:no-tool\n"); err == nil || err.Code != "TOOL_MISSING" {
		t.Fatalf("no tool: %v", err)
	}
}

func TestParseNetCheck(t *testing.T) {
	rows, err := parseNetCheck("db:5432 open - 3\nredis:6379 closed refused 1\nx:1 closed timeout 5000\n")
	if err == nil || err.Code != "PORT_CLOSED" || !strings.Contains(err.Message, "redis:6379 (refused)") || !strings.Contains(err.Message, "x:1 (timeout)") {
		t.Fatalf("closed: %v", err)
	}
	if rows[0]["open"] != true || rows[0]["reason"] != nil || rows[1]["reason"] != "refused" || rows[0]["ms"] != 3 {
		t.Fatalf("rows: %v", rows)
	}
	if _, err := parseNetCheck("db:5432 open - 3\n"); err != nil {
		t.Fatal(err)
	}
}

func TestNetDNS(t *testing.T) {
	if _, err := dnsCommand("x", "BOGUS"); err == nil {
		t.Fatal("unknown type must be refused")
	}
	c, _ := dnsCommand("example.com", "mx")
	if !strings.Contains(c, "dig +short -t MX 'example.com'") || !strings.Contains(c, "no-dig") {
		t.Fatalf("MX: %s", c)
	}
	c, _ = dnsCommand("example.com", "A")
	if !strings.Contains(c, "getent ahostsv4") {
		t.Fatalf("A falls back to getent: %s", c)
	}
	if _, e := dnsResult("x", "MX", "#komando:no-dig\n"); e == nil || e.Code != "DIG_MISSING" {
		t.Fatalf("no dig: %v", e)
	}
	if _, e := dnsResult("x", "MX", ""); e == nil || e.Code != "NO_RECORDS" || e.Exit != 3 {
		t.Fatalf("no records: %v", e)
	}
	if _, e := dnsResult("x", "", ""); e == nil || e.Code != "NXDOMAIN" {
		t.Fatalf("nxdomain: %v", e)
	}
	d, e := dnsResult("x", "MX", "10 mail.x.\n")
	if e != nil || dnsText(d) != "10 mail.x.\n" {
		t.Fatalf("records: %v %v", d, e)
	}
}

func TestParseUsersLocked(t *testing.T) {
	s := "#komando:passwd\nroot:x:0:0::/root:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\neve:x:1002:1002::/home/eve:/bin/sh\nsys:x:5:5::/:/usr/sbin/nologin\n" +
		"#komando:groups\nsudo:x:27:bob\n#komando:expire\nroot:\nbob:\neve:1\n#komando:today\n20000\n"
	rows := parseUsers(s, false)
	if len(rows) != 3 {
		t.Fatalf("rows: %+v", rows)
	}
	if !rows[1].AdminGroup || rows[2].AdminGroup || !rows[0].AdminGroup {
		t.Fatalf("admin groups: %+v", rows)
	}
	if rows[1].Locked == nil || *rows[1].Locked || rows[2].Locked == nil || !*rows[2].Locked {
		t.Fatalf("locked: %+v", rows)
	}
	if rows := parseUsers(strings.Replace(s, "eve:1\n", "", 1), false); rows[2].Locked != nil {
		t.Fatal("without an expiry line the state is unknown")
	}
	if !strings.Contains(usersText(rows), "LOCKED") {
		t.Fatal(usersText(rows))
	}
	if _, e := userResult("bob", "locked", &sshx.RunResult{Stdout: "#komando:no-user\n"}); e == nil || e.Code != "USER_NOT_FOUND" || e.Exit != 3 {
		t.Fatalf("unknown user: %v", e)
	}
}

func TestCronParsing(t *testing.T) {
	r := parseCronLine(`*/5 * * * * date +\%F >/dev/null # komando:bk`)
	if r["schedule"] != "*/5 * * * *" || r["command"] != `date +\%F >/dev/null` || r["id"] != "bk" {
		t.Fatalf("parse: %v", r)
	}
	r = parseCronLine("@daily  run  me")
	if r["schedule"] != "@daily" || r["command"] != "run  me" {
		t.Fatalf("macro: %v", r)
	}
	d, _ := cronRemoved(&sshx.RunResult{Stdout: "removed 2\n"})
	if d.(map[string]any)["removed"] != 2 {
		t.Fatalf("removed: %v", d)
	}
}

func TestRunOpsTextBlocks(t *testing.T) {
	d := opsData{Results: []opsRow{{Host: "a", OK: true, text: "x\n"}, {Host: "b", Stderr: "boom"}}, Summary: fleetSummary{Total: 2, OK: 1, Failed: 1}}
	s := d.Text()
	if !strings.Contains(s, "● a  ok\n  x\n") || !strings.Contains(s, "● b  FAILED\n  | boom\n") {
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
	for _, root := range []func() *cobra.Command{vpnCmd, svcCmd, pkgCmd, netCmd, userCmd, cronCmd, logsCmd} {
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

func TestDaemonReloadResult(t *testing.T) {
	d, err := daemonReloadResult(&sshx.RunResult{Stdout: "#komando:rc=0\n"})
	if err != nil || d.(map[string]any)["reloaded"] != true {
		t.Errorf("reload: %v %v", d, err)
	}
	d, err = daemonReloadResult(&sshx.RunResult{Stdout: "stale=app.service\n#komando:rc=0\n"})
	w, ok := d.(opsWarnings)
	if err != nil || !ok || len(w.warnings) != 1 || !strings.Contains(w.warnings[0], "app.service") {
		t.Errorf("a unit still stale: %v %v", d, err)
	}
	if _, err := daemonReloadResult(&sshx.RunResult{Stdout: "#komando:rc=1\n"}); err == nil || err.Code != "SVC_FAILED" {
		t.Errorf("failed reload: %v", err)
	}
	if _, err := daemonReloadResult(&sshx.RunResult{Stdout: "#komando:no-systemd\n"}); err == nil || err.Code != "NO_SYSTEMD" {
		t.Errorf("no systemd: %v", err)
	}
}

// reboot is destructive: blocked without --allow-dangerous, and --dry-run
// says so without touching a server.
func TestRebootNeedsAllowDangerous(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	t.Setenv("KOMANDO_NO_DIALOG", "1")
	t.Setenv("CLAUDECODE", "1")
	defer func() { g.dryRun, g.allowDangerous = false, false }()
	run := func(args ...string) error {
		root := newRoot()
		root.SetArgs(append([]string{"-o", "json"}, args...))
		return root.Execute()
	}
	if err := run("host", "add", "web1", "deploy@10.255.255.1"); err != nil {
		t.Fatal(err)
	}
	if err := run("--dry-run", "reboot", "web1"); err != nil {
		t.Errorf("dry run: %v", err)
	}
	g.dryRun = false
	err := run("reboot", "web1")
	if e := toErr(err); e == nil || e.Code != "POLICY_BLOCKED" {
		t.Errorf("reboot without --allow-dangerous: %v", err)
	}
}

// Replacing a recipe with a read-only one needs --yes; for an AI agent the
// person is asked on the screen, and that happens while the state file is
// free, so other komando commands do not wait for the answer.
func TestRecipeReadOnlyAsksBeforeLocking(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	run := func(args ...string) error {
		root := newRoot()
		root.SetArgs(append([]string{"-o", "json"}, args...))
		return root.Execute()
	}
	if err := run("recipe", "add", "du", "du -sh /srv"); err != nil {
		t.Fatal(err)
	}
	if e := toErr(run("recipe", "add", "du", "du -sh /srv", "--read-only", "--overwrite")); e == nil || e.Code != "SAFETY_SETTING" {
		t.Fatalf("read-only over a normal recipe without --yes: %v", e)
	}
	t.Setenv("CLAUDECODE", "1") // an agent: the approval window asks
	saved := askOnScreen
	defer func() { askOnScreen = saved; g.yes = false; resetApproval() }()
	lockFree := false
	askOnScreen = func(string) (bool, bool) {
		done := make(chan error, 1)
		go func() { done <- store.Update(func(*store.State) error { return nil }) }()
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
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	t.Setenv("CLAUDECODE", "1")
	saved := askOnScreen
	defer func() { askOnScreen = saved; g.yes = false; resetApproval() }()
	lockFree := false
	askOnScreen = func(string) (bool, bool) {
		done := make(chan error, 1)
		go func() { done <- store.Update(func(*store.State) error { return nil }) }()
		select {
		case <-done:
			lockFree = true
		case <-time.After(2 * time.Second):
		}
		return true, true
	}
	root := newRoot()
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

// A retired built-in recipe names the command that replaced it; it is no
// longer a recipe, and the command it names exists.
func TestRetiredRecipesNameTheirCommand(t *testing.T) {
	root := newRoot()
	for name, cmd := range retiredRecipes {
		if builtinRecipe(name) != nil {
			t.Errorf("%s is retired but still a built-in recipe", name)
		}
		e := recipeNotFound(name)
		if e.Code != "RECIPE_NOT_FOUND" || !strings.Contains(e.Hint, cmd) {
			t.Errorf("%s: %+v", name, e)
		}
		f := strings.Fields(cmd)
		if c, _, err := root.Find(f[1:3]); err != nil || c.Name() != f[2] {
			t.Errorf("%s: %q is not a command (%v)", name, cmd, err)
		}
	}
	if e := recipeNotFound("t-nope"); !strings.Contains(e.Hint, "recipe list") {
		t.Errorf("unknown recipe: %+v", e)
	}
}
