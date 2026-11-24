package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
)

// Recorded on Ubuntu 22.04 (ubuntu:jammy-20230425 after apt-get update),
// cut to a few packages.
const aptSecList = `#komando:pm
apt
#komando:index-age
2557
#komando:before
pending=61
security=3
#komando:security
apt/jammy-security 2.4.15ubuntu0.1 arm64 [upgradable from: 2.4.9]
bash/jammy-updates,jammy-security 5.1-6ubuntu1.1 arm64 [upgradable from: 5.1-6ubuntu1]
libc6/jammy-updates,jammy-security 2.35-0ubuntu3.15 arm64 [upgradable from: 2.35-0ubuntu3.1]
#komando:removes

`

const aptSecApply = aptSecList + `#komando:method
apt-get
#komando:rc
0
#komando:after
pending=13
security=0
#komando:changed
apt	2.4.9	2.4.15ubuntu0.1
bash	5.1-6ubuntu1	5.1-6ubuntu1.1
libc6:arm64	2.35-0ubuntu3.1	2.35-0ubuntu3.15
linux-image-6.8.0-90-generic	-	6.8.0-90.91
`

func TestPkgSecAptList(t *testing.T) {
	r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: aptSecList}, false, false)
	if !r.OK || r.PackageManager != "apt" || r.Count != 3 || r.Security[1].Name != "bash" || r.Security[1].From != "5.1-6ubuntu1" || r.Security[1].Version != "5.1-6ubuntu1.1" {
		t.Fatalf("row: %+v", r)
	}
	if r.State == nil || r.State.PendingUpdates != 61 || r.State.PendingSecurity != 3 || r.State.ContainersRunning != nil || r.Before != nil {
		t.Errorf("state: %+v", r.State)
	}
	if r.IndexAge != "42m" || len(r.Warnings) != 0 {
		t.Errorf("index age %q, warnings %v", r.IndexAge, r.Warnings)
	}
	stale := strings.Replace(aptSecList, "2557", "200000", 1)
	if r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: stale}, false, false); len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "--refresh") {
		t.Errorf("stale index: %v", r.Warnings)
	}
	withRm := strings.Replace(aptSecList, "#komando:removes\n", "#komando:removes\nopenssh-server\n", 1)
	if r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: withRm}, false, false); len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "openssh-server") {
		t.Errorf("essential removal: %v", r.Warnings)
	}
}

func TestPkgSecAptApply(t *testing.T) {
	r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: aptSecApply}, true, false)
	if !r.OK || r.Error != nil || r.Method != "apt-get" || len(r.Upgraded) != 4 || r.Upgraded[2].Name != "libc6:arm64" || r.Upgraded[2].From != "2.35-0ubuntu3.1" {
		t.Fatalf("row: %+v", r)
	}
	if r.Upgraded[3].From != "" || r.Upgraded[3].Version != "6.8.0-90.91" {
		t.Errorf("new kernel: %+v", r.Upgraded[3])
	}
	if r.Before == nil || r.After == nil || r.After.PendingSecurity != 0 || len(r.Unexpected) != 0 {
		t.Errorf("snapshots: %+v %+v %v", r.Before, r.After, r.Unexpected)
	}
	if !slicesHas(r.Changes, "pending updates 61 -> 13") || !slicesHas(r.Changes, "pending security updates 3 -> 0") {
		t.Errorf("changes: %v", r.Changes)
	}
	nothing := strings.Replace(aptSecList, "#komando:removes\n", "#komando:nothing\n", 1)
	if r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: nothing}, true, false); !r.OK || r.Method != "" || r.After == nil {
		t.Errorf("nothing to do: %+v", r)
	}
}

func slicesHas(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Fewer running containers or a newly failed unit stop the round.
func TestPkgSecUnexpectedChange(t *testing.T) {
	s := strings.Replace(aptSecApply, "#komando:before\n", "#komando:before\ncontainers=12\nfailed=old.service\n", 1)
	s = strings.Replace(s, "#komando:after\n", "#komando:after\ncontainers=10\nfailed=docker.service\nreboot=yes\nreboot_pkg=libc6\nsvc=containerd.service\n", 1)
	r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: s}, true, false)
	if r.OK || r.Error == nil || r.Error.Code != "UNEXPECTED_CHANGE" || r.Error.Exit != out.ExitConflict || !strings.Contains(r.Error.Hint, "--keep-going") {
		t.Fatalf("row: %+v %+v", r, r.Error)
	}
	for _, want := range []string{"running containers 12 -> 10", "unit failed: docker.service"} {
		if !slicesHas(r.Unexpected, want) {
			t.Errorf("unexpected %v misses %q", r.Unexpected, want)
		}
	}
	for _, want := range []string{"unit no longer failed: old.service", "a reboot is now required", "now need a restart: containerd.service"} {
		if !slicesHas(r.Changes, want) {
			t.Errorf("changes %v miss %q", r.Changes, want)
		}
	}
	if !r.RebootRequired || r.After.RebootPackages[0] != "libc6" {
		t.Errorf("reboot: %+v", r.After)
	}
	// more containers is fine
	ok := strings.Replace(aptSecApply, "#komando:before\n", "#komando:before\ncontainers=3\n", 1)
	ok = strings.Replace(ok, "#komando:after\n", "#komando:after\ncontainers=4\n", 1)
	if r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: ok}, true, false); !r.OK {
		t.Errorf("more containers: %+v", r.Error)
	}
}

func TestPkgSecFailures(t *testing.T) {
	ess := strings.Replace(aptSecList, "#komando:removes\n", "#komando:removes\nopenssh-server\n#komando:essential\nopenssh-server\n", 1)
	if r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: ess}, true, false); r.Error == nil || r.Error.Code != "POLICY_BLOCKED" || r.Error.Exit != out.ExitPolicy || len(r.Upgraded) != 0 {
		t.Errorf("essential: %+v", r.Error)
	}
	failed := strings.Replace(aptSecApply, "#komando:rc\n0\n", "#komando:rc\n100\n", 1)
	if r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: failed}, true, false); r.Error == nil || r.Error.Code != "PKG_FAILED" || !strings.Contains(r.Error.Message, "100") {
		t.Errorf("failed: %+v", r.Error)
	}
	cut := aptSecList + "#komando:method\napt-get\n"
	if r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: cut, TimedOut: true}, true, false); r.Error == nil || r.Error.Code != "TIMEOUT" || !strings.Contains(r.Error.Hint, "keeps running") {
		t.Errorf("timeout: %+v", r.Error)
	}
	if r := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: "#komando:unsupported\nnone\n"}, false, false); r.unsupported != "none" {
		t.Errorf("unsupported: %+v", r)
	}
	if r := pkgSecParse(tcl, "web1", &sshx.RunResult{ExitCode: 1, Stderr: "sudo: a password is required"}, false, false); r.Error == nil || r.Error.Code != "PKG_FAILED" {
		t.Errorf("no output: %+v", r.Error)
	}
}

func TestPkgSecDnf(t *testing.T) {
	s := `#komando:pm
dnf
#komando:before
pending=4
security=2
svc=sshd.service
reboot=yes
#komando:security
openssl-libs.x86_64          1:3.0.7-18.el9_2          baseos
curl.x86_64                  7.76.1-26.el9_3.2         baseos
#komando:method
dnf
#komando:rc
0
#komando:after
pending=2
security=0
reboot=yes
svc=sshd.service
#komando:changed
openssl-libs.x86_64	1:3.0.7-17.el9	1:3.0.7-18.el9_2
curl.x86_64	7.76.1-26.el9	7.76.1-26.el9_3.2
`
	r := pkgSecParse(tcl, "rh1", &sshx.RunResult{Stdout: s}, true, false)
	if !r.OK || r.Count != 2 || r.Security[0].Name != "openssl-libs" || len(r.Upgraded) != 2 || !r.RebootRequired || r.IndexAge != "" {
		t.Fatalf("row: %+v", r)
	}
	if slicesHas(r.Changes, "a reboot is now required") || len(r.Unexpected) != 0 {
		t.Errorf("changes: %v", r.Changes)
	}
}

func TestPkgSecSnapshotNeedrestart(t *testing.T) {
	s := parseSnapshot("containers=0\nksta=3\nsvc=docker.service\nsvc=docker.service\nsvc=cron.service\nnoise\n")
	if s.ContainersRunning == nil || *s.ContainersRunning != 0 || !s.RebootRequired || s.RebootPackages[0] != "kernel" || len(s.NeedRestart) != 2 {
		t.Errorf("snapshot: %+v", s)
	}
	if s := parseSnapshot("ksta=1\n"); s.RebootRequired || s.FailedUnits == nil || s.NeedRestart == nil {
		t.Errorf("current kernel: %+v", s)
	}
}

// The script runs the upgrade with needrestart quiet and config files
// kept, and nothing in it trips komando's own destructive-command rules.
func TestPkgSecScript(t *testing.T) {
	s := pkgSecScript(true, true, true)
	for _, want := range []string{"ACTION=apply REFRESH=1 GUARD=1", "NEEDRESTART_SUSPEND=1", "NEEDRESTART_MODE=l", "--force-confold", "--only-upgrade",
		"unattended-upgrade", "Automatic-Reboot", "upgrade --security -y", "setsid", "nohup", "openssh-server"} {
		if !strings.Contains(s, want) {
			t.Errorf("script misses %q", want)
		}
	}
	if !strings.HasPrefix(pkgSecScript(false, false, false), "ACTION=list REFRESH=0 GUARD=0") {
		t.Error("list script")
	}
	if hits := policy.CheckScript(s, nil); len(hits) != 0 {
		t.Errorf("policy hits: %+v", hits)
	}
}

// pkg security only lists: no protected stop (the closed port fails
// instead), and it takes no --apply or --keep-going.
func TestPkgSecGates(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@127.0.0.1", "--port", "2")
	mustRun(t, "host", "edit", "web1", "--protected")
	if _, e := invRun(t, "pkg", "security", "web1"); e == nil || e.Code == "PROTECTED_TARGET" {
		t.Errorf("list: %+v", e)
	}
	wantCode(t, "USAGE", "pkg", "security", "web1", "--apply")
	wantCode(t, "USAGE", "pkg", "security", "web1", "--keep-going")
}

func TestPkgSecText(t *testing.T) {
	list := pkgSecParse(tcl, "web1", &sshx.RunResult{Stdout: aptSecList}, false, false)
	s := strings.Replace(aptSecApply, "#komando:after\n", "#komando:after\nreboot=yes\nsvc=containerd.service\n", 1)
	applied := pkgSecParse(tcl, "web2", &sshx.RunResult{Stdout: s}, true, false)
	txt := pkgSecData{Results: []pkgSecRow{list}}.Text()
	if !strings.Contains(txt, "web1  3 security updates (apt)") || !strings.Contains(txt, "bash") {
		t.Errorf("list text:\n%s", txt)
	}
	txt = pkgSecData{Applied: true, Results: []pkgSecRow{applied}, NotRun: []string{"web3"}}.Text()
	for _, want := range []string{"web2  patched, 4 packages changed (apt-get)", "need a restart: containerd.service", "komando reboot web2", "not patched (stopped): web3"} {
		if !strings.Contains(txt, want) {
			t.Errorf("apply text misses %q:\n%s", want, txt)
		}
	}
}

// --refresh rewrites the server's package index as root, which is a
// change: on a protected server pkg upgradable and pkg security need a yes
// for it, and a dry run never refreshes.
func TestPkgRefreshIsAChange(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@127.0.0.1", "--port", "2")
	mustRun(t, "host", "edit", "web1", "--protected")
	wantCode(t, "PROTECTED_TARGET", "pkg", "security", "web1", "--refresh")
	wantCode(t, "PROTECTED_TARGET", "pkg", "upgradable", "web1", "--refresh")
	for _, args := range [][]string{{"pkg", "security", "web1"}, {"pkg", "upgradable", "web1"}} {
		if _, e := invRun(t, args...); e == nil || e.Code == "PROTECTED_TARGET" {
			t.Errorf("%v only lists: %+v", args, e)
		}
	}
	for _, args := range [][]string{{"pkg", "security", "web1", "--refresh", "--dry-run"}, {"pkg", "upgradable", "web1", "--refresh", "--dry-run"}} {
		if _, text := runMain(t, args...); !strings.Contains(text, "would_be_blocked") || !strings.Contains(text, "PROTECTED_TARGET") {
			t.Errorf("%v: %s", args, text)
		}
	}
	defer func() { tcl.flags.dryRun = false }()
	tcl.flags.dryRun = false
	if !pkgSecRefresh(tcl, true) || pkgSecRefresh(tcl, false) {
		t.Error("a real run refreshes when asked")
	}
	tcl.flags.dryRun = true
	if pkgSecRefresh(tcl, true) {
		t.Error("a dry run sends REFRESH=1")
	}
}

// recorded from alpine:3.20 (trimmed)
const apkSecList = `#komando:pm
apk
#komando:notices
no
#komando:before
pending=3
security=0
#komando:security
#komando:unclassified
apk-tools-2.14.13-r0 x86_64 {apk-tools} (GPL-2.0-only) [upgradable from: apk-tools-2.14.4-r1]
musl-1.2.5-r4 x86_64 {musl} (MIT) [upgradable from: musl-1.2.5-r3]
ca-certificates-bundle-20261020-r0 x86_64 {ca-certificates} (MPL-2.0 AND MIT) [upgradable from: ca-certificates-bundle-20260413-r0]
`

// Where the repositories keep no security notices, pkg security says so
// and lists every pending update instead of an empty list; installing
// "only the security updates" there stops with SECURITY_UNSUPPORTED.
func TestPkgSecNoNotices(t *testing.T) {
	r := pkgSecParse(tcl, "a1", &sshx.RunResult{Stdout: apkSecList}, false, false)
	if !r.OK || r.SecurityNotices || r.Count != 0 || len(r.Unclassified) != 3 || r.Unclassified[1].Name != "musl" || r.Unclassified[1].From != "1.2.5-r3" {
		t.Fatalf("%+v", r)
	}
	if len(r.Warnings) == 0 || !strings.Contains(r.Warnings[0], "all 3 pending updates") {
		t.Errorf("warnings %v", r.Warnings)
	}
	dnf := "#komando:pm\ndnf\n#komando:notices\nno\n#komando:before\npending=1\n#komando:security\n#komando:unclassified\nopenssl.x86_64  1:3.0.7-28.el9  baseos\n"
	if r := pkgSecParse(tcl, "c1", &sshx.RunResult{Stdout: dnf}, false, false); r.SecurityNotices || len(r.Unclassified) != 1 || r.Unclassified[0].Name != "openssl" {
		t.Errorf("dnf without notices: %+v", r)
	}
	for pm, want := range map[string]string{"apk": "publish no security notices", "pacman": "no partial upgrades"} {
		out := "#komando:pm\n" + pm + "\n#komando:notices\nno\n#komando:before\npending=1\n#komando:security\n#komando:no-notices\n"
		if r := pkgSecParse(tcl, "x", &sshx.RunResult{Stdout: out}, true, false); r.Error == nil || r.Error.Code != "SECURITY_UNSUPPORTED" || !strings.Contains(r.Error.Message, want) || !strings.Contains(r.Error.Hint, "pkg upgrade x") {
			t.Errorf("%s apply: %+v", pm, r.Error)
		}
	}
	// zypper: security patches by name; pacman: arch-audit's package names
	zy := "#komando:pm\nzypper\n#komando:notices\nyes\n#komando:before\npending=2\n#komando:security\nopenSUSE-SLE-15.6-2026-4101\nopenSUSE-SLE-15.6-2026-4120\n"
	if r := pkgSecParse(tcl, "s1", &sshx.RunResult{Stdout: zy}, false, false); !r.SecurityNotices || r.Count != 2 || r.Security[0].Name != "openSUSE-SLE-15.6-2026-4101" || len(r.Warnings) != 0 {
		t.Errorf("zypper: %+v", r)
	}
	if !strings.Contains(pkgSecScript(true, false, true), `run="zypper -n patch --category security"`) {
		t.Error("zypper applies security patches")
	}
}
