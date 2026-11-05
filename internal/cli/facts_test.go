package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var factsNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func bp(b bool) *bool { return &b }

func TestSupportOf(t *testing.T) {
	cases := []struct {
		id, ver, pretty string
		esm             *bool
		want            string
	}{
		{"ubuntu", "20.04", "", bp(false), "unsupported"}, // past standard, no ESM
		{"ubuntu", "20.04", "", nil, "unknown"},           // past standard, ESM unreadable
		{"ubuntu", "20.04", "", bp(true), "extended"},
		{"ubuntu", "24.04", "", bp(false), "supported"},
		{"ubuntu", "16.04", "", bp(true), "unsupported"}, // past ESM too
		{"ubuntu", "25.10", "", nil, "unknown"},          // not in the table
		{"debian", "12", "", nil, "extended"},            // Debian LTS, no subscription
		{"debian", "11", "", nil, "unsupported"},         // LTS ended 2026-08-31
		{"debian", "13", "", nil, "supported"},
		{"rocky", "9.4", "", nil, "supported"},
		{"centos", "7", "CentOS Linux 7 (Core)", nil, "unsupported"},
		{"centos", "9", "CentOS Stream 9", nil, "supported"},
		{"alpine", "3.20.3", "", nil, "unsupported"},
		{"alpine", "3.22.1", "", nil, "supported"},
		{"arch", "", "", nil, "unknown"},
	}
	for _, c := range cases {
		got := supportOf(c.id, c.ver, c.pretty, c.esm, factsNow)
		if got.Status != c.want {
			t.Errorf("%s %s esm=%v: status %q, want %q", c.id, c.ver, c.esm, got.Status, c.want)
		}
	}
	if s := supportOf("debian", "12", "", nil, factsNow); s.ESMEnabled != nil {
		t.Errorf("esm_enabled is for Ubuntu only, got %v", *s.ESMEnabled)
	}
}

func TestOSTableDates(t *testing.T) {
	check := func(id, v string, l osLife) {
		for _, d := range []string{l.standard, l.extended} {
			if d == "" {
				continue
			}
			if _, err := time.Parse("2006-01-02", d); err != nil {
				t.Errorf("%s %s: bad date %q", id, v, d)
			}
		}
		if l.extended != "" && l.extended < l.standard {
			t.Errorf("%s %s: extended support ends before standard support", id, v)
		}
	}
	for id, m := range osTable {
		for v, l := range m {
			check(id, v, l)
		}
	}
	for v, l := range centosStream {
		check("centos-stream", v, l)
	}
}

const aptSimOut = `NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Inst libssl1.1 [1.1.1f-1ubuntu2.19] (1.1.1f-1ubuntu2.20 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [amd64])
Inst python3-security [1.0] (1.1 Ubuntu:20.04/focal-updates [all])
Inst tzdata [2023c-0ubuntu0.20.04.2] (2024a-0ubuntu0.20.04 Ubuntu:20.04/focal-updates [all])
Inst curl [7.68.0-1ubuntu2.20] (7.68.0-1ubuntu2.22 UbuntuESM:20.04/focal-infra-security [amd64])
Inst libc6 [2.36-9] (2.36-9+deb12u7 Debian-Security:12/stable-security [amd64])
Conf libssl1.1 (1.1.1f-1ubuntu2.20 Ubuntu:20.04/focal-updates [amd64])`

func TestAptSimCounts(t *testing.T) {
	total, sec := aptSimCounts(aptSimOut)
	if total != 5 || sec != 3 {
		t.Errorf("total %d security %d, want 5 and 3", total, sec)
	}
	if total, sec := aptSimCounts(""); total != 0 || sec != 0 {
		t.Errorf("empty: %d %d", total, sec)
	}
}

func TestDnfCounts(t *testing.T) {
	upd := `
openssl.x86_64                     1:3.0.7-27.el9          baseos
kernel.x86_64                      5.14.0-427.el9          baseos
Obsoleting Packages
grub2-tools.x86_64                 1:2.06-80.el9           baseos
`
	if n := dnfCheckUpdateCount(upd); n != 2 {
		t.Errorf("check-update: %d, want 2", n)
	}
	sec := `RLSA-2024:1234 Important/Sec. openssl-1:3.0.7-27.el9.x86_64
RLSA-2024:1300 Moderate/Sec.  openssl-1:3.0.7-27.el9.x86_64
RLSA-2024:1400 Important/Sec. kernel-5.14.0-427.el9.x86_64`
	if n := dnfSecurityCount(sec); n != 2 {
		t.Errorf("security: %d, want 2", n)
	}
}

func TestParseProESM(t *testing.T) {
	on := `{"attached": true, "services": [{"name": "esm-apps", "status": "enabled"}, {"name": "esm-infra", "status": "enabled"}]}`
	off := `{"attached": false, "services": [{"name": "esm-infra", "available": "yes"}]}`
	disabled := `{"attached": true, "services": [{"name": "esm-infra", "status": "disabled"}]}`
	if v := parseProESM(on); v == nil || !*v {
		t.Errorf("attached with esm-infra: %v", v)
	}
	if v := parseProESM(off); v == nil || *v {
		t.Errorf("not attached: %v", v)
	}
	if v := parseProESM(disabled); v == nil || *v {
		t.Errorf("esm-infra disabled: %v", v)
	}
	for _, s := range []string{"", "not json", `{"services": []}`} {
		if v := parseProESM(s); v != nil {
			t.Errorf("%q: want unknown, got %v", s, *v)
		}
	}
}

func TestParseListening(t *testing.T) {
	ss := []string{
		"Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process",
		`udp   UNCONN 0      0       127.0.0.53%lo:53         0.0.0.0:*     users:(("systemd-resolve",pid=612,fd=13))`,
		`tcp   LISTEN 0      4096          0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=801,fd=3))`,
		`tcp   LISTEN 0      511         127.0.0.1:3000        0.0.0.0:*`,
		`tcp   LISTEN 0      4096             [::]:22             [::]:*     users:(("sshd",pid=801,fd=4))`,
		`tcp   LISTEN 0      4096                *:2377              *:*     users:(("dockerd",pid=900,fd=30))`,
	}
	got := parseListening("ss", ss)
	if len(got) != 5 {
		t.Fatalf("got %d ports: %+v", len(got), got)
	}
	if got[0].Port != 22 || got[0].Process != "sshd" || got[0].PID != 801 || got[0].Address != "0.0.0.0" {
		t.Errorf("first: %+v", got[0])
	}
	if got[1].Address != "::" {
		t.Errorf("ipv6 any: %+v", got[1])
	}
	if got[2].Port != 53 || got[2].Proto != "udp" || got[2].Address != "127.0.0.53%lo" {
		t.Errorf("udp: %+v", got[2])
	}
	if got[3].Port != 2377 || got[3].Address != "*" || got[4].Process != "" {
		t.Errorf("rest: %+v", got[3:])
	}
	l := listenFacts{Ports: got}
	if s := portsText(l); !strings.Contains(s, "22 sshd") || !strings.Contains(s, "3000 (local only)") || strings.Count(s, "22 sshd") != 1 {
		t.Errorf("text: %s", s)
	}

	ns := []string{
		"Active Internet connections (only servers)",
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name",
		"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1200/nginx: master",
		"tcp6       0      0 :::22                   :::*                    LISTEN      -",
		"udp        0      0 0.0.0.0:68              0.0.0.0:*                           700/dhclient",
	}
	got = parseListening("netstat", ns)
	if len(got) != 3 || got[0].Port != 22 || got[0].Address != "::" || got[2].Process != "nginx" || got[2].PID != 1200 {
		t.Errorf("netstat: %+v", got)
	}
	if got[1].Port != 68 || got[1].Proto != "udp" || got[1].PID != 700 {
		t.Errorf("netstat udp: %+v", got[1])
	}

	proc := []string{
		"tcp    0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1",
		"tcp    1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2",
		"tcp    2: 0100007F:1F90 0100007F:D2F0 01 00000000:00000000 00:00000000 00000000  1000        0 3",
		"tcp6   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0",
		"tcp6   1: 00000000000000000000000001000000:0019 00000000000000000000000000000000:0000 0A 0",
	}
	got = parseListening("proc", proc)
	if len(got) != 4 {
		t.Fatalf("proc: %+v", got)
	}
	if got[0].Address != "0.0.0.0" || got[0].Port != 22 || got[1].Address != "::" || got[2].Address != "::1" || got[2].Port != 25 || got[3].Address != "127.0.0.1" || got[3].Port != 8080 {
		t.Errorf("proc: %+v", got)
	}
}

func TestPM2From(t *testing.T) {
	js := `[{"name":"api","status":"online","pid":1234,"restarts":2,"cpu_pct":1.5,"memory_mb":120,"mode":"fork_mode"},{"name":"DB_PASSWORD=hunter22","status":"stopped","pid":0,"restarts":0,"cpu_pct":0,"memory_mb":0}]`
	p := pm2From([]string{"deploy", "root"}, "deploy", true, &js, true)
	if len(p.Apps) != 2 || p.Apps[0].Name != "api" || p.Apps[0].Restarts != 2 || p.AppsOf != "deploy" {
		t.Fatalf("apps: %+v", p)
	}
	if strings.Contains(p.Apps[1].Name, "hunter22") {
		t.Errorf("app name not masked: %s", p.Apps[1].Name)
	}
	if len(p.OtherUsers) != 1 || p.OtherUsers[0] != "root" || p.Note == "" {
		t.Errorf("other users: %+v", p)
	}
	// a daemon of another user only: the apps are unknown, not "none"
	p = pm2From([]string{"root"}, "deploy", false, nil, false)
	if p.Apps != nil {
		t.Errorf("apps of another user's daemon must be unknown: %+v", p.Apps)
	}
	// no PM2 at all: no apps
	p = pm2From(nil, "deploy", false, nil, false)
	if p.Apps == nil || len(p.Apps) != 0 || p.DaemonUsers == nil {
		t.Errorf("no pm2: %+v", p)
	}
	// own daemon, jlist did not answer
	p = pm2From([]string{"deploy"}, "deploy", true, nil, true)
	if p.Apps != nil || p.Note == "" {
		t.Errorf("unreadable jlist: %+v", p)
	}
	// a long user name cut by ps is still the login user
	js = `[]`
	p = pm2From([]string{"deploymen+"}, "deploymentuser", true, &js, true)
	if p.Apps == nil || len(p.OtherUsers) != 0 {
		t.Errorf("cut name: %+v", p)
	}
}

func TestDockerFrom(t *testing.T) {
	if d := dockerFrom(nil, "", nil); d["installed"] != false || len(d) != 1 {
		t.Errorf("no docker: %v", d)
	}
	tools := []string{"docker"}
	for info, want := range map[string]string{
		"24.0.7|active|true|14":   "manager",
		"24.0.7|active|false|3":   "worker",
		"24.0.7|inactive|false|0": "none",
		"24.0.7|locked|false|0":   "locked",
	} {
		d := dockerFrom(tools, "24.0.7", &info)
		if d["swarm"] != want || d["daemon_reachable"] != true {
			t.Errorf("%s: %v", info, d)
		}
	}
	running := "24.0.7|active|true|14"
	if d := dockerFrom(tools, "24.0.7", &running); d["containers_running"] != 14 {
		t.Errorf("running: %v", d["containers_running"])
	}
	empty := ""
	d := dockerFrom(tools, "24.0.7", &empty)
	if d["swarm"] != "unknown" || d["containers_running"] != nil || d["daemon_reachable"] != false {
		t.Errorf("no access must be unknown: %v", d)
	}
}

// a recorded run on an Ubuntu 20.04 server without Ubuntu Pro
const factsFocal = `hostname=app3
os=ubuntu
os_version=20.04
os_pretty=Ubuntu 20.04.6 LTS
kernel=5.4.0-200-generic
arch=x86_64
cpus=4
mem_total_mb=7962
mem_available_mb=5120
load=0.12 0.10 0.05
uptime_sec=2937600
disk_root_total_gb=78
disk_root_used_pct=63
ips=10.0.0.13 172.17.0.1
init=systemd
virt=kvm
pkg_manager=apt
tool=docker
tool=pm2
tool=systemctl
failed_units=1
users_logged_in=0
time_utc=2026-11-05T12:00:00Z
now_epoch=1793880000
timezone=Etc/UTC
login_user=deploy
sudo_nopasswd=true
pro_json={"attached": false, "services": [{"name": "esm-infra", "available": "yes"}]}
reboot_required=true
reboot_pkg=linux-image-5.4.0-201-generic
needrestart_ok=true
restart_svc=nginx.service
docker_version=24.0.7
docker_info=24.0.7|active|true|14
pm2_daemon=deploy
pm2_mine=true
pm2_json=[{"name":"api","status":"online","pid":1234,"restarts":2,"cpu_pct":1.5,"memory_mb":120,"mode":"cluster_mode"}]
listen_names=all
listen_src=ss
listen=Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
listen=tcp   LISTEN 0      4096       0.0.0.0:22        0.0.0.0:*     users:(("sshd",pid=801,fd=3))
listen=tcp   LISTEN 0      511      127.0.0.1:3000      0.0.0.0:*     users:(("node",pid=1234,fd=20))
units_checked=true
unit=pm2-deploy.service	enabled	active
unit=backup.timer	enabled	active
apt_sim_ok=true
apt_sim=Inst libssl1.1 [1.1.1f-1ubuntu2.23] (1.1.1f-1ubuntu2.24 Ubuntu:20.04/focal-updates [amd64])
apt_lists_mtime=1792929600
`

func TestParseFactsUnsupportedUbuntu(t *testing.T) {
	f := parseFactsAt(factsFocal, factsNow)
	sup := f["os_support"].(osSupport)
	if sup.Status != "unsupported" || sup.ESMEnabled == nil || *sup.ESMEnabled {
		t.Errorf("support: %+v", sup)
	}
	u := f["updates"].(pendingUpdates)
	if u.Security != nil {
		t.Errorf("an unsupported OS must not report 0 security updates, got %d", *u.Security)
	}
	if u.Total == nil || *u.Total != 1 || u.IndexAgeDays == nil || *u.IndexAgeDays != 11 {
		t.Errorf("updates: %+v", u)
	}
	ws := f["warnings"].([]string)
	if len(ws) != 2 || !strings.Contains(ws[0], "no security updates") || !strings.Contains(ws[0], "2025-05-31") || !strings.Contains(ws[1], "11 days old") {
		t.Errorf("warnings: %q", ws)
	}
	if f["sudo_nopasswd"] != true || f["reboot_required"] != true {
		t.Errorf("sudo/reboot: %v %v", f["sudo_nopasswd"], f["reboot_required"])
	}
	if r := f["services_need_restart"].([]string); len(r) != 1 || r[0] != "nginx.service" {
		t.Errorf("restart: %v", r)
	}
	if d := f["docker"].(map[string]any); d["swarm"] != "manager" || d["containers_running"] != 14 {
		t.Errorf("docker: %v", d)
	}
	if p := f["pm2"].(pm2Facts); len(p.Apps) != 1 || p.Apps[0].Name != "api" {
		t.Errorf("pm2: %+v", p)
	}
	if us := f["custom_units"].([]customUnit); len(us) != 2 || us[0].Unit != "pm2-deploy.service" || us[0].Active != "active" {
		t.Errorf("units: %+v", us)
	}
	if l := f["listening"].(listenFacts); len(l.Ports) != 2 || l.ProcessNames != "all" {
		t.Errorf("listening: %+v", l)
	}
	for _, k := range []string{"apt_sim", "listen", "unit", "pm2_json", "pro_json", "docker_info", "reboot_pkg"} {
		if _, ok := f[k]; ok {
			t.Errorf("raw key %s leaked into facts", k)
		}
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"security":null`) {
		t.Errorf("security must be null in JSON: %s", b)
	}

	txt := factsText(probeData{Results: []probeRow{{Host: "app3", OK: true, Data: f}}})
	for _, want := range []string{"● app3  Ubuntu 20.04.6 LTS", "UNSUPPORTED", "1 pending, security unknown", "REBOOT REQUIRED",
		"restart needed: nginx.service", "sudo without password", "swarm manager · 14 running", "(deploy) api online",
		"22 sshd, 3000 node (local only)", "pm2-deploy.service (active)", "warning: Ubuntu 20.04.6 LTS: standard support ended 2025-05-31"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text misses %q:\n%s", want, txt)
		}
	}
}

func TestParseFactsUnknownValues(t *testing.T) {
	// a minimal server: no systemd, no package index readable, no sudo
	f := parseFactsAt("os=alpine\nos_version=3.22.1\npkg_manager=apk\nsudo_nopasswd=false\nlisten_src=proc\n", factsNow)
	if f["reboot_required"] != nil {
		t.Errorf("reboot_required must be unknown, got %v", f["reboot_required"])
	}
	u := f["updates"].(pendingUpdates)
	if u.Total != nil || u.Security != nil {
		t.Errorf("updates must be unknown: %+v", u)
	}
	if f["custom_units"] != nil || f["services_need_restart"] != nil {
		t.Errorf("units/restarts must be unknown: %v %v", f["custom_units"], f["services_need_restart"])
	}
	if l := f["listening"].(listenFacts); l.ProcessNames != "none" {
		t.Errorf("proc gives no names: %+v", l)
	}
	if f["os_support"].(osSupport).Status != "supported" {
		t.Errorf("support: %+v", f["os_support"])
	}
	// Ubuntu past standard support without a readable `pro`: unknown, and
	// still no 0 security updates
	f = parseFactsAt("os=ubuntu\nos_version=20.04\napt_sim_ok=true\n", factsNow)
	if f["os_support"].(osSupport).Status != "unknown" || f["updates"].(pendingUpdates).Security != nil {
		t.Errorf("ubuntu 20.04 without pro: %+v %+v", f["os_support"], f["updates"])
	}
	// a supported Ubuntu keeps its 0
	f = parseFactsAt("os=ubuntu\nos_version=24.04\npro_json={\"attached\": false}\napt_sim_ok=true\n", factsNow)
	if s := f["updates"].(pendingUpdates).Security; s == nil || *s != 0 || len(f["warnings"].([]string)) != 0 {
		t.Errorf("ubuntu 24.04: %+v %v", f["updates"], f["warnings"])
	}
}

func TestTestResultsCarryHost(t *testing.T) {
	b, _ := json.Marshal(targetTest{Host: "web1", Name: "web1", Kind: "host", OK: true})
	if !strings.Contains(string(b), `"host":"web1"`) || !strings.Contains(string(b), `"name":"web1"`) {
		t.Errorf("test result: %s", b)
	}
}
