package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// factsScript gathers everything in one round trip. It only reads: it
// never refreshes a package index, never starts a PM2 daemon, and uses sudo
// only as `sudo -n` when sudo already works without a password (it never
// asks for one). Lines are key=value; repeated keys are lists.
const factsScript = `export LC_ALL=C
echo "hostname=$(hostname 2>/dev/null)"
echo "kernel=$(uname -r)"; echo "arch=$(uname -m)"
echo "cpus=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)"
[ -r /proc/meminfo ] && awk '/^MemTotal/{print "mem_total_mb="int($2/1024)}/^MemAvailable/{print "mem_available_mb="int($2/1024)}/^SwapTotal/{print "swap_total_mb="int($2/1024)}/^SwapFree/{print "swap_free_mb="int($2/1024)}' /proc/meminfo
[ -r /proc/loadavg ] && echo "load=$(cut -d' ' -f1-3 /proc/loadavg)"
[ -r /proc/uptime ] && echo "uptime_sec=$(cut -d. -f1 /proc/uptime)"
df -P -k / 2>/dev/null | awk 'NR==2{print "disk_root_total_gb="int($2/1048576); print "disk_root_used_pct="int($5)}'
echo "ips=$(hostname -I 2>/dev/null || ip -o -4 addr show scope global 2>/dev/null | awk '{sub("/.*", "", $4); print $4}' | tr '\n' ' ')"
echo "init=$(cat /proc/1/comm 2>/dev/null || ps -p 1 -o comm= 2>/dev/null)"
v=$(systemd-detect-virt 2>/dev/null)
if [ -z "$v" ] || [ "$v" = none ]; then
  if [ -f /.dockerenv ] || grep -qa docker /proc/1/cgroup 2>/dev/null; then v=docker
  elif [ -f /run/.containerenv ]; then v=podman
  elif grep -qa -e lxc -e kubepods /proc/1/cgroup 2>/dev/null; then v=container
  fi
fi
echo "virt=${v:-unknown}"
pm=""
for m in apt-get dnf yum apk zypper pacman; do command -v $m >/dev/null 2>&1 && { pm=$m; echo "pkg_manager=${m%-get}"; break; }; done
for b in curl wget openssl docker podman kubectl k3s systemctl nginx apache2 httpd caddy haproxy mysql psql redis-cli mongosh node python3 java go git ufw firewall-cmd certbot pm2; do command -v $b >/dev/null 2>&1 && printf 'tool=%s\n' $b; done
echo "users_logged_in=$(who 2>/dev/null | wc -l)"
echo "time_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "now_epoch=$(date +%s)"
echo "timezone=$(cat /etc/timezone 2>/dev/null || date +%Z)"
T=""; T20=""; command -v timeout >/dev/null 2>&1 && { T="timeout 60"; T20="timeout 20"; }
echo "login_user=$(id -un 2>/dev/null)"
S=""
if [ "$(id -u 2>/dev/null)" = 0 ]; then echo "sudo_nopasswd=true"; root=1
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then echo "sudo_nopasswd=true"; S="sudo -n"; root=1
else echo "sudo_nopasswd=false"; root=""
fi
` + osShell + hostStateShell + `HS_ROOT=$root hoststate
if command -v docker >/dev/null 2>&1; then
  echo "docker_version=$(docker version --format '{{.Client.Version}}' 2>/dev/null)"
  f='{{.ServerVersion}}|{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}|{{.ContainersRunning}}'
  di=$($T20 docker info --format "$f" 2>/dev/null)
  [ -z "$di" ] && [ -n "$S" ] && di=$($T20 $S docker info --format "$f" 2>/dev/null)
  echo "docker_info=$di"
fi
ps -eo user=,args= 2>/dev/null | awk '$2 == "PM2" && $3 ~ /^v[0-9]/ {print "pm2_daemon=" $1}' | sort -u
(
  for d in "$HOME"/.nvm/versions/node/*/bin /usr/local/bin; do [ -d "$d" ] && PATH="$PATH:$d"; done
  [ -f "$HOME/.pm2/pm2.pid" ] && kill -0 "$(cat "$HOME/.pm2/pm2.pid" 2>/dev/null)" 2>/dev/null && echo "pm2_mine=true" &&
  if command -v pm2 >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    echo "pm2_json=$($T20 pm2 jlist 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const i=s.search(/^\[/m);const l=JSON.parse(i<0?s:s.slice(i));console.log(JSON.stringify(l.map(p=>{const e=p.pm2_env||{},m=p.monit||{};return{name:p.name,status:e.status,pid:p.pid,restarts:e.restart_time,cpu_pct:m.cpu,memory_mb:Math.round((m.memory||0)/1048576),mode:e.exec_mode}})))}catch(x){}})' 2>/dev/null)"
  fi
)
[ -n "$S" ] || [ -n "$root" ] && echo "listen_names=all" || echo "listen_names=own"
if command -v ss >/dev/null 2>&1; then echo "listen_src=ss"; $S ss -ltnup 2>/dev/null | sed 's/^/listen=/'
elif command -v netstat >/dev/null 2>&1; then echo "listen_src=netstat"; $S netstat -ltnup 2>/dev/null | sed 's/^/listen=/'
else echo "listen_src=proc"; for p in tcp tcp6; do [ -r /proc/net/$p ] && sed "1d;s/^/listen=$p /" /proc/net/$p; done
fi
if [ -d /run/systemd/system ]; then
  echo "units_checked=true"
  for u in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
    [ -f "$u" ] || [ -L "$u" ] || continue
    n=${u##*/}
    case $n in snap.*|snap-*) continue;; esac
    if [ -L "$u" ]; then case $(readlink -f "$u") in /lib/*|/usr/lib/*|/dev/null|"") continue;; esac; fi
    printf 'unit=%s\t%s\t%s\n' "$n" "$(systemctl is-enabled "$n" 2>/dev/null)" "$(systemctl is-active "$n" 2>/dev/null)"
  done
fi
case $pm in
apt-get)
  o=$($T ` + aptSimCommand + ` 2>/dev/null) && echo "apt_sim_ok=true"
  printf '%s\n' "$o" | grep '^Inst ' | cut -c1-300 | sed 's/^/apt_sim=/'
  echo "apt_lists_mtime=$(stat -c %Y /var/lib/apt/lists/*Release 2>/dev/null | sort -n | tail -1)";;
dnf|yum)
  o=$($T $pm -q -C check-update 2>/dev/null); echo "upd_rc=$?"; printf '%s\n' "$o" | sed 's/^/upd=/'
  if [ $pm = dnf ]; then o=$($T dnf -q -C updateinfo list --security 2>/dev/null); else o=$($T yum -q -C updateinfo list security 2>/dev/null); fi
  echo "sec_rc=$?"; printf '%s\n' "$o" | sed 's/^/sec=/';;
esac
true
`

// pm2App is one PM2 app: its name and state, never its command line or
// environment (they can hold passwords).
type pm2App struct {
	Name     string  `json:"name"`
	Status   string  `json:"status"`
	PID      int     `json:"pid,omitempty"`
	Restarts int     `json:"restarts"`
	CPUPct   float64 `json:"cpu_pct"`
	MemoryMB int     `json:"memory_mb"`
	Mode     string  `json:"mode,omitempty"`
}

type pm2Facts struct {
	DaemonUsers []string `json:"daemon_users"`          // users with a running PM2 daemon
	AppsOf      string   `json:"apps_of,omitempty"`     // whose apps "apps" lists: the login user
	Apps        []pm2App `json:"apps"`                  // null: komando could not read them
	Note        string   `json:"note,omitempty"`        // why apps is null
	Installed   bool     `json:"pm2_in_path"`           // pm2 is on the login user's PATH
	OtherUsers  []string `json:"other_users,omitempty"` // daemon users whose apps are not listed
}

type listenPort struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"` // the program name, when visible
	PID     int    `json:"pid,omitempty"`
}

type listenFacts struct {
	Source string `json:"source"` // ss, netstat or proc
	// all: process names of every user; own: only the login user's
	// processes have names (no root, no passwordless sudo); none: /proc
	// gives no names
	ProcessNames string       `json:"process_names"`
	Ports        []listenPort `json:"ports"`
}

type customUnit struct {
	Unit    string `json:"unit"`
	Enabled string `json:"enabled"` // enabled, disabled, static ... ("" unknown)
	Active  string `json:"active"`  // active, inactive, failed ...
}

type pendingUpdates struct {
	Total    *int   `json:"total"`
	Security *int   `json:"security"`
	Source   string `json:"source,omitempty"`
	// how old the package index is: counts come from it as it is, komando
	// does not refresh it
	IndexAgeDays *int `json:"index_age_days,omitempty"`
}

// staleIndexDays is when an old package index earns a warning.
const staleIndexDays = 7

func parseFacts(h *store.Host, s string) (any, error) {
	if h.Windows() {
		return parseWinFacts(s, time.Now()), nil
	}
	return parseFactsAt(s, time.Now()), nil
}

// parseFactsAt turns the script's output into facts, judging OS support on
// day now.
func parseFactsAt(s string, now time.Time) map[string]any {
	f := map[string]any{}
	tools := []string{}
	var (
		aptSim, upd, sec, listenLines, daemons []string
		hs                                     hostState
		units                                  []customUnit
		pm2JSON, proJSON, dockerInfo           *string
	)
	set := map[string]string{} // raw values of the keys read below
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		raw := strings.TrimRight(v, "\r")
		v = strings.TrimSpace(v)
		if hs.line(k, v) {
			continue
		}
		switch k {
		case "tool":
			tools = append(tools, v)
		case "apt_sim":
			aptSim = append(aptSim, raw)
		case "upd":
			upd = append(upd, raw)
		case "sec":
			sec = append(sec, raw)
		case "listen":
			listenLines = append(listenLines, raw)
		case "pm2_daemon":
			daemons = append(daemons, v)
		case "unit":
			p := strings.Split(raw, "\t")
			for len(p) < 3 {
				p = append(p, "")
			}
			units = append(units, customUnit{Unit: p[0], Enabled: strings.TrimSpace(p[1]), Active: strings.TrimSpace(p[2])})
		case "pm2_json":
			pm2JSON = &v
		case "pro_json":
			proJSON = &v
		case "docker_info":
			dockerInfo = &v
		case "apt_sim_ok", "apt_lists_mtime", "upd_rc", "sec_rc", "listen_src", "listen_names",
			"units_checked", "now_epoch", "docker_version", "login_user", "pm2_mine":
			set[k] = v
		case "os_version", "hostname", "kernel":
			f[k] = v
		case "ips":
			f[k] = strings.Fields(v)
		case "load":
			var l []float64
			for _, x := range strings.Fields(v) {
				n, _ := strconv.ParseFloat(x, 64)
				l = append(l, n)
			}
			f[k] = l
		default:
			if v == "true" || v == "false" {
				f[k] = v == "true"
			} else if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				f[k] = n
			} else {
				f[k] = v
			}
		}
	}
	sort.Strings(tools)
	f["tools"] = tools
	hostStateFacts(f, hs)
	if _, ok := f["sudo_nopasswd"]; !ok {
		f["sudo_nopasswd"] = nil
	}
	f["login_user"] = set["login_user"]

	str := func(k string) string { x, _ := f[k].(string); return x }
	osID, osVer, pretty := str("os"), str("os_version"), str("os_pretty")
	sup := osSupportFrom(osID, osVer, pretty, proJSON, now)
	f["os_support"] = sup

	updates := pendingFrom(set, aptSim, upd, sec, str("pkg_manager"))
	var warnings []string
	if w, unknown := supportWarning(osName(osID, osVer, pretty), sup, now); w != "" {
		if unknown {
			w += "; security updates are shown as unknown because 0 would look safe"
			updates.Security = nil
		}
		warnings = append(warnings, w)
	}
	if updates.IndexAgeDays != nil && *updates.IndexAgeDays > staleIndexDays {
		warnings = append(warnings, fmt.Sprintf("the package index is %d days old, so the update counts may be too low; refresh it with `komando pkg update TARGET` (a change)", *updates.IndexAgeDays))
	}
	f["updates"] = updates
	f["docker"] = dockerFrom(tools, set["docker_version"], dockerInfo)
	f["pm2"] = pm2From(daemons, set["login_user"], set["pm2_mine"] == "true", pm2JSON, slices.Contains(tools, "pm2"))
	f["listening"] = listenFacts{Source: set["listen_src"], ProcessNames: listenNames(set), Ports: parseListening(set["listen_src"], listenLines)}
	if set["units_checked"] == "true" {
		f["custom_units"] = nonNil(units)
	} else {
		f["custom_units"] = nil
	}
	f["warnings"] = nonNil(warnings)
	return f
}

// hostStateFacts puts what hoststate printed into the facts, in the keys
// facts has always had.
func hostStateFacts(f map[string]any, hs hostState) {
	f["reboot_required"] = nil // not a Debian-family server and no needs-restarting
	if hs.Reboot != nil {
		f["reboot_required"] = *hs.Reboot
		if *hs.Reboot {
			f["reboot_packages"] = nonNil(hs.RebootPackages)
		}
	}
	f["services_need_restart"] = nil // nothing to check with, or no root to run it
	if hs.RestartChecked {
		f["services_need_restart"] = nonNil(hs.NeedRestart)
	}
	if hs.FailedChecked {
		f["failed_units"] = int64(len(hs.Failed))
	}
}

func listenNames(set map[string]string) string {
	if set["listen_src"] == "proc" {
		return "none"
	}
	if set["listen_names"] == "" {
		return "own"
	}
	return set["listen_names"]
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// pendingFrom builds the pending update counts; a count komando could not
// read stays nil (unknown), never 0.
func pendingFrom(set map[string]string, aptSim, upd, sec []string, pm string) pendingUpdates {
	var u pendingUpdates
	switch {
	case set["apt_sim_ok"] == "true":
		t, s := aptSimCounts(strings.Join(aptSim, "\n"))
		u.Total, u.Security, u.Source = &t, &s, "apt (package index on the server, not refreshed)"
		mt, err1 := strconv.ParseInt(set["apt_lists_mtime"], 10, 64)
		nw, err2 := strconv.ParseInt(set["now_epoch"], 10, 64)
		if err1 == nil && err2 == nil && nw >= mt {
			d := int((nw - mt) / 86400)
			u.IndexAgeDays = &d
		}
	case set["upd_rc"] == "0" || set["upd_rc"] == "100":
		t := dnfCheckUpdateCount(strings.Join(upd, "\n"))
		u.Total, u.Source = &t, pm+" (cached metadata, not refreshed)"
		if set["sec_rc"] == "0" {
			s := dnfSecurityCount(strings.Join(sec, "\n"))
			u.Security = &s
		}
	}
	return u
}

// parseProESM reads `pro status --format json`: whether esm-infra is
// enabled. nil when the output is not readable.
func parseProESM(s string) *bool {
	var p struct {
		Attached *bool `json:"attached"`
		Services []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"services"`
	}
	if s == "" || json.Unmarshal([]byte(s), &p) != nil || p.Attached == nil {
		return nil
	}
	on := false
	if *p.Attached {
		for _, sv := range p.Services {
			if sv.Name == "esm-infra" && sv.Status == "enabled" {
				on = true
			}
		}
	}
	return &on
}

// dockerFrom reads `docker info --format` output:
// version|LocalNodeState|ControlAvailable|ContainersRunning.
func dockerFrom(tools []string, version string, info *string) map[string]any {
	if !slices.Contains(tools, "docker") {
		return map[string]any{"installed": false}
	}
	d := map[string]any{"installed": true, "version": version, "daemon_reachable": false,
		"server_version": nil, "swarm": "unknown", "containers_running": nil}
	if version == "" {
		d["version"] = nil
	}
	if info == nil || *info == "" {
		d["note"] = "the login user may not talk to the Docker daemon (not in the docker group, no passwordless sudo), or the daemon is down"
		return d
	}
	p := strings.Split(*info, "|")
	if len(p) < 4 {
		return d
	}
	d["daemon_reachable"] = true
	d["server_version"] = p[0]
	switch p[1] {
	case "active":
		if p[2] == "true" {
			d["swarm"] = "manager"
		} else {
			d["swarm"] = "worker"
		}
	case "inactive", "":
		d["swarm"] = "none"
	default:
		d["swarm"] = p[1] // pending, error, locked
	}
	if n, err := strconv.Atoi(strings.TrimSpace(p[3])); err == nil {
		d["containers_running"] = n
	}
	return d
}

// pm2From lists the PM2 daemons and the login user's apps. App names go
// through secret masking (a name is the only free text kept).
//
// mine says the login user's own daemon runs (from its pid file: ps may
// cut a long user name to "longuse+").
func pm2From(daemons []string, login string, mine bool, js *string, inPath bool) pm2Facts {
	p := pm2Facts{DaemonUsers: nonNil(daemons), Installed: inPath}
	for _, u := range daemons {
		cut := strings.HasSuffix(u, "+") && strings.HasPrefix(login, strings.TrimSuffix(u, "+"))
		if u != login && !cut {
			p.OtherUsers = append(p.OtherUsers, u)
		}
	}
	if len(p.OtherUsers) > 0 {
		p.Note = "apps of other users' PM2 daemons are not listed; read them as that user"
	}
	switch {
	case len(daemons) == 0 && !mine:
		p.Apps = []pm2App{}
	case !mine:
		// apps stays nil: only other users run a daemon
	case js == nil || *js == "":
		p.AppsOf, p.Note = login, "pm2 jlist did not answer (pm2 or node not on the PATH of a non-interactive login)"
	default:
		var apps []pm2App
		if json.Unmarshal([]byte(*js), &apps) != nil {
			p.AppsOf, p.Note = login, "could not read pm2 jlist"
			break
		}
		for i := range apps {
			apps[i].Name = out.MaskSecrets(apps[i].Name)
		}
		p.AppsOf, p.Apps = login, nonNil(apps)
	}
	return p
}

var ssUsers = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)

// parseListening reads `ss -ltnup`, `netstat -ltnup` or /proc/net/tcp*
// lines into listening ports, sorted by port.
func parseListening(src string, lines []string) []listenPort {
	ports := []listenPort{}
	seen := map[string]bool{}
	add := func(p listenPort) {
		k := fmt.Sprintf("%s|%s|%d|%s", p.Proto, p.Address, p.Port, p.Process)
		if p.Port > 0 && !seen[k] {
			seen[k] = true
			ports = append(ports, p)
		}
	}
	for _, line := range lines {
		f := strings.Fields(line)
		switch src {
		case "ss":
			if len(f) < 5 || f[0] == "Netid" {
				continue
			}
			addr, port := splitHostPort(f[4])
			p := listenPort{Proto: f[0], Address: addr, Port: port}
			if m := ssUsers.FindStringSubmatch(line); m != nil {
				p.Process = m[1]
				p.PID, _ = strconv.Atoi(m[2])
			}
			add(p)
		case "netstat":
			if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") && !strings.HasPrefix(f[0], "udp") {
				continue
			}
			addr, port := splitHostPort(f[3])
			p := listenPort{Proto: strings.TrimSuffix(f[0], "6"), Address: addr, Port: port}
			i := 5 // udp has no State column
			if f[5] == "LISTEN" {
				i = 6
			}
			if i < len(f) && strings.Contains(f[i], "/") {
				id, name, _ := strings.Cut(f[i], "/")
				p.PID, _ = strconv.Atoi(id)
				p.Process = strings.TrimSuffix(name, ":") // "1200/nginx: master"
			}
			add(p)
		case "proc":
			// "tcp 0: 0100007F:0035 00000000:0000 0A ..."
			if len(f) < 5 || f[4] != "0A" {
				continue
			}
			h, pt, ok := strings.Cut(f[2], ":")
			if !ok {
				continue
			}
			port, err := strconv.ParseInt(pt, 16, 32)
			if err != nil {
				continue
			}
			add(listenPort{Proto: "tcp", Address: procAddr(h), Port: int(port)})
		}
	}
	sort.SliceStable(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		return ports[i].Proto < ports[j].Proto
	})
	return ports
}

// splitHostPort splits "0.0.0.0:22", "[::]:22", "*:22", ":::22" and
// "127.0.0.53%lo:53" at the last colon.
func splitHostPort(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0
	}
	port, _ := strconv.Atoi(s[i+1:])
	h := strings.TrimSuffix(strings.TrimPrefix(s[:i], "["), "]")
	if h == "" {
		h = "*"
	}
	return h, port
}

// procAddr turns a /proc/net/tcp address (little-endian hex words) into
// text.
func procAddr(h string) string {
	b := make([]byte, 0, 16)
	for i := 0; i+8 <= len(h); i += 8 {
		w, err := strconv.ParseUint(h[i:i+8], 16, 32)
		if err != nil {
			return h
		}
		b = append(b, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	switch len(b) {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	case 16:
		var sb strings.Builder
		for i := 0; i < 16; i += 2 {
			if i > 0 {
				sb.WriteByte(':')
			}
			fmt.Fprintf(&sb, "%x", uint16(b[i])<<8|uint16(b[i+1]))
		}
		return compactIPv6(sb.String())
	}
	return h
}

// compactIPv6 shortens "0:0:0:0:0:0:0:0" to "::" and "0:0:0:0:0:0:0:1"
// to "::1" (the addresses a listener usually has).
func compactIPv6(s string) string {
	switch s {
	case "0:0:0:0:0:0:0:0":
		return "::"
	case "0:0:0:0:0:0:0:1":
		return "::1"
	}
	return s
}

func factsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "facts TARGET",
		Aliases: []string{"info", "inspect"},
		Short:   "System facts: OS and support, updates, Docker, open ports",
		Long: `Run this first on a server you do not know yet: it tells an agent which
package manager, init system and tools exist, so later commands fit the server.

It also reports what needs attention: whether the OS still gets security
updates (Ubuntu ESM, Debian LTS, end of life), pending and security updates
(from the server's package index, which it does not refresh), a needed
reboot, passwordless sudo, Docker and the Swarm role, PM2 apps, listening
ports and services added by hand under /etc/systemd/system.

On Windows servers it reports the Windows version and its support dates,
pending updates from the Windows Update cache, a pending reboot, stopped
automatic services and listening ports.

It only reads, and it uses sudo only when sudo works without a password.
A value komando cannot read is null ("unknown"), never 0 or false; read
data.results[].data.warnings first.`,
		Example: "  komando facts web1\n  komando facts @prod -o json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probeText(cmd.Context(), "facts", args[0], factsScript, false, parseFacts, factsText)
		},
	}
}
