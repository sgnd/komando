package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// windowsProbes are the probes (probeText) that work on Windows servers,
// with the PowerShell they run there.
var windowsProbes = map[string]string{"facts": winFactsScript}

// winFactsScript is `komando facts` on Windows: key=value lines, like
// factsScript. It only reads. Pending updates come from the Windows Update
// cache on the server (Online = false): it does not search for new ones.
const winFactsScript = `$ErrorActionPreference = 'SilentlyContinue'
function kv($k, $v) { [Console]::Out.WriteLine("$k=$v") }
$o = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
kv os windows
kv hostname $env:COMPUTERNAME
kv os_pretty $o.Caption
kv os_version $o.Version
kv os_build $o.BuildNumber
kv arch $env:PROCESSOR_ARCHITECTURE
kv cpus $cs.NumberOfLogicalProcessors
kv mem_total_mb ([int64]($cs.TotalPhysicalMemory / 1MB))
kv mem_available_mb ([int64]($o.FreePhysicalMemory / 1KB))
kv uptime_sec ([int64]((Get-Date) - $o.LastBootUpTime).TotalSeconds)
$d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
if ($d.Size) { kv disk_root_total_gb ([int64]($d.Size / 1GB)); kv disk_root_used_pct ([int64](100 - 100 * $d.FreeSpace / $d.Size)) }
kv ips ((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $_.IPAddress } | Where-Object { $_ -notmatch ':' }) -join ' ')
kv virt $cs.Model
kv domain $cs.Domain
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
kv login_user $id.Name
kv admin ((New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
kv powershell $PSVersionTable.PSVersion
kv time_utc ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
kv timezone ([TimeZoneInfo]::Local.Id)
kv reboot_required ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'))
$h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($h) { kv last_update ($h.InstalledOn.ToString('yyyy-MM-dd')); kv last_update_id $h.HotFixID }
try {
  $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
  $s.Online = $false
  $r = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $n = 0
  foreach ($u in $r.Updates) { foreach ($c in $u.Categories) { if ($c.Name -eq 'Security Updates') { $n++; break } } }
  kv upd_total $r.Updates.Count
  kv upd_security $n
} catch { kv upd_error ($_.Exception.Message -replace '\s+', ' ') }
foreach ($t in 'docker', 'git', 'choco', 'winget', 'python', 'node', 'java', 'sqlcmd', 'nginx', 'kubectl', 'openssl', 'curl.exe') {
  if (Get-Command $t -ErrorAction SilentlyContinue) { kv tool ($t -replace '\.exe$', '') }
}
if (Get-Service W3SVC -ErrorAction SilentlyContinue) { kv tool iis }
Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" | ForEach-Object { kv stopped_auto $_.Name }
$names = @{}
Get-Process | ForEach-Object { $names[$_.Id] = $_.ProcessName }
Get-NetTCPConnection -State Listen | ForEach-Object { kv listen ("tcp {0} {1} {2} {3}" -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess, $names[[int]$_.OwningProcess]) }
Get-NetUDPEndpoint | ForEach-Object { kv listen ("udp {0} {1} {2} {3}" -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess, $names[[int]$_.OwningProcess]) }
kv done 1
`

// parseWinFacts turns winFactsScript's output into facts.
func parseWinFacts(s string, now time.Time) map[string]any {
	f := map[string]any{"os": "windows"}
	set := map[string]string{}
	tools, stopped := []string{}, []string{}
	var ports []listenPort
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "tool":
			tools = append(tools, v)
		case "stopped_auto":
			stopped = append(stopped, v)
		case "listen":
			if p, ok := winListen(v); ok {
				ports = append(ports, p)
			}
		case "ips":
			f[k] = strings.Fields(v)
		case "admin", "reboot_required":
			f[k] = strings.EqualFold(v, "true")
		case "cpus", "mem_total_mb", "mem_available_mb", "uptime_sec", "disk_root_total_gb", "disk_root_used_pct":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				f[k] = n
			}
		case "hostname", "os_pretty", "os_version", "os_build", "arch", "virt", "domain", "login_user", "powershell", "time_utc", "timezone":
			f[k] = v
		default:
			set[k] = v
		}
	}
	sort.Strings(tools)
	f["tools"], f["services_stopped"] = tools, stopped
	if _, ok := f["reboot_required"]; !ok {
		f["reboot_required"] = nil
	}
	if set["last_update"] != "" {
		f["last_update"] = map[string]string{"installed": set["last_update"], "id": set["last_update_id"]}
	}
	var warnings []string
	u := pendingUpdates{}
	if t, err := strconv.Atoi(set["upd_total"]); err == nil {
		sec, _ := strconv.Atoi(set["upd_security"])
		u.Total, u.Security, u.Source = &t, &sec, "Windows Update (the server's cache, not searched again)"
	} else {
		warnings = append(warnings, "pending updates unknown: Windows Update could not be read ("+dash(set["upd_error"])+"); Windows refuses its update search to many remote logins")
	}
	f["updates"] = u
	f["listening"] = listenFacts{Source: "Get-NetTCPConnection", ProcessNames: "all", Ports: nonNil(ports)}
	pretty, _ := f["os_pretty"].(string)
	build, _ := f["os_build"].(string)
	sup := osSupport{Status: "unknown", TableChecked: osTableChecked}
	if strings.Contains(pretty, "Server") {
		sup = supportOf("windows-server", build, pretty, nil, now)
	}
	f["os_support"] = sup
	if w, _ := supportWarning(osName("windows", build, pretty), sup, now); w != "" {
		warnings = append(warnings, strings.Replace(w, " and Ubuntu Pro (ESM) is not enabled", "", 1))
	}
	f["warnings"] = nonNil(warnings)
	return f
}

// winListen reads one "PROTO ADDRESS PORT PID NAME" line.
func winListen(v string) (listenPort, bool) {
	p := strings.Fields(v)
	if len(p) < 4 {
		return listenPort{}, false
	}
	port, err := strconv.Atoi(p[2])
	if err != nil {
		return listenPort{}, false
	}
	lp := listenPort{Proto: p[0], Address: p[1], Port: port}
	lp.PID, _ = strconv.Atoi(p[3])
	if len(p) > 4 {
		lp.Process = p[4]
	}
	return lp, true
}

// writeWinFactsHost is the text view of one Windows server's facts.
func writeWinFactsHost(b *strings.Builder, host string, f map[string]any) {
	str := func(k string) string { s, _ := f[k].(string); return s }
	num := func(k string) (int64, bool) { n, ok := f[k].(int64); return n, ok }
	head := []string{dash(str("os_pretty"))}
	if v := str("os_build"); v != "" {
		head = append(head, "build "+v)
	}
	if n, ok := num("cpus"); ok {
		head = append(head, fmt.Sprintf("%d cpu", n))
	}
	if n, ok := num("mem_total_mb"); ok {
		head = append(head, fmt.Sprintf("%.1f GB RAM", float64(n)/1024))
	}
	if n, ok := num("disk_root_used_pct"); ok {
		head = append(head, fmt.Sprintf("disk C: %d%%", n))
	}
	if n, ok := num("uptime_sec"); ok {
		head = append(head, "up "+humanAge(time.Duration(n)*time.Second))
	}
	fmt.Fprintf(b, "● %s  %s\n", host, strings.Join(head, " · "))
	line := func(label, v string) {
		if v != "" {
			fmt.Fprintf(b, "  %-10s %s\n", label+":", v)
		}
	}
	if s, ok := f["os_support"].(osSupport); ok {
		line("support", supportText(s))
	}
	var up []string
	if u, ok := f["updates"].(pendingUpdates); ok {
		up = append(up, countText(u.Total, "pending")+", "+countText(u.Security, "security"))
	}
	if lu, ok := f["last_update"].(map[string]string); ok {
		up = append(up, "last installed "+lu["installed"])
	}
	if r, ok := f["reboot_required"].(bool); ok && r {
		up = append(up, "REBOOT REQUIRED")
	}
	line("updates", strings.Join(up, " · "))
	acc := []string{"user " + dash(str("login_user"))}
	if a, ok := f["admin"].(bool); ok {
		acc = append(acc, map[bool]string{true: "administrator", false: "not an administrator"}[a])
	}
	line("access", strings.Join(acc, " · "))
	if s, ok := f["services_stopped"].([]string); ok && len(s) > 0 {
		line("stopped", shortList(s, 8)+" (start: automatic)")
	}
	if l, ok := f["listening"].(listenFacts); ok {
		line("ports", portsText(l))
	}
	if ws, ok := f["warnings"].([]string); ok {
		for _, w := range ws {
			fmt.Fprintf(b, "  warning: %s\n", w)
		}
	}
}
