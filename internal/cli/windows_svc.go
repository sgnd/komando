package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// `komando svc` on Windows servers: Windows services, through the Service
// Control Manager (Get-Service, Start-Service, Win32_Service).

// winService is one Windows service as svc shows it.
type winService struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state,omitempty"`      // Running, Stopped, Start Pending ...
	StartMode   string `json:"start_mode,omitempty"` // Auto, Manual, Disabled
	Delayed     bool   `json:"delayed_start,omitempty"`
	PID         int    `json:"pid,omitempty"`
	Account     string `json:"account,omitempty"`
	ExitCode    int    `json:"exit_code,omitempty"`
	Found       bool   `json:"found"`
}

// winServiceName is a name Windows gives services; it stays out of
// wildcards (Get-Service reads * ? [ ]) and WQL quoting (' and \).
var winServiceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.$#@+-]{0,255}$`)

// winServiceRow is the PowerShell that turns a Win32_Service ($s) into
// the JSON of winService.
const winServiceRow = `[pscustomobject]@{ name = $s.Name; display_name = $s.DisplayName; state = $s.State; start_mode = $s.StartMode; delayed_start = [bool]$s.DelayedAutoStart; pid = [int]$s.ProcessId; account = $s.StartName; exit_code = [int]$s.ExitCode; found = $true }`

// winSvcStatusScript prints the services' state as one marker line.
func winSvcStatusScript(names []string) string {
	return `$rows = foreach ($n in ` + sshx.PSArray(names) + `) {
  $s = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $n + "'")
  if (-not $s) { $s = Get-CimInstance -ClassName Win32_Service -Filter ("DisplayName='" + $n + "'") }
  if ($s) { ` + winServiceRow + ` } else { [pscustomobject]@{ name = $n; found = $false } }
}
[Console]::Out.WriteLine('#komando:json=' + (ConvertTo-Json -Compress -InputObject @($rows)))
`
}

// badServiceNames is a script that stops on names no service has, or "".
func badServiceNames(names []string) string {
	for _, n := range names {
		if !winServiceName.MatchString(n) {
			return "[Console]::Error.WriteLine(" + sshx.PSQ("komando: "+n+" is not a Windows service name (letters, digits, space and _ . $ # @ + -)") + "); exit 2\n"
		}
	}
	return ""
}

// winSvcActions are the PowerShell lines of each svc action, per service.
var winSvcActions = map[string][]string{
	"start":   {"Start-Service -Name %s"},
	"stop":    {"Stop-Service -Name %s"},
	"restart": {"Restart-Service -Name %s"},
	"enable":  {"Set-Service -Name %s -StartupType Automatic"},
	"disable": {"Set-Service -Name %s -StartupType Disabled"},
}

// winSvcScript is svcScript for Windows: run the action on each service,
// wait for them to run (--wait), then show their state.
func winSvcScript(action string, names []string, now bool, wait int) string {
	steps, ok := winSvcActions[action]
	if !ok {
		return ""
	}
	if bad := badServiceNames(names); bad != "" {
		return bad
	}
	if now && action == "enable" {
		steps = append(steps, "Start-Service -Name %s")
	} else if now && action == "disable" {
		steps = append(steps, "Stop-Service -Name %s")
	}
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n$rc = 0\n")
	for _, n := range names {
		for _, st := range steps {
			fmt.Fprintf(&b, "try { %s } catch { $rc = 1; [Console]::Error.WriteLine(%s + $_.Exception.Message) }\n", fmt.Sprintf(st, sshx.PSQ(n)), sshx.PSQ(n+": "))
		}
		if wait > 0 && (action == "start" || action == "restart") {
			fmt.Fprintf(&b, "try { (Get-Service -Name %s).WaitForStatus('Running', [TimeSpan]::FromSeconds(%d)) } catch {}\n", sshx.PSQ(n), wait)
		}
	}
	b.WriteString("$ErrorActionPreference = 'Continue'\n")
	b.WriteString(winSvcStatusScript(names))
	b.WriteString("[Console]::Out.WriteLine(\"#komando:rc=$rc\")\n")
	return b.String()
}

// winMarkers reads the "#komando:KEY=VALUE" lines of a script's stdout.
func winMarkers(stdout string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(stdout, "\n") {
		if kv, ok := strings.CutPrefix(strings.TrimSpace(l), "#komando:"); ok {
			k, v, _ := strings.Cut(kv, "=")
			m[k] = v
		}
	}
	return m
}

// winServices reads the services from the json marker; missing names
// fail the host with UNIT_NOT_FOUND.
func winServices(rr *sshx.RunResult) ([]winService, *out.Error) {
	var svcs []winService
	js := winMarkers(rr.Stdout)["json"]
	if js == "" || json.Unmarshal([]byte(js), &svcs) != nil {
		return nil, out.Errf(out.ExitRemote, "COMMAND_FAILED", "read stderr for the reason", "PowerShell gave no service list (exit code %d)", rr.ExitCode)
	}
	var missing []string
	for _, s := range svcs {
		if !s.Found {
			missing = append(missing, s.Name)
		}
	}
	if len(missing) > 0 {
		return svcs, out.Errf(out.ExitNotFound, "UNIT_NOT_FOUND", "check the name with `komando svc list TARGET`",
			"service not found: %s", strings.Join(missing, ", "))
	}
	return svcs, nil
}

// winSvcActionResult is svcActionResult for Windows.
func winSvcActionResult(action string, wait int, rr *sshx.RunResult) (any, *out.Error) {
	svcs, err := winServices(rr)
	if err != nil {
		return svcs, err
	}
	if winMarkers(rr.Stdout)["rc"] != "0" {
		return svcs, out.Errf(out.ExitRemote, "SVC_FAILED", "the reason is in stderr; the service's own log is in the Windows event log: `komando exec TARGET --read-only -- Get-WinEvent -LogName System -MaxEvents 20`",
			"%s failed", commandWord("svc."+action))
	}
	if wait > 0 {
		var down []string
		for _, s := range svcs {
			if s.State != "Running" {
				down = append(down, s.Name+" is "+s.State)
			}
		}
		if len(down) > 0 {
			return svcs, out.Errf(out.ExitRemote, "UNIT_NOT_ACTIVE", "read why in the event log: `komando exec TARGET --read-only -- Get-WinEvent -LogName System -MaxEvents 20`",
				"not running after %ds: %s", wait, strings.Join(down, ", "))
		}
	}
	return svcs, nil
}

// winSvcTable is svcTable for Windows services.
func winSvcTable(svcs []winService) string {
	rows := [][]string{}
	for _, s := range svcs {
		start := s.StartMode
		if s.Delayed {
			start += " (delayed)"
		}
		pid := ""
		if s.PID > 0 {
			pid = fmt.Sprint(s.PID)
		}
		rows = append(rows, []string{s.Name, s.State, start, pid, s.Account, s.DisplayName})
	}
	return textTable([]string{"service", "state", "start", "pid", "account", "name"}, rows)
}

// winSvcListScript lists every service.
const winSvcListScript = `$rows = foreach ($s in Get-CimInstance -ClassName Win32_Service) { ` + winServiceRow + ` }
[Console]::Out.WriteLine('#komando:json=' + (ConvertTo-Json -Compress -InputObject @($rows)))
`

// winSvcList filters the list by --state: running, stopped, or failed
// (set to start automatically, stopped with an error code).
func winSvcList(state string) func(*store.Host, *sshx.RunResult) (any, *out.Error) {
	return func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) {
		var svcs []winService
		if err := json.Unmarshal([]byte(winMarkers(rr.Stdout)["json"]), &svcs); err != nil {
			return nil, out.Errf(out.ExitRemote, "COMMAND_FAILED", "read stderr for the reason", "PowerShell gave no service list (exit code %d)", rr.ExitCode)
		}
		keep := []winService{}
		for _, s := range svcs {
			ok := true
			switch strings.ToLower(state) {
			case "running", "active":
				ok = s.State == "Running"
			case "stopped", "inactive", "dead":
				ok = s.State == "Stopped"
			case "failed":
				ok = s.StartMode == "Auto" && s.State == "Stopped" && s.ExitCode != 0
			}
			if ok {
				keep = append(keep, s)
			}
		}
		sort.SliceStable(keep, func(i, j int) bool { return strings.ToLower(keep[i].Name) < strings.ToLower(keep[j].Name) })
		return keep, nil
	}
}
