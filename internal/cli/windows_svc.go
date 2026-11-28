package cli

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Windows services for the svc snippets, through the Service
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

// winSvcStatusText is winSvcStatusScript over an array already written in
// PowerShell: the svc-status snippet gives its filled list.
func winSvcStatusText(array string) string {
	return `$rows = foreach ($n in ` + array + `) {
  $s = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $n + "'")
  if (-not $s) { $s = Get-CimInstance -ClassName Win32_Service -Filter ("DisplayName='" + $n + "'") }
  if ($s) { ` + winServiceRow + ` } else { [pscustomobject]@{ name = $n; found = $false } }
}
[Console]::Out.WriteLine('#komando:json=' + (ConvertTo-Json -Compress -InputObject @($rows)))
`
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
		return nil, out.Errf(out.ExitRemote, "COMMAND_FAILED", "read the error output (stderr) for the reason", "PowerShell gave no service list (exit code %d)", rr.ExitCode)
	}
	var missing []string
	for _, s := range svcs {
		if !s.Found {
			missing = append(missing, s.Name)
		}
	}
	if len(missing) > 0 {
		return svcs, out.Errf(out.ExitNotFound, "UNIT_NOT_FOUND", "check the name with `komando host ssh exec TARGET -- Get-Service`",
			"service not found: %s", strings.Join(missing, ", "))
	}
	return svcs, nil
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
			return nil, out.Errf(out.ExitRemote, "COMMAND_FAILED", "read the error output (stderr) for the reason", "PowerShell gave no service list (exit code %d)", rr.ExitCode)
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
