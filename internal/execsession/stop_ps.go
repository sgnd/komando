package execsession

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// checkRecordPS refuses a Windows record a stop or a lost check cannot
// trust: no usable PID, no CIM creation date, not Windows PowerShell, or a
// command line that is not this session's run.ps1.
func checkRecordPS(rec *store.ExecSession) error {
	if rec == nil {
		return errors.New("no record of the session on this computer")
	}
	if err := CheckID(rec.ID); err != nil {
		return err
	}
	created, ok := strings.CutPrefix(rec.ProcStart, "cim ")
	if _, err := time.Parse(time.RFC3339Nano, created); !ok || err != nil || rec.PID <= 4 ||
		!strings.EqualFold(rec.Image, "powershell.exe") || !strings.HasSuffix(rec.CmdLine, `\komando\sessions\`+rec.ID+`\run.ps1"`) {
		return errors.New("session " + rec.ID + ": the record has no usable pid, creation date, image or command line")
	}
	return nil
}

// StopScriptPS is the PowerShell text that stops a Windows run, built from
// its record alone (A-C324-1): the live process must have the recorded
// creation date, image and command line (A-C324-8), else exit
// ExitNotRunning. It lists the process tree, ends it with taskkill /T /F,
// prints "ended PID" for each, notes the stop in killed, and ends with
// "stopped ID". A process whose parent had already exited is not in the
// tree and may remain.
func StopScriptPS(rec *store.ExecSession) (string, error) {
	if err := checkRecordPS(rec); err != nil {
		return "", err
	}
	return "$ks_id = " + sshx.PSQ(rec.ID) + "\n$ks_pid = " + strconv.Itoa(rec.PID) +
		"\n$ks_created = " + sshx.PSQ(strings.TrimPrefix(rec.ProcStart, "cim ")) +
		"\n$ks_cmdline = " + sshx.PSQ(rec.CmdLine) + "\n" + psStop, nil
}

const psStop = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ks_q = @(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $ks_pid))
if ($ks_q.Count -ne 1) { exit 92 }
if ($ks_q[0].CreationDate.ToUniversalTime().ToString('o') -cne $ks_created -or $ks_q[0].Name -ne 'powershell.exe' -or $ks_q[0].CommandLine -cne $ks_cmdline) { exit 92 }
$ks_all = @(Get-CimInstance -ClassName Win32_Process | Select-Object ProcessId, ParentProcessId)
$ks_tree = @($ks_pid)
$ks_i = 0
while ($ks_i -lt $ks_tree.Count) {
    foreach ($c in $ks_all) {
        if ($c.ParentProcessId -eq $ks_tree[$ks_i] -and $ks_tree -notcontains $c.ProcessId) { $ks_tree += [int]$c.ProcessId }
    }
    $ks_i++
}
$null = & taskkill.exe /PID $ks_pid /T /F
if ($LASTEXITCODE -ne 0) { exit 1 }
foreach ($p in $ks_tree) { Write-Output ('ended ' + $p) }
try {
    $ks_d = Join-Path (Join-Path (Join-Path $env:LOCALAPPDATA 'komando') 'sessions') $ks_id
    $i = Get-Item -LiteralPath $ks_d -Force
    if ($i.PSIsContainer -and $i.Attributes.ToString() -notmatch 'ReparsePoint') { $null = New-Item -ItemType File -Path (Join-Path $ks_d 'killed') -Value 'stop' }
} catch {}
Write-Output ('stopped ' + $ks_id)
`

var errStopPS = errors.New("the server did not say which processes the stop ended")

// ParseStopPS reads the PIDs StopScriptPS ended; its end line must be
// there.
func ParseStopPS(s, id string) ([]int, error) {
	var pids []int
	done := false
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		if line == "stopped "+id {
			done = true
		}
		if v, ok := strings.CutPrefix(line, "ended "); ok {
			p, err := strconv.Atoi(v)
			if err != nil || p <= 4 {
				return nil, errStopPS
			}
			pids = append(pids, p)
		}
	}
	if !done {
		return nil, errStopPS
	}
	return pids, nil
}

// StopLimitPS is what a Windows stop cannot promise (design note 3.7).
const StopLimitPS = "a process whose parent had already exited may remain"

// SignalPS refuses --signal for a Windows session: Windows has no signals
// (decision E8). An empty sig is no --signal.
func SignalPS(sig string) error {
	if sig == "" {
		return nil
	}
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"Windows has no signals: `komando exec TARGET --attach ID --stop` alone ends the run",
		"--signal %s does not work on Windows servers", sig)
}
