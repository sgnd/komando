package execsession

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// RunPS is run.ps1, the session's root process on Windows (design note
// 3.5): CIM starts it outside the transport's job object, so it lives on
// when the connection drops. It finds its folder with $PSScriptRoot, so
// no path is in its text; only the cap and, with a timeout, the watcher
// are. It waits up to 5 s for .go from the start script (the facts are
// read by then), runs cmd.ps1 in a child Windows PowerShell with the
// input file as its stdin (cmd.exe's < is byte for byte), pumps its
// output and errors through ONE capped pipeline into out.log, writes the
// exit code through exit.tmp unless the run was stopped (killed), and
// deletes the input.
func RunPS(logMax int64, timeout time.Duration) []byte {
	watch := ""
	if timeout > 0 {
		watch = `Start-Process -FilePath powershell.exe -WindowStyle Hidden -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + (Join-Path $ks_d 'watch.ps1') + '"'), $PID)
`
	}
	return []byte(bom + psRunHead + watch + `$ks_cmd = 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $ks_d 'cmd.ps1') + '"'
$ks_in = Join-Path $ks_d 'in'
if (Test-Path -LiteralPath $ks_in) { $ks_cmd += ' < "' + $ks_in + '"' }
& cmd.exe /d /c $ks_cmd 2>&1 | ks_capped ` + strconv.FormatInt(logMax, 10) + ` | Out-File -FilePath (Join-Path $ks_d 'out.log') -Encoding UTF8 -Append
` + psRunTail)
}

// psRunHead: UTF-8 output where the language mode allows it, the wait
// for .go, and the pump. ks_capped keeps a line while it fits under the
// cap (its UTF-8 bytes and the CRLF Out-File adds), drops it and every
// line after it once one does not, so out.log is a prefix of the output,
// and writes the bytes it dropped to truncated. It reads on to the end,
// so the command never blocks on a full pipe.
const psRunHead = `$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$ks_d = $PSScriptRoot
try { $OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$null = & chcp.com 65001
function ks_capped([int64]$cap) {
    begin { $n = [int64]0; $drop = [int64]0 }
    process {
        $line = [string]$_
        $b = [Text.Encoding]::UTF8.GetByteCount($line) + 2
        if ($drop -eq 0 -and $n + $b -le $cap) { $n += $b; $line } else { $drop += $b }
    }
    end {
        if ($drop -gt 0) { Set-Content -LiteralPath (Join-Path $ks_d 'truncated') -Value ([string]$drop) -Encoding ASCII -NoNewline }
    }
}
# end ks_capped
$ks_i = 0
while (-not (Test-Path -LiteralPath (Join-Path $ks_d '.go')) -and $ks_i -lt 50) { Start-Sleep -Milliseconds 100; $ks_i++ }
if (-not (Test-Path -LiteralPath (Join-Path $ks_d '.go'))) { exit 0 }
Remove-Item -LiteralPath (Join-Path $ks_d '.go') -Force
`

const psRunTail = `$ks_c = $LASTEXITCODE
Remove-Item -LiteralPath $ks_in -Force -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath (Join-Path $ks_d 'killed'))) {
    Set-Content -LiteralPath (Join-Path $ks_d 'exit.tmp') -Value ([string]$ks_c) -Encoding ASCII -NoNewline
    Move-Item -LiteralPath (Join-Path $ks_d 'exit.tmp') -Destination (Join-Path $ks_d 'exit') -Force
}
`

// WatchPS is watch.ps1, the timeout watcher run.ps1 starts with its own
// PID: it ends when exit appears; at the deadline it writes killed and
// ends run.ps1's whole tree (taskkill /T), itself included.
func WatchPS(timeout time.Duration) []byte {
	secs := strconv.Itoa(int((timeout + time.Second - 1) / time.Second))
	return []byte(bom + `param([int]$run)
$ks_d = $PSScriptRoot
$ks_end = (Get-Date).AddSeconds(` + secs + `)
while ((Get-Date) -lt $ks_end) {
    if (Test-Path -LiteralPath (Join-Path $ks_d 'exit')) { exit 0 }
    Start-Sleep -Seconds 1
}
if (Test-Path -LiteralPath (Join-Path $ks_d 'exit')) { exit 0 }
Set-Content -LiteralPath (Join-Path $ks_d 'killed') -Value 'TERM timeout' -Encoding ASCII
$null = & taskkill.exe /PID $run /T /F
`)
}

// psLaunch starts run.ps1 through CIM with only its path on the command
// line, reads the process's facts (PID, creation date, image, command
// line), writes pid for --attach, prints the facts between markers that
// carry the ID, and only then writes .go. When the facts cannot be read
// the process is ended (ks_fail) before it ran anything.
const psLaunch = `    $ks_run = Join-Path $ks_d 'run.ps1'
    $ks_p = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = ('powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $ks_run + '"'); CurrentDirectory = $ks_d }
    if ($ks_p.ReturnValue -ne 0 -or -not $ks_p.ProcessId) { ks_fail 99 }
    $ks_pid = [int]$ks_p.ProcessId
    $ks_q = @(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $ks_pid))
    if ($ks_q.Count -ne 1) { ks_fail 99 }
    Set-Content -LiteralPath (Join-Path $ks_d 'pid') -Value ([string]$ks_pid) -Encoding ASCII -NoNewline
    Write-Output ('facts-begin ' + $ks_id)
    Write-Output ('pid ' + $ks_pid)
    Write-Output ('created ' + $ks_q[0].CreationDate.ToUniversalTime().ToString('o'))
    Write-Output ('image ' + $ks_q[0].Name)
    Write-Output ('cmdline ' + $ks_q[0].CommandLine)
    Write-Output ('facts-end ' + $ks_id)
    $null = New-Item -ItemType File -Path (Join-Path $ks_d '.go')
`

var errFactsPS = errors.New("the server did not give the run's process: pid, creation date, image and command line")

// ParseFactsPS reads psLaunch's facts for session id: only the lines
// between its markers, each fact once. The PID is above 4 (0 is the idle
// process, 4 System), the image is Windows PowerShell, and the command
// line runs this session's run.ps1: a stop later checks the same three
// on the live process (A-C324-8).
func ParseFactsPS(s, id string) (Facts, error) {
	var f Facts
	seen := map[string]bool{}
	inside, ended := false, false
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		switch {
		case line == "facts-begin "+id && !inside && !ended:
			inside = true
			continue
		case line == "facts-end "+id && inside:
			inside, ended = false, true
			continue
		case !inside:
			continue
		}
		k, v, _ := strings.Cut(line, " ")
		if seen[k] {
			return Facts{}, errFactsPS
		}
		seen[k] = true
		var err error
		switch k {
		case "pid":
			f.PID, err = strconv.Atoi(v)
		case "created":
			_, err = time.Parse(time.RFC3339Nano, v)
			f.Start = "cim " + v
		case "image":
			f.Image = v
		case "cmdline":
			f.CmdLine = v
		default:
			err = errFactsPS
		}
		if err != nil {
			return Facts{}, errFactsPS
		}
	}
	if !ended || len(seen) != 4 || f.PID <= 4 || !strings.EqualFold(f.Image, "powershell.exe") ||
		!strings.HasSuffix(f.CmdLine, `\komando\sessions\`+id+`\run.ps1"`) {
		return Facts{}, errFactsPS
	}
	return f, nil
}
