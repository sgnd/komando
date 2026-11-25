package execsession

import (
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// psSession: the login user's SID and the shared checks of remove and
// the sweep. ks_safeDir: a folder, not a reparse point, owned by the
// login user. ks_ended: the run wrote exit, was stopped (killed) or found
// lost. ks_gone: the recorded process is not the live one (gone, or its
// PID reused). Deleting is by rmdir /s /q, which removes a junction
// inside the folder without following it.
const psSession = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ks_sid = @(whoami.exe /user /fo csv /nh | ConvertFrom-Csv -Header 'n', 's')
if ($ks_sid.Count -eq 1) { $ks_sid = $ks_sid[0].s } else { $ks_sid = 'none' }
function ks_safeDir([string]$p) {
    if (-not (Test-Path -LiteralPath $p)) { return $false }
    $i = Get-Item -LiteralPath $p -Force
    if (-not $i.PSIsContainer -or $i.Attributes.ToString() -match 'ReparsePoint') { return $false }
    if ((ks_owner (Get-Acl -LiteralPath $p).Sddl) -ne $ks_sid) { return $false }
    return $true
}
function ks_ended([string]$d) {
    return (Test-Path -LiteralPath (Join-Path $d 'exit')) -or (Test-Path -LiteralPath (Join-Path $d 'killed')) -or (Test-Path -LiteralPath (Join-Path $d 'lost'))
}
function ks_gone([int]$p, [string]$created, [string]$cmdline) {
    $q = @(Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $p))
    if ($q.Count -ne 1) { return $true }
    return ($q[0].CreationDate.ToUniversalTime().ToString('o') -cne $created) -or ($q[0].CommandLine -cne $cmdline)
}
$ks_base = $env:LOCALAPPDATA
$ks_s = $null
if ($ks_base -and $ks_base -match '^[A-Za-z]:\\') { $ks_s = Join-Path (Join-Path $ks_base 'komando') 'sessions' }
`

// goneCheckPS is PowerShell that is true when rec's process is no longer
// the live one; a record a check cannot trust never counts ($false).
func goneCheckPS(id string, rec *store.ExecSession) string {
	if rec == nil || rec.ID != id || checkRecordPS(rec) != nil {
		return "$false"
	}
	return "ks_gone " + strconv.Itoa(rec.PID) + " " + sshx.PSQ(strings.TrimPrefix(rec.ProcStart, "cim ")) + " " + sshx.PSQ(rec.CmdLine)
}

// RemoveScriptPS is the PowerShell text that deletes one ended Windows
// session: komando, sessions and the session folder must pass ks_safeDir
// (ExitUnsafe; a missing one ExitGone), and the run must have ended
// (ExitNotRunning). With a record the run can be trusted for, its process
// alone decides, whatever files the run wrote; without one, the files do
// (as RemoveScript on Unix).
func RemoveScriptPS(id string, rec *store.ExecSession) (string, error) {
	if err := CheckID(id); err != nil {
		return "", err
	}
	cmdline := ""
	if rec != nil {
		cmdline = rec.CmdLine
	}
	over := "ks_ended $ks_d"
	if g := goneCheckPS(id, rec); g != "$false" {
		over = strings.Replace(g, sshx.PSQ(cmdline), "$ks_cmdline", 1)
	}
	return "$ks_id = " + sshx.PSQ(id) + "\n$ks_cmdline = " + sshx.PSQ(cmdline) + "\n" + psACL + psSession + `try {
    if (-not $ks_s) { exit 95 }
    $ks_d = Join-Path $ks_s $ks_id
    foreach ($p in @((Split-Path -Parent $ks_s), $ks_s, $ks_d)) {
        if (-not (Test-Path -LiteralPath $p)) { exit 95 }
        if (-not (ks_safeDir $p)) { exit 90 }
    }
    if (-not (` + over + `)) { exit 92 }
    $null = & cmd.exe /d /c rmdir /s /q $ks_d
    if (Test-Path -LiteralPath $ks_d) { exit 1 }
} catch {
    exit 99
}
`, nil
}

// SweepPS is the PowerShell text that deletes every Windows session
// folder whose run ended more than Retention ago by the server's clock,
// and prints "swept ID" for each (design note 3.8, A-C324-10). Only
// folders right below the resolved sessions folder, named like an ID,
// passing ks_safeDir; a running session is never swept. A folder with a
// record in recs is decided by its process alone: a live one is skipped
// whatever files the run wrote, and a gone one is marked lost when it
// wrote no end (as Sweep on Unix). It runs inside a function, so a
// caller's script goes on after it.
func SweepPS(recs []*store.ExecSession) string {
	var cases strings.Builder
	for _, rec := range recs {
		if gone := goneCheckPS(rec.ID, rec); gone != "$false" {
			cases.WriteString("            " + sshx.PSQ(rec.ID) + " { if (-not (" + gone + ")) { $skip = $true } elseif (-not ((Test-Path -LiteralPath (Join-Path $d 'exit')) -or (Test-Path -LiteralPath (Join-Path $d 'killed')))) { $null = New-Item -ItemType File -Path (Join-Path $d 'lost') -ErrorAction SilentlyContinue } }\n")
		}
	}
	lost := ""
	if cases.Len() > 0 {
		lost = "        $skip = $false\n        switch -exact ($n) {\n" + cases.String() + "        }\n        if ($skip) { continue }\n"
	}
	return "function ks_sweep {\n" + psACL + psSession + `    if (-not $ks_s -or -not (ks_safeDir (Split-Path -Parent $ks_s)) -or -not (ks_safeDir $ks_s)) { return }
    $now = [int64](((Get-Date).ToUniversalTime()) - [datetime]'1970-01-01').TotalSeconds
    foreach ($e in @(Get-ChildItem -LiteralPath $ks_s -Force -Directory)) {
        $n = $e.Name
        if (-not ($n -cmatch '^[a-z2-7]{52}$')) { continue }
        $d = Join-Path $ks_s $n
        if (-not (ks_safeDir $d)) { continue }
` + lost + `        if (-not (ks_ended $d)) { continue }
        $b = (-join (@(Get-Content -LiteralPath (Join-Path $d 'started') -Encoding Byte -TotalCount 16 -ErrorAction SilentlyContinue) | ForEach-Object { [char]$_ }))
        if ($b -notmatch '^[0-9]+$') { continue }
        if (($now - [int64]$b) -le ` + strconv.Itoa(Retention) + `) { continue }
        $null = & cmd.exe /d /c rmdir /s /q $d
        if (-not (Test-Path -LiteralPath $d)) { Write-Output ('swept ' + $n) }
    }
}
try { ks_sweep } catch {}
`
}

// BeginScriptPS is a starting Windows exec's one call: the sweep, between
// markers that carry the new session's ID (Swept), then StartScriptPS.
func BeginScriptPS(s StartPS, recs []*store.ExecSession) (string, []byte, error) {
	start, input, err := StartScriptPS(s)
	if err != nil {
		return "", nil, err
	}
	return "Write-Output 'sweep-begin " + s.ID + "'\n" + SweepPS(recs) + "Write-Output 'sweep-end " + s.ID + "'\n" + start, input, nil
}

// RemoveExitPS maps a Windows remove's exit as RemoveExit does a Unix
// one, with the Windows folder hint.
func RemoveExitPS(host, id string, exit int) error {
	if exit == ExitUnsafe {
		return Follow{Host: host, ID: id, Windows: true}.readExit(exit)
	}
	return RemoveExit(host, id, exit)
}
