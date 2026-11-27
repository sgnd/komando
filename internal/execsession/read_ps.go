package execsession

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// ReadMaxPS is the most of out.log one Windows read takes (design note
// 3.3 step 4): the bytes travel as base64 on PowerShell's output.
const ReadMaxPS = 64 << 10

// ReadScriptPS is the PowerShell text that reads a Windows session from
// byte from on. On every read it checks that komando, sessions and the
// session folder are folders, not reparse points, owned by the login user
// (exit ExitUnsafe; a missing one exits ExitGone). It prints the status
// between markers that carry the ID, the exit file before the size, then
// at most ReadMaxPS bytes as one base64 data line. Without .NET file
// calls (Constrained Language Mode) it reads out.log in 64 KiB pieces and
// skips to the piece that holds from. It deletes nothing.
func ReadScriptPS(id string, from int64) (string, error) {
	if err := CheckID(id); err != nil {
		return "", err
	}
	if from < 0 {
		return "", errors.New("session read: a negative offset")
	}
	return "$ks_id = " + sshx.PSQ(id) + "\n$ks_from = " + strconv.FormatInt(from, 10) + "\n" + psACL + psRead, nil
}

const psRead = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function ks_head([string]$p, [int]$n) {
    $b = @(Get-Content -LiteralPath $p -Encoding Byte -TotalCount $n)
    return (-join ($b | ForEach-Object { [char]$_ })) -replace '[\r\n]', ''
}
try {
    $ks_sid = @(whoami.exe /user /fo csv /nh | ConvertFrom-Csv -Header 'n', 's')
    if ($ks_sid.Count -ne 1) { exit 99 }
    $ks_sid = $ks_sid[0].s
    $ks_base = $env:LOCALAPPDATA
    if (-not $ks_base -or $ks_base -notmatch '^[A-Za-z]:\\') { exit 95 }
    $ks_s = Join-Path (Join-Path $ks_base 'komando') 'sessions'
    $ks_d = Join-Path $ks_s $ks_id
    foreach ($p in @((Join-Path $ks_base 'komando'), $ks_s, $ks_d)) {
        if (-not (Test-Path -LiteralPath $p)) { exit 95 }
        $i = Get-Item -LiteralPath $p -Force
        if (-not $i.PSIsContainer -or $i.Attributes.ToString() -match 'ReparsePoint') { exit 90 }
        if ((ks_owner (Get-Acl -LiteralPath $p).Sddl) -ne $ks_sid) { exit 90 }
    }
    foreach ($f in @('out.log', 'exit', 'killed', 'truncated')) {
        $p = Join-Path $ks_d $f
        if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes.ToString() -match 'ReparsePoint|Directory')) { exit 90 }
    }
    $ks_log = Join-Path $ks_d 'out.log'
    if (-not (Test-Path -LiteralPath $ks_log)) { exit 95 }
    Write-Output ('read-begin ' + $ks_id)
    if (Test-Path -LiteralPath (Join-Path $ks_d 'exit')) { Write-Output ('exit ' + (ks_head (Join-Path $ks_d 'exit') 16)) }
    if (Test-Path -LiteralPath (Join-Path $ks_d 'killed')) { Write-Output ('killed ' + (ks_head (Join-Path $ks_d 'killed') 64)) }
    if (Test-Path -LiteralPath (Join-Path $ks_d 'truncated')) { Write-Output ('truncated ' + (ks_head (Join-Path $ks_d 'truncated') 24)) }
    $ks_size = (Get-Item -LiteralPath $ks_log -Force).Length
    Write-Output ('size ' + $ks_size)
    Write-Output ('read-end ' + $ks_id)
    if ($ks_from -lt $ks_size) {
        $ks_k = ($ks_from - ($ks_from % 65536)) / 65536
        $ks_all = @(Get-Content -LiteralPath $ks_log -Encoding Byte -ReadCount 65536 | Select-Object -Skip $ks_k -First 2 | ForEach-Object { $_ })
        $ks_o = $ks_from - $ks_k * 65536
        $ks_n = $ks_all.Count - $ks_o
        if ($ks_n -gt 65536) { $ks_n = 65536 }
        if ($ks_n -gt 0) {
            $ks_part = $ks_all[$ks_o..($ks_o + $ks_n - 1)]
            Write-Output ('data ' + [Convert]::ToBase64String([byte[]]$ks_part))
        }
    }
} catch {
    exit 99
}
`

var errReadPS = errors.New("the server did not give the session's status and output")

// ParseReadPS reads ReadScriptPS's output for session id: the status
// lines between its markers (as ParseRead reads them), then at most one
// base64 data line of at most ReadMaxPS bytes.
func ParseReadPS(s, id string) (Status, []byte, error) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	end := "read-end " + id + "\n"
	i := strings.Index(s, end)
	if i < 0 {
		return Status{}, nil, errReadPS
	}
	st, _, err := ParseRead(s[:i+len(end)], id)
	if err != nil {
		return Status{}, nil, err
	}
	var data []byte
	for _, line := range strings.Split(strings.TrimSuffix(s[i+len(end):], "\n"), "\n") {
		if line == "" {
			continue
		}
		b64, ok := strings.CutPrefix(line, "data ")
		if !ok || data != nil {
			return Status{}, nil, errReadPS
		}
		if data, err = base64.StdEncoding.DecodeString(b64); err != nil || len(data) > ReadMaxPS {
			return Status{}, nil, errReadPS
		}
	}
	return st, data, nil
}

func folderDeniedPS(host string) error {
	return out.Errf(out.ExitRemote, "SESSION_FOLDER_DENIED",
		"look with `komando exec TARGET -- icacls $env:LOCALAPPDATA\\komando\\sessions`: each is to be a plain folder of the login user that only it, SYSTEM and Administrators can write",
		"%s: %%LOCALAPPDATA%%\\komando or its sessions folder is a link or junction, a file, not the login user's, or others can write it", host)
}
