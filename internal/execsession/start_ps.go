package execsession

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// Exits of the Windows start script, beside ExitUnsafe, ExitNoFolder and
// ExitNoSpace, which mean what they mean on Unix.
const (
	ExitACL         = 96 // the session folder's ACL could not be set to the user and SYSTEM alone; the folder is gone
	ExitDenied      = 97 // Constrained Language Mode or AppLocker blocked a step; the folder is gone
	ExitShortInput  = 98 // stdin ended before every file arrived; the folder is gone
	ExitStartFailed = 99 // any other error; the folder is gone
)

// StartPS is what one run in a session on a Windows server needs
// (design note 3.3).
type StartPS struct {
	ID      string
	Command string   // the PowerShell text the run runs, as exec built it
	Env     []EnvVar // values from the vault and --env
	Stdin   []byte   // the run's input; nil: none
	LogMax  int64    // out.log's cap in bytes
}

// EnvVar is one environment variable of a run.
type EnvVar struct{ Key, Value string }

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// bom is UTF-8's byte order mark: Windows PowerShell 5.1 reads a .ps1
// without it in the ANSI code page.
const bom = "\xef\xbb\xbf"

// envPrelude is cmd.ps1's head when the run has env: it reads the env
// file next to it into $env: and deletes the file, also when reading
// fails; a failed read stops the run before the command (exit 125), so a
// command never runs without a value it was given.
const envPrelude = `$ks_env = Join-Path $PSScriptRoot 'env'
try {
    foreach ($ks_l in @(Get-Content -LiteralPath $ks_env -Encoding UTF8 -ErrorAction Stop)) {
        $ks_k, $ks_v = $ks_l -split '=', 2
        Set-Item -LiteralPath ('env:' + $ks_k) -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ks_v))) -ErrorAction Stop
    }
} catch {
    Write-Output 'komando: the session could not read its environment values'
    exit 125
} finally {
    Remove-Item -LiteralPath $ks_env -Force -ErrorAction SilentlyContinue
}
Remove-Variable ks_env, ks_l, ks_k, ks_v -ErrorAction SilentlyContinue
`

// CmdPS is cmd.ps1: the env prelude when the run has env, then the
// command. It holds no value: those are in the env file.
func CmdPS(command string, env bool) []byte {
	s := bom
	if env {
		s += envPrelude
	}
	return []byte(s + command + "\n")
}

// envFilePS is the env file: one KEY=base64 line per value, so a value
// may hold anything.
func envFilePS(vars []EnvVar) ([]byte, error) {
	var b strings.Builder
	for _, v := range vars {
		if !envKey.MatchString(v.Key) {
			return nil, out.Usage("%q is not an environment variable name: use letters, digits and _", v.Key)
		}
		b.WriteString(v.Key + "=" + base64.StdEncoding.EncodeToString([]byte(v.Value)) + "\r\n")
	}
	return []byte(b.String()), nil
}

// StartScriptPS is the one PowerShell call that prepares a run in a
// session on a Windows server, and the input it reads: cmd.ps1, the env
// file and the run's input, each one base64 line, in that order. Only the
// checked ID and the cap go into the text; everything else is data.
func StartScriptPS(s StartPS) (script string, input []byte, err error) {
	if err := CheckID(s.ID); err != nil {
		return "", nil, err
	}
	if s.LogMax <= 0 {
		return "", nil, errors.New("session start: no log cap")
	}
	var files []string
	var in strings.Builder
	put := func(name string, b []byte) {
		files = append(files, "ks_put "+sshx.PSQ(name))
		in.WriteString(base64.StdEncoding.EncodeToString(b) + "\n")
	}
	put("cmd.ps1", CmdPS(s.Command, s.Env != nil))
	if s.Env != nil {
		env, err := envFilePS(s.Env)
		if err != nil {
			return "", nil, err
		}
		put("env", env)
	}
	if s.Stdin != nil {
		put("in", s.Stdin)
	}
	script = "$ks_id = " + sshx.PSQ(s.ID) + "\n$ks_cap = " + strconv.FormatInt(s.LogMax, 10) + "\n" +
		psStartHead + psStartFolders + "    " + strings.Join(files, "\n    ") + "\n" + psStartTail
	return script, []byte(in.String()), nil
}

// psStartHead: helpers and the checks before any folder is made. Errors
// stop the script ($ErrorActionPreference); ks_fail deletes the session
// folder when this call made it, then exits.
const psStartHead = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ks_d = $null
$ks_made = $false
function ks_fail([int]$code) {
    if ($ks_made) { Remove-Item -LiteralPath $ks_d -Recurse -Force -ErrorAction SilentlyContinue }
    exit $code
}
# rights of an ACE as a mask; an unknown letter pair counts as every right
function ks_mask([string]$r) {
    if ($r -match '^0x[0-9A-Fa-f]+$') { return [int64]$r }
    $m = @{ GA = 0x10000000; GR = 0x80000000L; GW = 0x40000000; GX = 0x20000000; RC = 0x20000; SD = 0x10000; WD = 0x40000; WO = 0x80000;
        CC = 0x1; DC = 0x2; LC = 0x4; SW = 0x8; RP = 0x10; WP = 0x20; DT = 0x40; LO = 0x80; CR = 0x100;
        FA = 0x1F01FF; FR = 0x120089; FW = 0x120116; FX = 0x1200A0 }
    $n = [int64]0
    for ($i = 0; $i -lt $r.Length; $i += 2) {
        if ($i + 2 -gt $r.Length) { return [int64]0xFFFFFFFFL }
        $k = $r.Substring($i, 2)
        if (-not $m.ContainsKey($k)) { return [int64]0xFFFFFFFFL }
        $n = $n -bor $m[$k]
    }
    return $n
}
# the allow ACEs of an SDDL's DACL: type;flags;rights;;;trustee
function ks_aces([string]$sd) {
    $i = $sd.IndexOf('D:')
    if ($i -lt 0) { return @() }
    $dacl = $sd.Substring($i)
    $j = $dacl.IndexOf('S:')
    if ($j -ge 0) { $dacl = $dacl.Substring(0, $j) }
    $all = @($dacl | Select-String -Pattern '\(([^;()]*);([^;()]*);([^;()]*);[^;()]*;[^;()]*;([^;()]*)\)' -AllMatches | ForEach-Object { $_.Matches })
    return @($all | Where-Object { $_.Groups[1].Value -match '^(A|OA|XA|ZA)$' })
}
`

// psStartFolders: the login user's SID, %LOCALAPPDATA% resolved once,
// the free-space check, komando and sessions checked (no reparse point,
// owned by the user, writable only by the user, SYSTEM and
// Administrators), then the session folder made new with its two-entry
// ACL, read back and compared before any file is written.
const psStartFolders = `try {
    $ks_sid = @(whoami.exe /user /fo csv /nh | ConvertFrom-Csv -Header 'n', 's')
    if ($ks_sid.Count -ne 1 -or $ks_sid[0].s -notmatch '^S-1-5(-[0-9]+)+$') { ks_fail 99 }
    $ks_sid = $ks_sid[0].s
    $ks_base = $env:LOCALAPPDATA
    if (-not $ks_base -or $ks_base -notmatch '^[A-Za-z]:\\') { ks_fail 91 }
    $ks_r = Join-Path $ks_base 'komando'
    $ks_s = Join-Path $ks_r 'sessions'
    $ks_v = Get-PSDrive -Name $ks_base.Substring(0, 1) -PSProvider FileSystem -ErrorAction SilentlyContinue
    if ($ks_v -and $null -ne $ks_v.Free -and $ks_v.Free -lt ($ks_cap + ($ks_v.Used + $ks_v.Free) / 20)) { ks_fail 93 }
    # an elevated administrator's new folder may be owned by
    # Administrators: the login user takes it (WRITE_OWNER is its own)
    function ks_own([string]$p, [int]$code) {
        $null = & icacls.exe $p /setowner ('*' + $ks_sid)
        if ($LASTEXITCODE -ne 0) { ks_fail $code }
    }
    function ks_dir([string]$p) {
        if (-not (Test-Path -LiteralPath $p)) {
            try { $null = New-Item -ItemType Directory -Path $p } catch { ks_fail 91 }
            ks_own $p 90
        }
        $i = Get-Item -LiteralPath $p -Force
        if (-not $i.PSIsContainer -or $i.Attributes.ToString() -match 'ReparsePoint') { ks_fail 90 }
        $sd = (Get-Acl -LiteralPath $p).Sddl
        if (-not ($sd -match '^O:(S-[0-9-]+|[A-Z]{2})') -or $Matches[1] -ne $ks_sid) { ks_fail 90 }
        foreach ($a in ks_aces $sd) {
            if ($a.Groups[2].Value -match 'IO') { continue }
            if (@($ks_sid, 'SY', 'S-1-5-18', 'BA', 'S-1-5-32-544') -contains $a.Groups[4].Value) { continue }
            if ((ks_mask $a.Groups[3].Value) -band 0x500D0156) { ks_fail 90 }
        }
    }
    ks_dir $ks_r
    ks_dir $ks_s
    $ks_d = Join-Path $ks_s $ks_id
    if (Test-Path -LiteralPath $ks_d) { ks_fail 90 }
    try { $null = New-Item -ItemType Directory -Path $ks_d } catch { ks_fail 91 }
    $ks_made = $true
    ks_own $ks_d 96
    $null = & icacls.exe $ks_d /inheritance:r /grant:r ('*' + $ks_sid + ':(OI)(CI)F') '*S-1-5-18:(OI)(CI)F'
    if ($LASTEXITCODE -ne 0) { ks_fail 96 }
    function ks_aclExact([string]$sd) {
        if (-not ($sd -match '^O:(S-[0-9-]+|[A-Z]{2})') -or $Matches[1] -ne $ks_sid) { return $false }
        if (-not ($sd -match 'D:([A-Z]*)\(') -or $Matches[1] -notmatch 'P') { return $false }
        $got = @(ks_aces $sd | ForEach-Object { $_.Value }) | Sort-Object
        $want = @(('(A;OICI;FA;;;' + $ks_sid + ')'), '(A;OICI;FA;;;SY)') | Sort-Object
        return ($got.Count -eq 2) -and ($got[0] -ceq $want[0]) -and ($got[1] -ceq $want[1])
    }
    if (-not (ks_aclExact (Get-Acl -LiteralPath $ks_d).Sddl)) { ks_fail 96 }
    function ks_put([string]$name) {
        $l = [Console]::In.ReadLine()
        if ($null -eq $l) { ks_fail 98 }
        Set-Content -LiteralPath (Join-Path $ks_d $name) -Value ([Convert]::FromBase64String($l)) -Encoding Byte
    }
`

// psStartTail: the start time (UTC seconds) and an empty out.log, then
// the line ReadStartPS looks for. An error anywhere is ExitDenied when
// PowerShell names its language mode or a policy block, else
// ExitStartFailed with its reason on one line.
const psStartTail = `    $ks_now = [int64](((Get-Date).ToUniversalTime()) - [datetime]'1970-01-01').TotalSeconds
    Set-Content -LiteralPath (Join-Path $ks_d 'started') -Value ([string]$ks_now) -Encoding ASCII -NoNewline
    $null = New-Item -ItemType File -Path (Join-Path $ks_d 'out.log')
    Write-Output ('prepared ' + $ks_id)
} catch {
    $ks_e = ($_.FullyQualifiedErrorId + ' ' + $_.Exception.Message) -replace '[\r\n]+', ' '
    Write-Output ('failed ' + $ks_e)
    if ($ks_e -match 'ConstrainedLanguage|language mode|AppLocker|group policy') { ks_fail 97 }
    ks_fail 99
}
`

// psBlocked is how PowerShell names a block by Constrained Language Mode
// or by AppLocker (Software Restriction) policy.
var psBlocked = regexp.MustCompile(`(?i)ConstrainedLanguage|language mode|AppLocker|blocked by group policy`)

// ReadStartPS reads what StartScriptPS printed, its exit and its stderr on
// host. ErrNoFolder (no folder can be made) is the only error after which
// exec may run the command without a session; a blocked start, also one
// blocked before the script ran (the bootstrap under Constrained Language
// Mode), is SESSION_START_DENIED and never falls back.
func ReadStartPS(host string, exit int, stdout, stderr, id string) error {
	reason := ""
	for _, line := range strings.Split(strings.ReplaceAll(stdout, "\r", ""), "\n") {
		if line == "prepared "+id && exit == 0 {
			return nil
		}
		if r, ok := strings.CutPrefix(line, "failed "); ok {
			reason = r
		}
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	switch exit {
	case ExitNoFolder:
		return ErrNoFolder
	case ExitUnsafe:
		return out.Errf(out.ExitRemote, "SESSION_FOLDER_DENIED",
			"look with `komando exec TARGET -- icacls $env:LOCALAPPDATA\\komando\\sessions`: each is to be a plain folder of the login user that only it, SYSTEM and Administrators can write",
			"%s: %%LOCALAPPDATA%%\\komando or its sessions folder is a link or junction, a file, not the login user's, or others can write it", host)
	case ExitNoSpace:
		return out.Errf(out.ExitRemote, "SESSION_SPACE_DENIED",
			"free space on the drive of %LOCALAPPDATA%, or give a smaller log cap: `komando exec TARGET --log-max 100MiB -- COMMAND`",
			"%s: the drive of %%LOCALAPPDATA%% has less free space than the log cap plus 5 percent of the disk; nothing ran", host)
	case ExitACL:
		return out.Errf(out.ExitRemote, "SESSION_ACL_FAILED",
			"look with `komando exec TARGET -- icacls $env:LOCALAPPDATA\\komando\\sessions`: a policy may add entries to new folders there",
			"%s: the session folder's access list could not be limited to the login user and SYSTEM; the folder is deleted and nothing ran", host)
	case ExitDenied:
		return startDenied(host)
	case ExitShortInput:
		return startFailedPS(host, "the start got only part of its input")
	case ExitStartFailed:
		return startFailedPS(host, reason)
	}
	if psBlocked.MatchString(stderr) {
		return startDenied(host)
	}
	return startFailedPS(host, "exit "+strconv.Itoa(exit))
}

func startDenied(host string) error {
	return out.Errf(out.ExitRemote, "SESSION_START_DENIED",
		"look with `komando exec TARGET -- $ExecutionContext.SessionState.LanguageMode`: komando runs no command there without the session's protections, so the server's administrator allows its session scripts in the AppLocker rules first",
		"%s: Constrained Language Mode or AppLocker blocked the start of the run in a session; nothing ran and no session folder is left", host)
}

func startFailedPS(host, why string) error {
	return out.Errf(out.ExitRemote, "SESSION_START_FAILED",
		"komando runs every command on Windows in Windows PowerShell: look with `komando exec TARGET -- $PSVersionTable.PSVersion` and read the reason",
		"%s: the run in a session did not start (%s)", host, why)
}
