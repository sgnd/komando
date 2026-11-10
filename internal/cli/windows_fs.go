package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// fs, upload and download on Windows servers. There is no SFTP over WinRM,
// so both ways to Windows use PowerShell: file contents travel as base64
// lines on the command's input and output. Paths are Windows paths
// (C:\inetpub\app.config, or C:/inetpub/app.config); "" and ~ are the
// login user's profile folder.

// windowsOne is the server target picks when it is one Windows server;
// h is nil otherwise (the command takes its usual path and reports any
// problem with the target itself).
func windowsOne(target string) (*store.State, *store.Host) {
	st, err := loadState()
	if err != nil {
		return nil, nil
	}
	h, err := singleHost(st, target)
	if err != nil || !h.Windows() {
		return nil, nil
	}
	return st, h
}

// winPath is the start of every file script: $p is the path, made
// absolute against the login's profile folder, and mark writes a marker.
func winPath(p string) string {
	return `$ErrorActionPreference = 'Stop'
function mark($m) { [Console]::Out.WriteLine('#komando:' + $m) }
$p = ` + sshx.PSQ(p) + `
if ($p -eq '' -or $p -eq '~') { $p = $HOME } elseif ($p -like '~[\/]*') { $p = Join-Path $HOME $p.Substring(2) }
$p = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p)
`
}

// winCatch wraps body so a missing path or a refused one becomes a marker.
func winCatch(body string) string {
	return "try {\n" + body + `
} catch [System.UnauthorizedAccessException] { mark 'denied'; exit 0
} catch [System.Management.Automation.ItemNotFoundException] { mark 'not-found'; exit 0
} catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] { mark 'not-found'; exit 0 }
`
}

// winRow is the PowerShell that turns an item ($f) into a winEntry.
const winRow = `[pscustomobject]@{ name = $f.Name; path = $f.FullName; dir = $f.PSIsContainer; size = $(if ($f.PSIsContainer) { 0 } else { $f.Length }); mode = $f.Mode; mtime = $f.LastWriteTimeUtc.ToString('o'); link = [string]($f.Target | Select-Object -First 1); linktype = [string]$f.LinkType }`

// winEntry is one file or folder as winRow gives it.
type winEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Dir      bool   `json:"dir"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode"`
	MTime    string `json:"mtime"`
	Link     string `json:"link"`
	LinkType string `json:"linktype"`
}

func (e winEntry) info() fileInfo {
	t := map[bool]string{true: "dir", false: "file"}[e.Dir]
	if e.LinkType == "SymbolicLink" || e.LinkType == "Junction" {
		t = "symlink"
	}
	mt, _ := time.Parse(time.RFC3339Nano, e.MTime)
	inf := fileInfo{Name: e.Name, Path: e.Path, Type: t, Size: e.Size, Mode: e.Mode, ModTime: mt.UTC()}
	if t == "symlink" {
		inf.Link = e.Link
	}
	return inf
}

// winRun runs a komando file script on h and reads its markers. A marker
// that says the path is missing, a folder or refused is its error.
func winRun(ctx context.Context, st *store.State, h *store.Host, p, script string, maxOut int) (map[string]string, error) {
	var rr *sshx.RunResult
	err := withClient(allowWindows(ctx), st, h, func(c *sshx.Client) error {
		var err error
		rr, err = sshx.Run(ctx, c, sshx.RunRequest{Command: script, Timeout: cmdTimeout(st), MaxOutput: maxOut})
		return err
	})
	if err != nil {
		return nil, err
	}
	m := winMarkers(rr.Stdout)
	if e := winMarkerErr(p, m); e != nil {
		return m, e
	}
	if rr.ExitCode != 0 {
		return m, out.Errf(out.ExitRemote, "COMMAND_FAILED", "read the message; check the path with `komando fs stat "+h.Name+" PATH`",
			"%s", dash(strings.TrimSpace(rr.Stderr)))
	}
	return m, nil
}

// winMarkerErr is the error a file script's marker stands for, or nil.
func winMarkerErr(p string, m map[string]string) error {
	switch {
	case hasKey(m, "not-found"):
		return fsErrHint(p, os.ErrNotExist, "")
	case hasKey(m, "denied"):
		return out.Errf(out.ExitError, "PERMISSION_DENIED", "log in as a user with the rights to it (Windows has no sudo)", "%s: access denied", p)
	case hasKey(m, "dir"):
		return isADirectory(p)
	case hasKey(m, "no-dir"):
		return folderMissing(m["no-dir"])
	case hasKey(m, "symlink"):
		return isASymlink(p)
	case hasKey(m, "invalid"):
		return validateFailed("")
	}
	return nil
}

func hasKey(m map[string]string, k string) bool { _, ok := m[k]; return ok }

// winFsLs is fs ls on a Windows server. Hidden files are left out unless
// --all, as dotfiles are on Linux.
func winFsLs(ctx context.Context, st *store.State, h *store.Host, p string, all, recursive bool, maxEntries int) (any, error) {
	script := winPath(p) + winCatch(`if (-not (Test-Path -LiteralPath $p)) { mark 'not-found'; exit 0 }
$i = Get-Item -LiteralPath $p -Force
if ($i.PSIsContainer) { $items = @(Get-ChildItem -LiteralPath $p -Force:$`+strconv.FormatBool(all)+` -Recurse:$`+strconv.FormatBool(recursive)+` -ErrorAction SilentlyContinue | Select-Object -First `+strconv.Itoa(maxEntries+1)+`) } else { $items = @($i) }
$rows = foreach ($f in $items) { `+winRow+` }
mark ('path=' + $p)
mark ('json=' + (ConvertTo-Json -Compress -InputObject @($rows)))`)
	m, err := winRun(ctx, st, h, p, script, 64<<20)
	if err != nil {
		return nil, err
	}
	var es []winEntry
	if err := json.Unmarshal([]byte(m["json"]), &es); err != nil {
		return nil, out.Errf(out.ExitRemote, "COMMAND_FAILED", "run it again; if it happens again, report it at "+releaseSite+"/issues", "cannot read the folder list: %v", err)
	}
	r := lsResult{Path: m["path"], Entries: []fileInfo{}, recursive: recursive}
	for _, e := range es {
		if len(r.Entries) >= maxEntries {
			r.Truncated = true
			break
		}
		r.Entries = append(r.Entries, e.info())
	}
	r.Count = len(r.Entries)
	return r, nil
}

// winFsStat is fs stat on a Windows server.
func winFsStat(ctx context.Context, st *store.State, h *store.Host, p string, hash bool) (any, error) {
	sum := ""
	if hash {
		sum = "\nif (-not $f.PSIsContainer) { mark ('sha256=' + (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()) }"
	}
	script := winPath(p) + winCatch(`if (-not (Test-Path -LiteralPath $p)) { mark 'missing'; mark ('path=' + $p); exit 0 }
$f = Get-Item -LiteralPath $p -Force
mark ('json=' + (ConvertTo-Json -Compress -InputObject (`+winRow+`)))`+sum)
	m, err := winRun(ctx, st, h, p, script, 1<<20)
	if err != nil {
		return nil, err
	}
	if hasKey(m, "missing") {
		return map[string]any{"path": m["path"], "exists": false}, nil
	}
	var e winEntry
	if err := json.Unmarshal([]byte(m["json"]), &e); err != nil {
		return nil, out.Errf(out.ExitRemote, "COMMAND_FAILED", "run it again; if it happens again, report it at "+releaseSite+"/issues", "cannot read the file's details: %v", err)
	}
	r := map[string]any{"exists": true, "info": e.info()}
	if s := m["sha256"]; s != "" {
		r["sha256"] = s
	}
	return r, nil
}

// winReadFile reads up to limit bytes of a file on a Windows server; trunc
// says the file is longer. p comes back absolute.
func winReadFile(ctx context.Context, st *store.State, h *store.Host, p string, limit int64) (b []byte, abs string, trunc bool, err error) {
	script := winPath(p) + winCatch(`if (Test-Path -LiteralPath $p -PathType Container) { mark 'dir'; exit 0 }
if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { mark 'not-found'; exit 0 }
$fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
try {
  $n = [Math]::Min($fs.Length, [int64]`+strconv.FormatInt(limit, 10)+`)
  $buf = New-Object byte[] $n
  $r = 0
  while ($r -lt $n) { $k = $fs.Read($buf, $r, $n - $r); if ($k -le 0) { break }; $r += $k }
  mark ('size=' + $fs.Length)
  mark ('path=' + $p)
  mark ('data=' + [Convert]::ToBase64String($buf, 0, $r))
} finally { $fs.Close() }`)
	m, err := winRun(ctx, st, h, p, script, int(limit*4/3)+(1<<16))
	if err != nil {
		return nil, p, false, err
	}
	b, err = base64.StdEncoding.DecodeString(m["data"])
	if err != nil {
		return nil, p, false, out.Errf(out.ExitRemote, "READ_FAILED", "run it again; the output was cut (raise --max-output?)", "cannot read %s: %v", p, err)
	}
	size, _ := strconv.ParseInt(m["size"], 10, 64)
	return b, m["path"], size > int64(len(b)), nil
}

// winWriteOpts are the fs write and upload options Windows has.
type winWriteOpts struct {
	backup, mkdirs, noFollow bool
	validate                 string // PowerShell; %s is the new file's path
	intoDir                  string // upload: a folder at the path gets the file under this name
}

// winWriteScript writes the base64 lines on its input to a temporary file
// next to p, checks it (--validate), keeps a backup, then puts it in place
// in one step: [IO.File]::Replace keeps the old file's permissions (ACL).
func winWriteScript(p string, o winWriteOpts, now time.Time) string {
	var b strings.Builder
	b.WriteString(winPath(p))
	if o.intoDir != "" {
		b.WriteString("if ([IO.Directory]::Exists($p)) { $p = Join-Path $p " + sshx.PSQ(o.intoDir) + " }\n")
	}
	b.WriteString(`$dir = [IO.Path]::GetDirectoryName($p)
if ([IO.Directory]::Exists($p)) { mark 'dir'; exit 0 }
if (-not [IO.Directory]::Exists($dir)) { if ($` + strconv.FormatBool(o.mkdirs) + `) { [void][IO.Directory]::CreateDirectory($dir) } else { mark ('no-dir=' + $dir); exit 0 } }
$exists = [IO.File]::Exists($p)
`)
	if o.noFollow {
		b.WriteString("if ($exists -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { mark 'symlink'; exit 0 }\n")
	}
	body := `$tmp = Join-Path $dir ('.komando-' + [guid]::NewGuid().ToString('N') + '.tmp')
$sha = [Security.Cryptography.SHA256]::Create()
$n = 0
try {
  $out = [IO.File]::Open($tmp, 'CreateNew', 'Write', 'None')
  try {
    while ($null -ne ($l = [Console]::In.ReadLine())) {
      if ($l.Length -eq 0) { continue }
      $d = [Convert]::FromBase64String($l)
      $out.Write($d, 0, $d.Length); [void]$sha.TransformBlock($d, 0, $d.Length, $null, 0); $n += $d.Length
    }
  } finally { $out.Close() }
  [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
`
	if o.validate != "" {
		// in a PowerShell of its own, so its `exit` ends only the check
		body += "  $v = " + sshx.PSQ(o.validate) + ".Replace('%s', \"'\" + $tmp.Replace(\"'\", \"''\") + \"'\")\n" +
			"  $exe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName\n" +
			"  & $exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($v)))\n" +
			"  if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath $tmp -Force; mark 'invalid'; exit 0 }\n"
	}
	if o.backup {
		ts := now.UTC().Format(backupStamp)
		body += `  if ($exists) {
    $bak = $p + '.bak'
    if (Test-Path -LiteralPath $bak) { $s0 = $p + '.bak.` + ts + `'; $bak = $s0; $i = 2; while (Test-Path -LiteralPath $bak) { $bak = $s0 + '-' + $i; $i++ } }
    [IO.File]::Copy($p, $bak, $false)
    mark ('backup=' + $bak)
  }
`
	}
	body += `  if ($exists) { [IO.File]::Replace($tmp, $p, [NullString]::Value) } else { [IO.File]::Move($tmp, $p) }
} catch { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }; throw }
mark ('path=' + $p)
mark ('bytes=' + $n)
mark ('replaced=' + $exists)
mark ('sha256=' + ([BitConverter]::ToString($sha.Hash) -replace '-', '').ToLower())`
	b.WriteString(winCatch(body))
	return b.String()
}

// winWrite writes src to p on a Windows server (fs write, upload).
func winWrite(ctx context.Context, c *sshx.Client, p string, src io.Reader, o winWriteOpts) (map[string]string, error) {
	var stdout strings.Builder
	code, stderr, err := sshx.RunPS(ctx, c, winWriteScript(p, o, time.Now()), &b64Lines{r: src}, &stdout)
	if err != nil {
		return nil, err
	}
	m := winMarkers(stdout.String())
	if hasKey(m, "invalid") {
		return m, validateFailed(stderr)
	}
	if e := winMarkerErr(p, m); e != nil {
		return m, e
	}
	if code != 0 || m["sha256"] == "" {
		return m, out.Errf(out.ExitRemote, "WRITE_FAILED", "the file was not changed; read the message", "cannot write %s: %s", p, dash(strings.TrimSpace(stderr)))
	}
	return m, nil
}

// b64Lines reads r as base64 lines (48 KiB of data each).
type b64Lines struct {
	r   io.Reader
	buf []byte
	eof bool
}

func (l *b64Lines) Read(p []byte) (int, error) {
	for len(l.buf) == 0 {
		if l.eof {
			return 0, io.EOF
		}
		chunk := make([]byte, 48<<10)
		n, err := io.ReadFull(l.r, chunk)
		if n > 0 {
			l.buf = append([]byte(base64.StdEncoding.EncodeToString(chunk[:n])), '\n')
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			l.eof = true
		} else if err != nil {
			return 0, err
		}
	}
	n := copy(p, l.buf)
	l.buf = l.buf[n:]
	return n, nil
}

// winBase is the last part of a Windows or Unix path.
func winBase(p string) string {
	p = strings.TrimRight(p, `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// printed prints a command's result, or returns its error.
func printed(command string) func(any, error) error {
	return func(res any, err error) error {
		if err != nil {
			return err
		}
		out.P.Print(command, res, nil)
		return nil
	}
}

// winFsCat is fs cat on a Windows server.
func winFsCat(ctx context.Context, st *store.State, h *store.Host, p string, sudo bool, maxBytes int64, head, tail int, numbered bool) (any, error) {
	if sudo {
		return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED", "Windows has no sudo: log in as a user that may read the file", "--sudo does not work on Windows servers")
	}
	b, abs, trunc, err := winReadFile(ctx, st, h, p, maxBytes)
	if err != nil {
		return nil, err
	}
	return catContent(h.Name, abs, b, trunc, head, tail, numbered)
}

// winFsWrite is fs write on a Windows server, after the content was read
// and checked for [hidden] values: the same safety steps, then
// winWrite. --append and --if-changed read the file first, as on Linux.
func winFsWrite(ctx context.Context, st *store.State, h *store.Host, p string, data []byte, o writeOpts, appendMode, ifChanged bool) error {
	if o.sudo || o.mode != "" || o.owner != "" {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED", "Windows has no sudo or file modes: leave --sudo, --mode and --owner out; the new file keeps the old one's permissions (ACL)",
			"--sudo, --mode and --owner do not work on Windows servers")
	}
	if err := checkValidate(o.validate); err != nil {
		return err
	}
	if err := guard(st, []*store.Host{h}, o.validate, true); err != nil {
		return err
	}
	data, err := expandSecretRefsBytes(data, h.Name+":"+p)
	if err != nil {
		return err
	}
	var old []byte
	exists := true
	if appendMode || ifChanged || g.dryRun {
		var trunc bool
		old, _, trunc, err = winReadFile(ctx, st, h, p, 64<<20)
		switch {
		case err != nil && toErr(err).Code == "PATH_NOT_FOUND":
			old, exists, err = nil, false, nil
		case err != nil:
			return err
		case trunc && appendMode:
			return out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "append to it with exec instead, e.g. `Add-Content FILE`", "the file is larger than 64MiB, the most fs write --append reads")
		}
	}
	if appendMode {
		data = append(old, data...)
	}
	if g.dryRun {
		res := fsChange{"host": h.Name, "path": p, "bytes": len(data), "append": appendMode, "would_change": !exists || !sameForAgent(old, data)}
		if !exists {
			res["exists"] = false
		}
		if utf8Text(old) && utf8Text(data) {
			res["diff"] = unifiedDiff(string(old), string(data), 3)
		}
		out.P.Print("fs.write", res, nil)
		return nil
	}
	if ifChanged && exists && sameForAgent(old, data) {
		out.P.Print("fs.write", fsChange{"path": p, "changed": false}, nil)
		return nil
	}
	var m map[string]string
	err = withClient(allowWindows(ctx), st, h, func(c *sshx.Client) error {
		m, err = winWrite(ctx, c, p, bytes.NewReader(data), winWriteOpts{backup: o.backup, mkdirs: o.mkdirs, noFollow: o.noFollow, validate: o.validate})
		return err
	})
	audit(st, "fs.write", []string{h.Name}, "", err == nil, map[string]any{"path": p})
	if err != nil {
		return err
	}
	res := fsChange{"path": m["path"], "bytes": atoi64(m["bytes"]), "sha256": m["sha256"], "changed": true}
	if b := m["backup"]; b != "" {
		res["backup"] = b
	}
	if out.P.Mask && out.P.View(string(data)).Text != string(data) {
		delete(res, "sha256") // see fs replace
	}
	out.P.Print("fs.write", res, nil)
	return nil
}

func utf8Text(b []byte) bool { return utf8.Valid(b) && !bytes.ContainsRune(b, 0) }
