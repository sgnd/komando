package execsession

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// Each shape of run.ps1 and watch.ps1 parses as Windows PowerShell 5.1
// and uses no .NET beyond the allowed calls (A-590-1).
func TestRunPSParses(t *testing.T) {
	for name, run := range map[string][]byte{
		"no timeout": RunPS(1<<30, 0),
		"timeout":    RunPS(1<<30, 90*time.Second),
		"watch":      WatchPS(90 * time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			s := strings.TrimPrefix(string(run), bom)
			if !strings.HasPrefix(string(run), bom) {
				t.Error("no byte order mark")
			}
			psParse(t, s)
			psOnlyAllowed(t, s)
		})
	}
}

// run.ps1 holds no value: only the cap and the timeout, as numbers. It
// waits for .go, pumps the command's output and errors through ONE
// capped pipeline into out.log (A-C324-11), writes exit through exit.tmp
// unless the run was stopped, and deletes the input.
func TestRunPSText(t *testing.T) {
	r := string(RunPS(12345, 0))
	for _, want := range []string{
		"$ks_d = $PSScriptRoot",
		"$ErrorActionPreference = 'Continue'",
		"Join-Path $ks_d '.go'",
		"& cmd.exe /d /c $ks_cmd 2>&1 | ks_capped 12345 | Out-File -FilePath (Join-Path $ks_d 'out.log') -Encoding UTF8 -Append",
		"if (-not (Test-Path -LiteralPath (Join-Path $ks_d 'killed'))) {",
		"Move-Item -LiteralPath (Join-Path $ks_d 'exit.tmp') -Destination (Join-Path $ks_d 'exit') -Force",
		"Remove-Item -LiteralPath $ks_in -Force",
		"' < \"' + $ks_in + '\"'",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("run.ps1 has no %q", want)
		}
	}
	if strings.Count(r, "Out-File") != 1 || strings.Contains(r, "Add-Content") {
		t.Error("run.ps1 writes out.log other than through one Out-File")
	}
	if strings.Contains(r, "watch.ps1") {
		t.Error("run.ps1 without a timeout starts the watcher")
	}
	if r := string(RunPS(1, 90*time.Second)); !strings.Contains(r, "'watch.ps1'") || !strings.Contains(r, "$PID") {
		t.Error("run.ps1 with a timeout does not start the watcher with its own PID")
	}
	at := func(s string) int { return strings.Index(r, s) }
	if !(at("'.go'") < at("& cmd.exe") && at("& cmd.exe") < at("$ks_c = $LASTEXITCODE") && at("$ks_c = $LASTEXITCODE") < at("'exit.tmp'")) {
		t.Error("run.ps1 does its steps out of order")
	}
}

// watch.ps1 stops when exit appears; at the deadline it notes the
// timeout and ends the run's whole tree.
func TestWatchPSText(t *testing.T) {
	w := string(WatchPS(90 * time.Second))
	for _, want := range []string{"AddSeconds(90)", "Join-Path $ks_d 'exit'", "'TERM timeout'", "& taskkill.exe /PID $run /T /F"} {
		if !strings.Contains(w, want) {
			t.Errorf("watch.ps1 has no %q", want)
		}
	}
	if w := string(WatchPS(1500 * time.Millisecond)); !strings.Contains(w, "AddSeconds(2)") {
		t.Error("a timeout is not rounded up to whole seconds")
	}
}

// The pump keeps lines while they fit under the cap (UTF-8 bytes plus
// CRLF, as Out-File writes them), drops every line after the first that
// does not, and writes the bytes it dropped to truncated (A-C324-4).
func TestCappedPump(t *testing.T) {
	dir := t.TempDir()
	script := strings.TrimPrefix(string(RunPS(1, 0)), bom)
	fn := script[strings.Index(script, "function ks_capped"):strings.Index(script, "# end ks_capped")]
	got := psOutput(t, "$ks_d = '"+strings.ReplaceAll(dir, "'", "''")+"'\n"+fn+
		"@('abc', 'defg', 'x', 'é') | ks_capped 10 | ForEach-Object { Write-Output ('kept ' + $_) }\n")
	if got != "kept abc\n" {
		t.Errorf("kept %q", got)
	}
	b, err := os.ReadFile(filepath.Join(dir, "truncated"))
	// defg 4+2, x 1+2, é 2+2 bytes dropped
	if err != nil || string(b) != "13" {
		t.Errorf("truncated %q, %v; want 13", b, err)
	}
}

// The start script, after the files, starts run.ps1 through CIM (not as
// a child of the transport's shell), with only its path on the command
// line, prints the process's facts between markers, and only then lets
// the run go.
func TestStartScriptPSLaunch(t *testing.T) {
	s := psStart()
	s.Timeout = time.Minute
	script, input, err := StartScriptPS(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = ('powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"' + $ks_run + '\"'); CurrentDirectory = $ks_d }",
		"Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $ks_pid)",
		"Write-Output ('facts-begin ' + $ks_id)",
		"ks_put 'run.ps1'", "ks_put 'watch.ps1'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the start script has no %q", want)
		}
	}
	at := func(x string) int { return strings.Index(script, x) }
	if !(at("'out.log'") < at("Invoke-CimMethod") && at("Invoke-CimMethod") < at("'facts-end '") && at("'facts-end '") < at("Join-Path $ks_d '.go'")) {
		t.Error("the start script launches before its files, or lets the run go before its facts")
	}
	if n := strings.Count(string(input), "\n"); n != 5 {
		t.Errorf("%d input lines, want cmd.ps1, env, in, run.ps1, watch.ps1", n)
	}
	s.Timeout = 0
	script, _, _ = StartScriptPS(s)
	if strings.Contains(script, "watch.ps1") {
		t.Error("a start without a timeout writes watch.ps1")
	}
}

func psFacts(pid, created, image, cmdline string) string {
	return "noise\nfacts-begin " + testID + "\npid " + pid + "\ncreated " + created + "\nimage " + image + "\ncmdline " + cmdline + "\nfacts-end " + testID + "\n"
}

const goodCmdline = `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\a\AppData\Local\komando\sessions\` + testID + `\run.ps1"`

func TestParseFactsPS(t *testing.T) {
	f, err := ParseFactsPS(psFacts("4242", "2026-11-25T10:00:00.1234567Z", "powershell.exe", goodCmdline), testID)
	if err != nil {
		t.Fatal(err)
	}
	if f.PID != 4242 || f.Start != "cim 2026-11-25T10:00:00.1234567Z" || f.Image != "powershell.exe" || f.CmdLine != goodCmdline {
		t.Errorf("facts %+v", f)
	}
	bad := map[string]string{
		"pid 4 (System)":   psFacts("4", "2026-11-25T10:00:00Z", "powershell.exe", goodCmdline),
		"pid not a number": psFacts("x", "2026-11-25T10:00:00Z", "powershell.exe", goodCmdline),
		"bad created":      psFacts("4242", "yesterday", "powershell.exe", goodCmdline),
		"other image":      psFacts("4242", "2026-11-25T10:00:00Z", "cmd.exe", goodCmdline),
		"other session":    psFacts("4242", "2026-11-25T10:00:00Z", "powershell.exe", strings.Replace(goodCmdline, testID, strings.Repeat("a", 52), 1)),
		"no end marker":    strings.Replace(psFacts("4242", "2026-11-25T10:00:00Z", "powershell.exe", goodCmdline), "facts-end", "x", 1),
		"doubled inside":   strings.Replace(psFacts("4242", "2026-11-25T10:00:00Z", "powershell.exe", goodCmdline), "pid 4242\n", "pid 4242\npid 4243\n", 1),
		"other ID":         strings.ReplaceAll(psFacts("4242", "2026-11-25T10:00:00Z", "powershell.exe", goodCmdline), "facts-begin "+testID, "facts-begin x"),
		"missing cmdline":  strings.Replace(psFacts("4242", "2026-11-25T10:00:00Z", "powershell.exe", goodCmdline), "cmdline ", "x ", 1),
	}
	for name, s := range bad {
		t.Run(name, func(t *testing.T) {
			if f, err := ParseFactsPS(s, testID); err == nil {
				t.Errorf("accepted %+v", f)
			}
		})
	}
}

// A start is done when its facts are read; a start that printed no facts
// is a failed start, and when the facts cannot be read the run never
// went (no .go).
func TestReadStartPSFacts(t *testing.T) {
	ok := psFacts("4242", "2026-11-25T10:00:00Z", "PowerShell.EXE", goodCmdline)
	f, err := ReadStartPS("web1", 0, ok, "", testID)
	if err != nil || f.PID != 4242 {
		t.Fatalf("%+v, %v", f, err)
	}
	var e *out.Error
	if _, err := ReadStartPS("web1", 0, "facts-begin "+testID+"\n", "", testID); !errors.As(err, &e) || e.Code != "SESSION_START_FAILED" {
		t.Errorf("half the facts: %v", err)
	}
}
