package execsession

import (
	"errors"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// psRecord is a Windows session's record as C448's start leaves it.
func psRecord() *store.ExecSession {
	return &store.ExecSession{ID: testID, Host: "win1", PID: 4242, ProcStart: "cim 2026-11-25T10:00:00.1234567Z",
		Image: "powershell.exe", CmdLine: goodCmdline}
}

// The stop is built from the record alone (A-C324-1); a record without a
// usable PID, creation date, image or command line builds nothing.
func TestStopScriptPSChecksTheRecord(t *testing.T) {
	bad := map[string]func(*store.ExecSession){
		"pid 4":         func(r *store.ExecSession) { r.PID = 4 },
		"unix start":    func(r *store.ExecSession) { r.ProcStart = "proc 99" },
		"bad date":      func(r *store.ExecSession) { r.ProcStart = "cim yesterday" },
		"other image":   func(r *store.ExecSession) { r.Image = "cmd.exe" },
		"other cmdline": func(r *store.ExecSession) { r.CmdLine = "powershell.exe -File x.ps1" },
		"bad ID":        func(r *store.ExecSession) { r.ID = "../x" },
	}
	for name, f := range bad {
		t.Run(name, func(t *testing.T) {
			r := psRecord()
			f(r)
			if _, err := StopScriptPS(r); err == nil {
				t.Error("made a script")
			}
		})
	}
}

// The stop checks the live process's creation date, image and command
// line against the record (A-C324-8), lists the tree it ends, ends it
// with taskkill /T /F, and only then notes the stop.
func TestStopScriptPSText(t *testing.T) {
	s, err := StopScriptPS(psRecord())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"$ks_pid = 4242", "$ks_created = '2026-11-25T10:00:00.1234567Z'",
		"Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $ks_pid)",
		"if ($ks_q.Count -ne 1) { exit 92 }",
		"if ($ks_q[0].CreationDate.ToUniversalTime().ToString('o') -cne $ks_created",
		"$ks_q[0].Name -ne 'powershell.exe'",
		"$ks_q[0].CommandLine -cne $ks_cmdline",
		"$null = & taskkill.exe /PID $ks_pid /T /F",
		"'killed'", "-Value 'stop'",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the stop script has no %q", want)
		}
	}
	at := func(x string) int { return strings.Index(s, x) }
	if !(at("-cne $ks_cmdline") < at("taskkill.exe") && at("ParentProcessId") < at("taskkill.exe") && at("taskkill.exe") < at("-Value 'stop'")) {
		t.Error("the stop script kills before its checks or its list, or notes the stop first")
	}
	if strings.Contains(s, "Get-Content") {
		t.Error("the stop reads a file on the server: it trusts only the record")
	}
	psOnlyAllowed(t, s)
	psParse(t, s)
}

func TestParseStopPS(t *testing.T) {
	pids, err := ParseStopPS("noise\r\nended 4242\r\nended 4300\r\nstopped "+testID+"\r\n", testID)
	if err != nil || len(pids) != 2 || pids[0] != 4242 || pids[1] != 4300 {
		t.Fatalf("%v, %v", pids, err)
	}
	if _, err := ParseStopPS("ended 4242\n", testID); err == nil {
		t.Error("a stop without its end line counts")
	}
	if _, err := ParseStopPS("ended x\nstopped "+testID+"\n", testID); err == nil {
		t.Error("a bad PID counts")
	}
	if _, err := ParseStopPS("ended 4\nstopped "+testID+"\n", testID); err == nil {
		t.Error("PID 4 (System) counts")
	}
}

// Windows has no signals: --signal is refused before any connection.
func TestSignalOnWindows(t *testing.T) {
	err := SignalPS("TERM")
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "NOT_SUPPORTED" || e.Exit != out.ExitUsage || !strings.Contains(e.Hint, "--stop") {
		t.Errorf("got %v", err)
	}
	if SignalPS("") != nil {
		t.Error("a stop without --signal is refused")
	}
}

// Remove and the sweep delete a session folder only by rmdir (which
// never follows a junction inside it), only below the resolved sessions
// folder, only a folder named like an ID, not a reparse point, owned by
// the login user, and only an ended run.
func TestRemoveScriptPSText(t *testing.T) {
	s, err := RemoveScriptPS(testID, psRecord())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveScriptPS("../x", nil); err == nil {
		t.Error("a bad ID made a script")
	}
	for _, want := range []string{
		"$ks_rm = 'rmdir /s /q \"' + $ks_d + '\"'", "& cmd.exe /d /c $ks_rm",
		"if ($ks_unsafe) { exit 90 }",
		"if (-not (ks_gone 4242 '2026-11-25T10:00:00.1234567Z' $ks_cmdline)) { exit 92 }",
		"(ks_owner (Get-Acl -LiteralPath $p).Sddl) -ne $ks_sid",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the remove script has no %q", want)
		}
	}
	if strings.Contains(s, "Remove-Item") {
		t.Error("the remove script deletes with Remove-Item, which may follow a junction")
	}
	psSafeBaseChecked(t, "remove", s)
	psOnlyAllowed(t, s)
	psParse(t, s)
	if s, _ := RemoveScriptPS(testID, nil); !strings.Contains(s, "if (-not (ks_ended $ks_d)) { exit 92 }") {
		t.Error("without a record, only the files on the server say the run ended")
	}
}

func TestSweepPSText(t *testing.T) {
	other := *psRecord()
	other.ID = strings.Repeat("b", 52)
	other.CmdLine = strings.Replace(goodCmdline, testID, other.ID, 1)
	s := SweepPS([]*store.ExecSession{psRecord(), &other, {ID: "../x"}})
	for _, want := range []string{
		"-cmatch '^[a-z2-7]{52}$'", "'ReparsePoint'", "604800",
		"$ks_rm = 'rmdir /s /q \"' + $d + '\"'", "& cmd.exe /d /c $ks_rm",
		"Write-Output ('swept ' + $n)",
		"'" + testID + "' { if (-not (ks_gone 4242", "'" + other.ID + "' { if (-not (ks_gone 4242", "{ $skip = $true }", "if ($skip) { continue }",
		"New-Item -ItemType File -Path (Join-Path $d 'lost')",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the sweep has no %q", want)
		}
	}
	psSafeBaseChecked(t, "sweep", s)
	if strings.Contains(s, "../x") || strings.Contains(s, "Remove-Item") {
		t.Error("the sweep holds a bad record ID or deletes with Remove-Item")
	}
	psOnlyAllowed(t, s)
	psParse(t, s)
}

// A starting Windows exec sweeps first, between markers that carry the
// new session's ID, so Swept reads only its own lines.
func TestBeginScriptPS(t *testing.T) {
	s, _, err := BeginScriptPS(psStart(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, e := strings.Index(s, "Write-Output 'sweep-begin "+testID+"'"), strings.Index(s, "Write-Output 'sweep-end "+testID+"'")
	if b != 0 || e < b || e > strings.Index(s, "$ks_cap") {
		t.Error("the sweep is not first and between its markers")
	}
	psParse(t, s)
}

// A-450-1: the folder reaches cmd.exe only inside one /c string, in quotes,
// and only when %LOCALAPPDATA% holds nothing outside letters, digits,
// space and _ . - \ : a user name with & ^ ( ) or | would make cmd.exe run
// a different path first. The bare argument is gone.
func psSafeBaseChecked(t *testing.T, what, script string) {
	t.Helper()
	if !strings.Contains(script, `-cnotmatch '^[A-Za-z]:\\[A-Za-z0-9 _.\\-]+\z'`) {
		t.Errorf("the %s script does not refuse a %%LOCALAPPDATA%% outside [A-Za-z0-9 _.\\-]", what)
	}
	// .NET's $ also matches before a trailing newline: the allowlist ends in \z
	if strings.Contains(script, `_.\\-]+$'`) {
		t.Errorf("the %s script ends its allowlist with $, which lets a trailing newline pass: use \\z", what)
	}
	for _, bare := range []string{"rmdir /s /q $ks_d", "rmdir /s /q $d"} {
		if strings.Contains(script, bare) {
			t.Errorf("the %s script hands the folder to cmd.exe as a bare argument (%s)", what, bare)
		}
	}
}

// The start refuses the same base with the same allowlist (the fallback is
// a run without a session, never a different folder).
func TestStartScriptPSRefusesMetaPath(t *testing.T) {
	script, _, err := StartScriptPS(psStart())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, `-cnotmatch '^[A-Za-z]:\\[A-Za-z0-9 _.\\-]+\z') { Write-Output 'unsafe-path'; ks_fail 91 }`) {
		t.Error("the start does not refuse a %LOCALAPPDATA% outside the allowlist")
	}
	_, err = ReadStartPS("web1", ExitNoFolder, "unsafe-path\n", "", testID)
	if err == nil || !strings.Contains(err.Error(), "& ^ ( ) |") {
		t.Errorf("the message must name what is refused: %v", err)
	}
}
