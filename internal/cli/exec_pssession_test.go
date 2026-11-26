package cli

import (
	"encoding/base64"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/execsession"
	"github.com/sgnd/komando/internal/store"
)

// winSessionServer answers exec's PowerShell session scripts as a Windows
// server would. Each call is told apart by the script in the bootstrap's
// first input line: the start (sweep markers), a read, a stop, a remove.
type winSessionServer struct {
	*fakeServer
	swept string // an old session ID the start's sweep reports (with CRLF, as Windows prints)
	begin int    // the start's exit (0: it runs)
	log   string // out.log
	ended bool
	stop  int // the stop's exit
}

var (
	psID       = regexp.MustCompile(`\$ks_id = '([a-z2-7]{52})'`)
	psFrom     = regexp.MustCompile(`\$ks_from = ([0-9]+)`)
	psCmdline  = `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File "C:\Users\u\AppData\Local\komando\sessions\%s\run.ps1"`
	psLineHead = regexp.MustCompile(`^[^\n]*`)
)

func startWinSessionServer(t *testing.T, log string, ended bool) *winSessionServer {
	t.Helper()
	sessionsOn = true
	t.Cleanup(func() { sessionsOn = false })
	s := &winSessionServer{fakeServer: startWindowsServer(t), log: log, ended: ended}
	s.answerIn = func(cmd, stdin string) (string, int) {
		script := decodeFirstLine(stdin)
		m := psID.FindStringSubmatch(script)
		if m == nil {
			return "direct\n", 0
		}
		id := m[1]
		switch {
		case strings.Contains(script, "sweep-begin"):
			if s.begin != 0 {
				return "sweep-begin " + id + "\nsweep-end " + id + "\n", s.begin
			}
			sweep := "sweep-begin " + id + "\r\n"
			if s.swept != "" {
				sweep += "swept " + s.swept + "\r\n"
			}
			sweep += "sweep-end " + id + "\r\n"
			return sweep + "facts-begin " + id + "\npid 4242\ncreated 2026-11-26T10:00:00.0000000Z\nimage powershell.exe\ncmdline " +
				strings.Replace(psCmdline, "%s", id, 1) + "\nfacts-end " + id + "\n", 0
		case strings.Contains(script, "read-begin"):
			from, _ := strconv.Atoi(psFrom.FindStringSubmatch(script)[1])
			head := "read-begin " + id + "\n"
			if s.ended {
				head += "exit 0\n"
			}
			rest := s.log[min(from, len(s.log)):]
			return head + "size " + strconv.Itoa(len(s.log)) + "\nread-end " + id + "\ndata " + base64.StdEncoding.EncodeToString([]byte(rest)) + "\n", 0
		case strings.Contains(script, "taskkill"):
			if s.stop != 0 {
				return "", s.stop
			}
			return "ended 4242\nended 4300\nstopped " + id + "\n", 0
		case strings.Contains(script, "rmdir"):
			return "", 0
		}
		return "direct\n", 0
	}
	return s
}

func decodeFirstLine(stdin string) string {
	line := psLineHead.FindString(stdin)
	b, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return ""
	}
	return string(b)
}

// kinds sorts the server's execs: start, read, stop, remove or other.
func (s *winSessionServer) kinds() []string {
	var k []string
	for _, e := range s.take() {
		script := decodeFirstLine(e.stdin)
		switch {
		case strings.Contains(script, "sweep-begin"):
			k = append(k, "start")
		case strings.Contains(script, "read-begin"):
			k = append(k, "read")
		case strings.Contains(script, "taskkill"):
			k = append(k, "stop")
		case strings.Contains(script, "rmdir"):
			k = append(k, "remove")
		default:
			k = append(k, "other")
		}
	}
	return k
}

// setHostEnv gives the Windows server "win" its own env.
func setHostEnv(t *testing.T, env map[string]string) {
	t.Helper()
	if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["win"].Env = env; return nil }); err != nil {
		t.Fatal(err)
	}
}

// W-wire 1: a plain exec on a Windows server runs in a session as on a
// Unix one: start, read, then the removal of a run read to its end by its
// starter; the record keeps the image and command line a stop checks.
func TestWindowsExecRunsInASession(t *testing.T) {
	srv := startWinSessionServer(t, "hello\r\n", true)
	first, res, err := runSession(t, "exec", "win", "--", "Get-Date")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := first["session"].(string)
	if execsession.CheckID(id) != nil || first["host"] != "win" {
		t.Fatalf("first line %v", first)
	}
	if r := res.Data.Results[0]; r.Session == nil || *r.Session != id || r.Stdout != "hello\r\n" || r.ExitCode != 0 {
		t.Fatalf("result %+v", r)
	}
	if k := srv.kinds(); !slices.Equal(k, []string{"start", "read", "remove"}) {
		t.Fatalf("calls %v", k)
	}
	if rt, _ := store.ReadRuntime(); rt.ExecSessions[id] != nil {
		t.Fatal("the record stayed after a full read")
	}
}

// The record of a run still going has what a stop checks again.
func TestWindowsExecRecordHoldsTheProcessFacts(t *testing.T) {
	startWinSessionServer(t, "step", false)
	first, _, _ := runSession(t, "exec", "win", "--wait", "0", "--", "Get-Date")
	id := sessionID(t, first)
	rt, _ := store.ReadRuntime()
	rec := rt.ExecSessions[id]
	if rec == nil || rec.Host != "win" || rec.PID != 4242 || rec.ProcStart != "cim 2026-11-26T10:00:00.0000000Z" ||
		rec.Image != "powershell.exe" || rec.CmdLine != strings.Replace(psCmdline, "%s", id, 1) || rec.Command != "Get-Date" {
		t.Fatalf("record %+v", rec)
	}
}

// Values travel as data: the script text holds the ID and the cap and
// nothing of the user's; the command, the env and the input are base64
// lines on the bootstrap's input.
func TestWindowsExecValuesAreData(t *testing.T) {
	srv := startWinSessionServer(t, "", true)
	setHostEnv(t, map[string]string{"KSZEBRA": "it's \"x\"", "N": "1"})
	const command, input = "Write-Output 'marker-cmd-7'", "marker-in-9\n"
	tmp := t.TempDir() + "/in.txt"
	writeFile(t, tmp, []byte(input))
	_ = captureOutput(t, func() error { return runRoot(t, "exec", "win", "--stdin-file", tmp, "--", command) })
	execs := srv.take()
	if len(execs) == 0 {
		t.Fatal("no call")
	}
	start := execs[0]
	script := decodeFirstLine(start.stdin)
	for _, bad := range []string{"marker-cmd-7", "marker-in-9", "it's", `"x"`, "KSZEBRA"} {
		if strings.Contains(script, bad) {
			t.Errorf("the start script holds %q", bad)
		}
	}
	lines := strings.Split(strings.TrimSuffix(start.stdin, "\n"), "\n")
	var files []string
	for _, l := range lines[1:] {
		b, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			t.Fatalf("an input line is not base64: %q", l)
		}
		files = append(files, string(b))
	}
	all := strings.Join(files, "\x00")
	for _, want := range []string{"marker-cmd-7", "marker-in-9", "KSZEBRA=" + base64.StdEncoding.EncodeToString([]byte(`it's "x"`))} {
		if !strings.Contains(all, want) {
			t.Errorf("the input lacks %q", want)
		}
	}
	if cmdFile := files[0]; strings.Contains(cmdFile, "it's") || !strings.Contains(cmdFile, "marker-cmd-7") || !strings.Contains(cmdFile, "$LASTEXITCODE") {
		t.Errorf("cmd.ps1 must hold the command with its trailer and no env value:\n%s", cmdFile)
	}
}

// With --dir the run starts there: the Set-Location line is part of the
// command cmd.ps1 runs, as in a plain Windows exec.
func TestWindowsExecKeepsTheWorkingFolder(t *testing.T) {
	srv := startWinSessionServer(t, "", true)
	_ = captureOutput(t, func() error { return runRoot(t, "exec", "win", "--dir", `C:\app`, "--", "Get-Date") })
	start := srv.take()[0]
	if cmdFile, _ := base64.StdEncoding.DecodeString(strings.Split(start.stdin, "\n")[1]); !strings.Contains(string(cmdFile), "Set-Location -LiteralPath 'C:\\app'") {
		t.Fatalf("cmd.ps1:\n%s", cmdFile)
	}
}

// A blocked start never falls back to a run without a session: nothing
// runs after it.
func TestWindowsExecStartDeniedNeverFallsBack(t *testing.T) {
	srv := startWinSessionServer(t, "", false)
	srv.begin = execsession.ExitDenied
	_, res, err := runSession(t, "exec", "win", "--", "Get-Date")
	if err == nil || res.Error.Code != "SESSION_START_DENIED" {
		t.Fatalf("got %v, %+v", err, res.Error)
	}
	if k := srv.kinds(); !slices.Equal(k, []string{"start"}) {
		t.Fatalf("calls %v", k)
	}
}

// No folder can be made: the command runs as a plain Windows exec in a
// new call, with session null and a warning.
func TestWindowsExecNoFolderRunsDirect(t *testing.T) {
	srv := startWinSessionServer(t, "", false)
	srv.begin = execsession.ExitNoFolder
	first, res, err := runSession(t, "exec", "win", "--", "Get-Date")
	if err != nil {
		t.Fatal(err)
	}
	execs := srv.take()
	if len(execs) != 2 || strings.Contains(decodeFirstLine(execs[1].stdin), "sweep-begin") || !strings.Contains(decodeFirstLine(execs[1].stdin), "Get-Date") {
		t.Fatalf("execs %+v", execs)
	}
	if v, ok := first["session"]; !ok || v != nil || res.Data.Results[0].Session != nil {
		t.Fatalf("first %v, result %+v", first, res.Data.Results[0])
	}
	if len(res.Meta.Warnings) != 1 || !strings.Contains(res.Meta.Warnings[0], "without a session") {
		t.Fatalf("warnings %v", res.Meta.Warnings)
	}
}

// With sessions off, no PowerShell session text is built or sent: the
// run is a plain Windows exec.
func TestWindowsExecSessionsOffSendsNoSessionText(t *testing.T) {
	srv := startWindowsServer(t)
	srv.answerIn = func(string, string) (string, int) { return "up\n", 0 }
	_ = captureOutput(t, func() error { return runRoot(t, "exec", "win", "--", "Get-Date") })
	execs := srv.take()
	if len(execs) != 1 {
		t.Fatalf("execs %+v", execs)
	}
	for _, e := range execs {
		for _, bad := range []string{"sweep-begin", "ks_put", "run.ps1", "komando\\sessions"} {
			if strings.Contains(e.stdin, bad) || strings.Contains(decodeFirstLine(e.stdin), bad) {
				t.Errorf("session text %q was sent with sessions off", bad)
			}
		}
	}
}

// --attach reads a Windows session through the Windows read, from the
// offset, and shows its output.
func TestWindowsAttachReads(t *testing.T) {
	srv := startWinSessionServer(t, "abcdef", true)
	first, _, _ := runSession(t, "exec", "win", "--wait", "0", "--", "Get-Date")
	id := sessionID(t, first)
	srv.take()
	_, res, err := runSession(t, "exec", "win", "--attach", id, "--offset", "3")
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Data.Results[0]; r.Stdout != "def" {
		t.Fatalf("result %+v", r)
	}
	if k := srv.kinds(); k[0] != "read" {
		t.Fatalf("calls %v", k)
	}
}

// --stop ends the run from the record alone: the stop script is built
// from the record, the answer lists the PIDs and the limit.
func TestWindowsStop(t *testing.T) {
	srv := startWinSessionServer(t, "", false)
	first, _, _ := runSession(t, "exec", "win", "--wait", "0", "--", "Get-Date")
	id := sessionID(t, first)
	srv.take()
	out := captureOutput(t, func() error { return runRoot(t, "exec", "win", "--attach", id, "--stop") })
	if k := srv.kinds(); !slices.Equal(k, []string{"stop"}) {
		t.Fatalf("calls %v", k)
	}
	for _, want := range []string{`"pids":[4242,4300]`, execsession.StopLimitPS, `"session":"` + id + `"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"signal"`) {
		t.Errorf("Windows has no signals; output names one:\n%s", out)
	}
	if rt, _ := store.ReadRuntime(); rt.ExecSessions[id] == nil {
		t.Error("a stop keeps the record: the removal drops it")
	}
}

// --signal is refused before any connection, whatever the signal.
func TestWindowsStopRefusesASignal(t *testing.T) {
	srv := startWinSessionServer(t, "", false)
	first, _, _ := runSession(t, "exec", "win", "--wait", "0", "--", "Get-Date")
	id := sessionID(t, first)
	srv.take()
	for _, sig := range []string{"KILL", "TERM"} {
		if code := runCode(t, "exec", "win", "--attach", id, "--stop", "--signal", sig); code != "NOT_SUPPORTED" {
			t.Errorf("--signal %s: code %q", sig, code)
		}
	}
	if e := srv.take(); len(e) != 0 {
		t.Fatalf("a refused signal reached the server: %+v", e)
	}
}

// A stop whose process is gone says so, with the Windows hints.
func TestWindowsStopMissingProcess(t *testing.T) {
	srv := startWinSessionServer(t, "", false)
	first, _, _ := runSession(t, "exec", "win", "--wait", "0", "--", "Get-Date")
	id := sessionID(t, first)
	srv.stop = execsession.ExitNotRunning
	if code := runCode(t, "exec", "win", "--attach", id, "--stop"); code != "SESSION_PROCESS_MISSING" {
		t.Fatalf("code %q", code)
	}
}

// Any other stop failure does not point to sudo, which Windows has not.
func TestWindowsStopFailureHintHasNoSudo(t *testing.T) {
	srv := startWinSessionServer(t, "", false)
	first, _, _ := runSession(t, "exec", "win", "--wait", "0", "--", "Get-Date")
	id := sessionID(t, first)
	srv.stop = 1
	var hint string
	_ = captureOutput(t, func() error {
		err := runRoot(t, "exec", "win", "--attach", id, "--stop")
		hint = toErr(err).Hint
		return nil
	})
	if hint == "" || strings.Contains(hint, "sudo") {
		t.Fatalf("hint %q", hint)
	}
}

// --remove deletes through the Windows remove and drops the record.
func TestWindowsRemove(t *testing.T) {
	srv := startWinSessionServer(t, "", true)
	first, _, _ := runSession(t, "exec", "win", "--wait", "0", "--", "Get-Date")
	id := sessionID(t, first)
	srv.take()
	if err := runRoot(t, "exec", "win", "--attach", id, "--remove"); err != nil {
		t.Fatal(err)
	}
	if k := srv.kinds(); !slices.Equal(k, []string{"remove"}) {
		t.Fatalf("calls %v", k)
	}
	if rt, _ := store.ReadRuntime(); rt.ExecSessions[id] != nil {
		t.Error("the record stayed after the removal")
	}
}

// A change to a Windows session goes through the gate as on Unix: the
// audit log names the stop and the remove.
func TestWindowsStopAndRemoveAreAudited(t *testing.T) {
	srv := startWinSessionServer(t, "", false)
	first, _, _ := runSession(t, "exec", "win", "--wait", "0", "--", "Get-Date")
	id := sessionID(t, first)
	srv.take()
	_ = captureOutput(t, func() error { return runRoot(t, "exec", "win", "--attach", id, "--stop") })
	srv.ended = true
	_ = captureOutput(t, func() error { return runRoot(t, "exec", "win", "--attach", id, "--remove") })
	log := auditText(t)
	for _, want := range []string{`"stop":"`, `"remove":true`} {
		if !strings.Contains(log, want) {
			t.Errorf("the audit log lacks %s", want)
		}
	}
}

// A dry run of a Windows stop sends nothing and prints the script.
func TestWindowsStopDryRunSendsNothing(t *testing.T) {
	srv := startWinSessionServer(t, "", false)
	first, _, _ := runSession(t, "exec", "win", "--wait", "0", "--", "Get-Date")
	id := sessionID(t, first)
	srv.take()
	out := captureOutput(t, func() error { return runRoot(t, "--dry-run", "exec", "win", "--attach", id, "--stop") })
	if e := srv.take(); len(e) != 0 || !strings.Contains(out, "would_run") {
		t.Fatalf("execs %+v, output %s", e, out)
	}
}

// sessionID is the session a run's first line names; none fails the test.
func sessionID(t *testing.T, first map[string]any) string {
	t.Helper()
	id, _ := first["session"].(string)
	if execsession.CheckID(id) != nil {
		t.Fatalf("the first line names no session: %v", first)
	}
	return id
}

// The start's sweep reports in CRLF lines on Windows: the records of what
// it swept are dropped all the same.
func TestWindowsExecForgetsWhatTheSweepRemoved(t *testing.T) {
	srv := startWinSessionServer(t, "", true)
	old := strings.Repeat("b", 52)
	rec := &store.ExecSession{ID: old, Host: "win", Command: "x", PID: 7, Actor: "someone"}
	if err := store.UpdateRuntime(store.Save(), func(s *store.State) error { s.ExecSessions[old] = rec; return nil }); err != nil {
		t.Fatal(err)
	}
	srv.swept = old
	if _, _, err := runSession(t, "exec", "win", "--", "Get-Date"); err != nil {
		t.Fatal(err)
	}
	if rt, _ := store.ReadRuntime(); rt.ExecSessions[old] != nil {
		t.Error("the record of a swept session stayed")
	}
}
