package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// startWindowsServer is startFakeServer with a Windows server "win" on the
// same fake SSH server, and nothing protected (the hosts are one server).
func startWindowsServer(t *testing.T) *fakeServer {
	t.Helper()
	srv := startFakeServer(t)
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["prod"].Protected = false
		w := *st.Hosts["dev"]
		w.Name, w.OS = "win", store.OSWindows
		st.Hosts["win"] = &w
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return srv
}

// psScript is the PowerShell script an exec sent: the bootstrap's first
// input line, decoded.
func psScript(t *testing.T, e fakeExec) string {
	t.Helper()
	if e.cmd != sshx.PSCommandLine {
		t.Fatalf("command %q is not the PowerShell bootstrap", e.cmd)
	}
	line, _, _ := strings.Cut(e.stdin, "\n")
	b, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		t.Fatalf("first input line is not base64: %q", line)
	}
	return string(b)
}

func errCode(err error) string {
	if err == nil {
		return ""
	}
	return toErr(err).Code
}

// runCode runs komando and gives its error code: the returned one, or for
// fleet commands (which print it and return the exit code) the printed one.
func runCode(t *testing.T, args ...string) string {
	t.Helper()
	var err error
	got := captureOutput(t, func() error { err = runRoot(t, args...); return err })
	if e, ok := err.(*out.Error); ok && e.Code != "" {
		return e.Code
	}
	if i := strings.Index(got, `"code":"`); i >= 0 {
		rest := got[i+8:]
		return rest[:strings.IndexByte(rest, '"')]
	}
	return errCode(err)
}

func TestWindowsRefusals(t *testing.T) {
	startWindowsServer(t)
	cases := map[string][]string{
		"NOT_SUPPORTED":       {"logs", "win"},
		"MIXED_OS":            {"exec", "all", "--", "hostname"},
		"POLICY_BLOCKED":      {"exec", "win", "--", `Remove-Item -Recurse -Force C:\`},
		"READ_ONLY_VIOLATION": {"exec", "win", "--read-only", "--", `Get-Item C:\x | Remove-Item`},
	}
	for code, args := range cases {
		if got := runCode(t, args...); got != code {
			t.Errorf("%v: got %s, want %s", args, got, code)
		}
	}
	for _, args := range [][]string{
		{"docker", "ps", "win"},
		{"fs", "rm", "win", `C:\x`},
		{"pkg", "upgrade", "win"},
		{"exec", "win", "--sudo", "--", "Get-Date"},
		{"exec", "win", "--pty", "--", "Get-Date"},
		{"svc", "reload", "win", "W3SVC"},
		{"fs", "write", "win", `C:\x`, "--content", "a", "--sudo"},
		{"upload", "win", "./windows_test.go", `C:\x`, "--mode", "0644"},
	} {
		if got := runCode(t, args...); got != "NOT_SUPPORTED" {
			t.Errorf("%v: got %s, want NOT_SUPPORTED", args, got)
		}
	}
}

// TestWindowsReadOnlyFailsClosed: a command outside the read-only subset
// is refused before anything runs, with the hint that says how to go on.
func TestWindowsReadOnlyFailsClosed(t *testing.T) {
	srv := startWindowsServer(t)
	var err error
	_ = captureOutput(t, func() error {
		err = runRoot(t, "exec", "win", "--read-only", "--", "Get-Service $name")
		return err
	})
	e, ok := err.(*out.Error)
	if !ok || e.Code != "READ_ONLY_VIOLATION" || !strings.Contains(e.Hint, "only simple read commands on Windows") || !strings.Contains(e.Message, "$ (variables") {
		t.Fatalf("err = %#v", err)
	}
	if execs := srv.take(); len(execs) != 0 {
		t.Errorf("ran %v", execs)
	}
}

func TestWindowsExecSendsPowerShell(t *testing.T) {
	srv := startWindowsServer(t)
	srv.reply("Running\n")
	got := captureOutput(t, func() error {
		return runRoot(t, "exec", "win", "--read-only", "-e", "MODE=it's", "-C", `C:\app`, "--", "Get-Service W3SVC")
	})
	execs := srv.take()
	if len(execs) != 1 {
		t.Fatalf("execs = %v (%s)", execs, got)
	}
	s := psScript(t, execs[0])
	for _, want := range []string{"$env:MODE = 'it''s'", `Set-Location -LiteralPath 'C:\app'`, "Get-Service W3SVC"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(got, "Running") {
		t.Errorf("output = %s", got)
	}
}

func TestWindowsScriptArgs(t *testing.T) {
	srv := startWindowsServer(t)
	f := filepath.Join(t.TempDir(), "check.ps1")
	_ = os.WriteFile(f, []byte("Write-Output $args[0]\n"), 0o600)
	_ = captureOutput(t, func() error { return runRoot(t, "exec", "win", "--script", f, "--arg", "a'b") })
	execs := srv.take()
	if len(execs) != 1 || !strings.Contains(psScript(t, execs[0]), "& ([scriptblock]::Create('Write-Output $args[0]\n"+sshx.PSTrailer+"')) 'a''b'\n") {
		t.Fatalf("execs = %v", execs)
	}
	// param( ) must come first in a script block of its own, and get the
	// --arg values: lines komando puts before the script (env, -C) are
	// outside that block
	_ = os.WriteFile(f, []byte("param([string]$Stage)\nWrite-Output $Stage\n"), 0o600)
	_ = captureOutput(t, func() error {
		return runRoot(t, "exec", "win", "--script", f, "-e", "A=1", "-C", `C:\app`, "--arg", "staging", "--arg", "-x")
	})
	execs = srv.take()
	if s := psScript(t, execs[0]); !strings.Contains(s, "\n& ([scriptblock]::Create('param([string]$Stage)\n") || !strings.Contains(s, "')) 'staging' '-x'\n") {
		t.Fatalf("param script:\n%s", s)
	}
	if got := errCode(runRoot(t, "exec", "win", "--script", f, "--interpreter", "python3")); got != "NOT_SUPPORTED" {
		t.Errorf("--interpreter python3 on Windows: %s", got)
	}
}

func TestWindowsFsLsAndCat(t *testing.T) {
	srv := startWindowsServer(t)
	srv.reply(`#komando:path=C:\app` + "\n" + `#komando:json=[{"name":"web.config","path":"C:\\app\\web.config","dir":false,"size":12,"mode":"-a----","mtime":"2026-11-01T10:00:00.0000000Z","link":"","linktype":""}]` + "\n")
	got := captureOutput(t, func() error { return runRoot(t, "fs", "ls", "win", `C:\app`) })
	if !strings.Contains(got, `"name":"web.config"`) || !strings.Contains(got, `"mode":"-a----"`) {
		t.Errorf("fs ls = %s", got)
	}
	if s := psScript(t, srv.take()[0]); !strings.Contains(s, `$p = 'C:\app'`) || !strings.Contains(s, "-Force:$false") {
		t.Errorf("fs ls script:\n%s", s)
	}
	data := base64.StdEncoding.EncodeToString([]byte("line1\nline2\n"))
	srv.reply("#komando:size=12\n#komando:path=C:\\app\\a.txt\n#komando:data=" + data + "\n")
	got = captureOutput(t, func() error { return runRoot(t, "fs", "cat", "win", `C:\app\a.txt`, "--tail", "1") })
	if !strings.Contains(got, `"content":"line2\n"`) {
		t.Errorf("fs cat = %s", got)
	}
	srv.take()
	srv.reply("#komando:not-found\n")
	if code := errCode(runRoot(t, "fs", "cat", "win", `C:\nope`)); code != "PATH_NOT_FOUND" {
		t.Errorf("missing file: %s", code)
	}
}

func TestWindowsDownloadAndUpload(t *testing.T) {
	srv := startWindowsServer(t)
	body := []byte(strings.Repeat("windows data ", 5000))
	srv.reply("#komando:size=" + strconv.Itoa(len(body)) + "\n" + base64.StdEncoding.EncodeToString(body[:40000]) + "\n" + base64.StdEncoding.EncodeToString(body[40000:]) + "\n")
	dir := t.TempDir()
	_ = captureOutput(t, func() error { return runRoot(t, "download", "win", `C:\logs\app.log`, "--to", dir+"/") })
	b, err := os.ReadFile(filepath.Join(dir, "app.log"))
	if err != nil || !bytes.Equal(b, body) {
		t.Fatalf("downloaded %d bytes, %v", len(b), err)
	}
	srv.take()

	src := filepath.Join(t.TempDir(), "site.zip")
	_ = os.WriteFile(src, body, 0o600)
	srv.reply("#komando:path=C:\\site.zip\n#komando:bytes=65000\n#komando:replaced=False\n#komando:sha256=abc\n")
	got := captureOutput(t, func() error { return runRoot(t, "upload", "win", src, `C:\`) })
	execs := srv.take()
	if len(execs) != 1 || !strings.Contains(got, `"sha256":"abc"`) {
		t.Fatalf("upload: %v %s", execs, got)
	}
	s := psScript(t, execs[0])
	if !strings.Contains(s, "Join-Path $p 'site.zip'") || !strings.Contains(s, "[IO.File]::Replace($tmp, $p, [NullString]::Value)") {
		t.Errorf("upload script:\n%s", s)
	}
	_, rest, _ := strings.Cut(execs[0].stdin, "\n")
	var sent []byte
	for _, l := range strings.Fields(rest) {
		d, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			t.Fatal(err)
		}
		sent = append(sent, d...)
	}
	if !bytes.Equal(sent, body) {
		t.Errorf("sent %d bytes, want %d", len(sent), len(body))
	}
}

func TestWindowsSvcAndFacts(t *testing.T) {
	srv := startWindowsServer(t)
	srv.reply(`#komando:json=[{"name":"W3SVC","display_name":"World Wide Web Publishing Service","state":"Running","start_mode":"Auto","pid":4242,"found":true},{"name":"nope","found":false}]` + "\n")
	if code := runCode(t, "svc", "status", "win", "W3SVC", "nope"); code != "UNIT_NOT_FOUND" {
		t.Errorf("svc status with a missing service: %s", code)
	}
	if s := psScript(t, srv.take()[0]); !strings.Contains(s, "foreach ($n in @('W3SVC', 'nope'))") {
		t.Errorf("svc status script:\n%s", s)
	}
	srv.reply("os=windows\nos_pretty=Microsoft Windows Server 2019 Datacenter\nos_build=17763\ncpus=4\nupd_total=3\nupd_security=1\nlisten=tcp 0.0.0.0 5985 4 System\nadmin=True\n")
	got := captureOutput(t, func() error { return runRoot(t, "facts", "win") })
	for _, want := range []string{`"os_build":"17763"`, `"status":"supported"`, `"total":3`, `"port":5985`, `"admin":true`} {
		if !strings.Contains(got, want) {
			t.Errorf("facts lack %s: %s", want, got)
		}
	}
	srv.take()
}

func TestWinSvcScriptQuoting(t *testing.T) {
	s := winSvcScript("stop", []string{"W3SVC"}, false, 0)
	if !strings.Contains(s, "Stop-Service -Name 'W3SVC'") {
		t.Errorf("stop script:\n%s", s)
	}
	if s := winSvcScript("start", []string{"x'; Remove-Item C:\\ -Recurse; '"}, false, 0); !strings.HasPrefix(s, "[Console]::Error.WriteLine(") || strings.Contains(s, "Start-Service") {
		t.Errorf("a name that is no service name must stop the script:\n%s", s)
	}
	if winSvcScript("reload", []string{"W3SVC"}, false, 0) != "" {
		t.Error("reload has no Windows form")
	}
	s = winSvcScript("enable", []string{"sshd"}, true, 0)
	if !strings.Contains(s, "Set-Service -Name 'sshd' -StartupType Automatic") || !strings.Contains(s, "Start-Service -Name 'sshd'") {
		t.Errorf("enable --now:\n%s", s)
	}
	rr := &sshx.RunResult{Stdout: `#komando:json=[{"name":"W3SVC","state":"Stopped","found":true}]` + "\n#komando:rc=1\n"}
	if _, e := winSvcActionResult("start", 0, rr); e == nil || e.Code != "SVC_FAILED" {
		t.Errorf("rc=1: %v", e)
	}
	rr.Stdout = strings.Replace(rr.Stdout, "rc=1", "rc=0", 1)
	if _, e := winSvcActionResult("start", 5, rr); e == nil || e.Code != "UNIT_NOT_ACTIVE" {
		t.Errorf("stopped after --wait: %v", e)
	}
	list, _ := winSvcList("failed")(nil, &sshx.RunResult{Stdout: `#komando:json=[{"name":"a","state":"Stopped","start_mode":"Auto","exit_code":1067,"found":true},{"name":"b","state":"Stopped","start_mode":"Manual","found":true}]`})
	if l, _ := list.([]winService); len(l) != 1 || l[0].Name != "a" {
		t.Errorf("--failed = %v", list)
	}
}

func TestWindowsSelectorsAndHosts(t *testing.T) {
	st := testState()
	st.Hosts["win-1"] = &store.Host{Name: "win-1", Address: "w.lan", OS: store.OSWindows}
	hs, err := resolveTargets(tcl, st, "os:windows")
	if err != nil || len(hs) != 1 || hs[0].Name != "win-1" {
		t.Errorf("os:windows = %v %v", hostNames(hs), err)
	}
	if hs, _ := resolveTargets(tcl, st, "all,!os:windows"); len(hs) != 4 {
		t.Errorf("all,!os:windows = %v", hostNames(hs))
	}
	if _, err := resolveTargets(tcl, st, "os:mac"); err == nil {
		t.Error("os:mac must be refused")
	}
	if _, err := sameOS(st.SortedHosts()); errCode(err) != "MIXED_OS" {
		t.Errorf("mixed: %v", err)
	}

	startFakeServer(t)
	if err := runRoot(t, "host", "add", "w2", "Administrator@10.0.0.9", "--os", "Windows"); err != nil {
		t.Fatal(err)
	}
	s, _ := store.Load()
	if s.Hosts["w2"].OS != store.OSWindows {
		t.Errorf("os = %q", s.Hosts["w2"].OS)
	}
	if errCode(runRoot(t, "host", "add", "w3", "a@10.0.0.10", "--os", "mac")) != "USAGE" {
		t.Error("--os mac must be refused")
	}
	if err := runRoot(t, "host", "edit", "w2", "--os", "linux"); err != nil {
		t.Fatal(err)
	}
	s, _ = store.Load()
	if s.Hosts["w2"].OS != "" {
		t.Errorf("os after --os linux = %q", s.Hosts["w2"].OS)
	}
}

func TestWinFactsSupport(t *testing.T) {
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	f := parseWinFacts("os_pretty=Microsoft Windows Server 2012 R2 Standard\nos_build=9600\nupd_error=Access is denied\nreboot_required=True\n", now)
	sup := f["os_support"].(osSupport)
	if sup.Status != "unsupported" {
		t.Errorf("2012 R2 after its ESU: %+v", sup)
	}
	ws := f["warnings"].([]string)
	if len(ws) != 2 || !strings.Contains(ws[0], "Access is denied") || strings.Contains(ws[1], "Ubuntu") {
		t.Errorf("warnings = %q", ws)
	}
	if u := f["updates"].(pendingUpdates); u.Total != nil {
		t.Errorf("unreadable updates must be unknown, got %d", *u.Total)
	}
	var b strings.Builder
	writeWinFactsHost(&b, "win", f)
	if !strings.Contains(b.String(), "UNSUPPORTED") || !strings.Contains(b.String(), "REBOOT REQUIRED") {
		t.Errorf("text:\n%s", b.String())
	}
	// Windows Server 2025 shipped in November 2024: its support ends on
	// Microsoft's date, 2034-11-14
	if s := parseWinFacts("os_pretty=Microsoft Windows Server 2025 Standard\nos_build=26100\n", now)["os_support"].(osSupport); s.StandardUntil == nil || *s.StandardUntil != "2034-11-14" {
		t.Errorf("Server 2025: %+v", s)
	}
	if parseWinFacts("os_pretty=Microsoft Windows 11 Pro\nos_build=26100\n", now)["os_support"].(osSupport).Status != "unknown" {
		t.Error("a Windows desktop build is not in the server table")
	}
}

func TestB64LinesAndSink(t *testing.T) {
	data := bytes.Repeat([]byte{0, 1, 2, 250}, 30000)
	enc, err := io.ReadAll(&b64Lines{r: bytes.NewReader(data)})
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	sink := &b64Sink{save: func(in io.Reader) (xferStats, error) {
		n, err := io.Copy(&got, in)
		return xferStats{Bytes: n}, err
	}}
	_, _ = sink.Write([]byte("#komando:size=120000\n"))
	for _, chunk := range bytes.SplitAfter(enc, []byte("A")) { // odd splits
		if _, err := sink.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	res, err := sink.close(nil)
	if err != nil || res.Bytes != int64(len(data)) || !bytes.Equal(got.Bytes(), data) {
		t.Errorf("round trip: %d bytes, %v", res.Bytes, err)
	}
	var e winEntry
	_ = json.Unmarshal([]byte(`{"name":"l","path":"C:\\l","linktype":"Junction","link":"D:\\x","mtime":"2026-01-02T03:04:05.1234567Z"}`), &e)
	if inf := e.info(); inf.Type != "symlink" || inf.Link != `D:\x` || inf.ModTime.Year() != 2026 {
		t.Errorf("info = %+v", inf)
	}
	if winBase(`C:\a\b.txt`) != "b.txt" || winBase("C:/a/b/") != "b" {
		t.Error("winBase")
	}
}
