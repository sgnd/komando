package execsession

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// These tests replay the Windows start script in Windows PowerShell 5.1
// on this computer (the CI's Windows runner), with %LOCALAPPDATA% set to
// a test folder: the folder checks, the ACL read back, the files, and
// cmd.ps1 reading its env. They need no server.

// psRunFile runs script with args in Windows PowerShell, with env added
// and stdin, and gives its output and exit code.
func psRunFile(t *testing.T, script string, stdin []byte, env []string, args ...string) (string, int) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "s.ps1")
	if err := os.WriteFile(f, []byte(bom+script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("powershell.exe", append([]string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", f}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = bytes.NewReader(stdin)
	b, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(b), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), 0
}

// runStartPS runs the start script with %LOCALAPPDATA% at base.
func runStartPS(t *testing.T, base string, s StartPS) (string, int) {
	t.Helper()
	script, input, err := StartScriptPS(s)
	if err != nil {
		t.Fatal(err)
	}
	return psRunFile(t, script, input, []string{"LOCALAPPDATA=" + base})
}

func sessionDirPS(base string) string { return filepath.Join(base, "komando", "sessions", testID) }

func loginSID(t *testing.T) string {
	t.Helper()
	b, err := exec.Command("whoami.exe", "/user", "/fo", "csv", "/nh").Output()
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Split(strings.TrimSpace(string(b)), ",")
	return strings.Trim(f[len(f)-1], `"`)
}

func sddl(t *testing.T, path string) string {
	t.Helper()
	o, code := psRunFile(t, "param([string]$p)\n(Get-Acl -LiteralPath $p).Sddl\n", nil, nil, path)
	if code != 0 {
		t.Fatalf("Get-Acl %s: exit %d: %s", path, code, o)
	}
	return strings.TrimSpace(o)
}

var sddlACE = regexp.MustCompile(`\([^()]*\)`)

// W3 in part: the session folder is owned by the login user, protected,
// and holds exactly two entries; the files hold exactly what was sent.
func TestStartScriptPSOnWindows(t *testing.T) {
	base := t.TempDir()
	s := psStart()
	got, code := runStartPS(t, base, s)
	if code != 0 || !strings.Contains(got, "prepared "+testID) {
		t.Fatalf("exit %d: %s", code, got)
	}
	if err := ReadStartPS("web1", code, got, "", testID); err != nil {
		t.Fatal(err)
	}
	d := sessionDirPS(base)
	sid := loginSID(t)
	sd := sddl(t, d)
	dacl := sd[strings.Index(sd, "D:"):]
	aces := sddlACE.FindAllString(dacl, -1)
	sort.Strings(aces)
	want := []string{"(A;OICI;FA;;;" + sid + ")", "(A;OICI;FA;;;SY)"}
	sort.Strings(want)
	if !strings.HasPrefix(sd, "O:"+sid) || !strings.HasPrefix(dacl, "D:P") || strings.Join(aces, "") != strings.Join(want, "") {
		t.Errorf("the session folder's security is %s, want owner %s, protected, entries %v", sd, sid, want)
	}
	files := map[string][]byte{"cmd.ps1": CmdPS(s.Command, true), "env": mustEnvFile(t, s.Env), "in": s.Stdin, "out.log": {}}
	for name, w := range files {
		b, err := os.ReadFile(filepath.Join(d, name))
		if err != nil || !bytes.Equal(b, w) {
			t.Errorf("%s: %q, %v; want %q", name, b, err, w)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(d, "started")); !regexp.MustCompile(`^[0-9]{10}$`).Match(b) {
		t.Errorf("started %q", b)
	}
}

// cmd.ps1 sets each env value as given, deletes the env file before the
// command runs, and the command then sees the values (W5 in part).
func TestCmdPSReadsEnvOnWindows(t *testing.T) {
	base := t.TempDir()
	s := psStart()
	s.Command = "Write-Output ('a=' + $env:A_B + '|p=' + $env:PGPASSWORD + '|env:' + (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'env')))"
	if got, code := runStartPS(t, base, s); code != 0 {
		t.Fatalf("exit %d: %s", code, got)
	}
	cmd := filepath.Join(sessionDirPS(base), "cmd.ps1")
	o, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, o)
	}
	if got := strings.ReplaceAll(string(o), "\r", ""); got != "a=line1\nline2|p=s3cret='x'|env:False\n" {
		t.Errorf("cmd.ps1 printed %q", got)
	}
	if _, err := os.Stat(filepath.Join(sessionDirPS(base), "env")); !os.IsNotExist(err) {
		t.Errorf("the env file is still there: %v", err)
	}
}

// W4 in part: a junction for sessions, a sessions folder others may
// write, and a session folder that exists already each refuse the start
// (ExitUnsafe), and leave nothing behind.
func TestStartScriptPSRefusesUnsafeFolders(t *testing.T) {
	cases := map[string]string{
		"junction":      "$t = Join-Path $p 'elsewhere'; $null = New-Item -ItemType Directory -Path $t; $null = New-Item -ItemType Junction -Path (Join-Path $p 'komando\\sessions') -Target $t",
		"others write":  "$s = Join-Path $p 'komando\\sessions'; $null = New-Item -ItemType Directory -Path $s; $null = & icacls.exe $s /grant '*S-1-1-0:(W)'",
		"exists":        "$null = New-Item -ItemType Directory -Path (Join-Path $p 'komando\\sessions\\" + testID + "')",
		"komando file":  "$null = New-Item -ItemType File -Path (Join-Path $p 'komando')",
		"sessions file": "$null = New-Item -ItemType Directory -Path (Join-Path $p 'komando'); $null = New-Item -ItemType File -Path (Join-Path $p 'komando\\sessions')",
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			if o, code := psRunFile(t, "param([string]$p)\n$ErrorActionPreference = 'Stop'\n"+setup+"\n", nil, nil, base); code != 0 {
				t.Fatalf("setup: exit %d: %s", code, o)
			}
			got, code := runStartPS(t, base, psStart())
			if code != ExitUnsafe {
				t.Fatalf("exit %d, want %d: %s", code, ExitUnsafe, got)
			}
			if _, err := os.Stat(filepath.Join(base, "elsewhere", testID)); !os.IsNotExist(err) {
				t.Error("the start made its folder through the junction")
			}
			if name != "exists" {
				if _, err := os.Stat(sessionDirPS(base)); !os.IsNotExist(err) {
					t.Error("a session folder is left")
				}
			}
		})
	}
}

// No absolute %LOCALAPPDATA%: no folder can be made (ExitNoFolder).
func TestStartScriptPSNoLocalAppData(t *testing.T) {
	if got, code := runStartPS(t, "relative", psStart()); code != ExitNoFolder {
		t.Fatalf("exit %d: %s", code, got)
	}
}
