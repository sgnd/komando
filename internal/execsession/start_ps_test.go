package execsession

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// psStart is a Windows start with every part a run can have.
func psStart() StartPS {
	return StartPS{ID: testID, Command: "Write-Output 'zqcmd'", Env: []EnvVar{{"PGPASSWORD", "s3cret='x'"}, {"A_B", "line1\nline2"}},
		Stdin: []byte("in\x00put"), LogMax: 1 << 30}
}

// psVariants are the four shapes of the start script: with and without
// env, with and without input (A-590-1: each is parsed).
func psVariants() map[string]StartPS {
	v := map[string]StartPS{}
	for _, env := range []bool{false, true} {
		for _, in := range []bool{false, true} {
			s := psStart()
			name := "env"
			if !env {
				s.Env, name = nil, "no env"
			}
			if in {
				name += ", input"
			} else {
				s.Stdin, name = nil, name+", no input"
			}
			v[name] = s
		}
	}
	return v
}

func TestStartScriptPSChecksItsStart(t *testing.T) {
	bad := map[string]func(*StartPS){
		"bad ID":       func(s *StartPS) { s.ID = "../x" },
		"no log cap":   func(s *StartPS) { s.LogMax = 0 },
		"bad env name": func(s *StartPS) { s.Env = []EnvVar{{"A;B", "x"}} },
		"env name =":   func(s *StartPS) { s.Env = []EnvVar{{"A=B", "x"}} },
		"empty env":    func(s *StartPS) { s.Env = []EnvVar{{"", "x"}} },
	}
	for name, f := range bad {
		t.Run(name, func(t *testing.T) {
			s := psStart()
			f(&s)
			if _, _, err := StartScriptPS(s); err == nil {
				t.Fatal("made a script")
			}
		})
	}
}

// Every shape of the start script parses as Windows PowerShell 5.1, and
// so does cmd.ps1 with and without the env prelude (A-590-1).
func TestStartScriptPSParses(t *testing.T) {
	for name, s := range psVariants() {
		t.Run(name, func(t *testing.T) {
			script, _, err := StartScriptPS(s)
			if err != nil {
				t.Fatal(err)
			}
			psParse(t, script)
			psParse(t, strings.TrimPrefix(string(CmdPS(s.Command, s.Env != nil)), "\ufeff"))
		})
	}
}

// psDotNet finds a .NET type in PowerShell text: [Type] or [Type]::.
var psDotNet = regexp.MustCompile(`\[[A-Za-z][A-Za-z0-9_.]*\](::[A-Za-z0-9_.]+)?`)

// psAllowed are the .NET uses the bootstrap itself makes (sshx.psBootstrap):
// if Constrained Language Mode blocks them, no Windows command runs at
// all (W10), so the session adds none beyond them. The rest are casts
// Constrained Language Mode allows.
var psAllowed = []string{"[Console]::In.ReadLine", "[Convert]::FromBase64String", "[Text.Encoding]::UTF8.GetString",
	"[Text.Encoding]::UTF8", "[Text.Encoding]::UTF8.GetByteCount",
	"[string]", "[int]", "[int64]", "[datetime]"}

// psBanned are the ways to more .NET or new code that Constrained
// Language Mode blocks or that run text as code.
var psBanned = []string{"Add-Type", "New-Object", "scriptblock", "ProcessStartInfo", "Invoke-Expression", "iex ", "EncodedCommand", "[IO."}

func psOnlyAllowed(t *testing.T, script string) {
	t.Helper()
	for _, m := range psDotNet.FindAllString(script, -1) {
		if !slices.Contains(psAllowed, m) {
			t.Errorf("the script uses %s, which Constrained Language Mode may block", m)
		}
	}
	for _, b := range psBanned {
		if strings.Contains(script, b) {
			t.Errorf("the script holds %q", b)
		}
	}
}

func TestStartScriptPSOnlyAllowedDotNet(t *testing.T) {
	for name, s := range psVariants() {
		t.Run(name, func(t *testing.T) {
			script, _, err := StartScriptPS(s)
			if err != nil {
				t.Fatal(err)
			}
			psOnlyAllowed(t, script)
			psOnlyAllowed(t, string(CmdPS(s.Command, true)))
		})
	}
	// the lint itself finds what it is for
	if m := psDotNet.FindAllString("$x = [IO.File]::ReadAllText('a'); [scriptblock]::Create('b')", -1); len(m) != 2 {
		t.Errorf("psDotNet found %q", m)
	}
}

// The command, the env values and the input travel on stdin, never in the
// script text; only the checked ID and the cap number are in it.
func TestStartScriptPSValuesAsData(t *testing.T) {
	s := psStart()
	script, input, err := StartScriptPS(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{s.Command, "zqcmd", "s3cret", "line1", "PGPASSWORD", "in\x00put"} {
		if strings.Contains(script, v) {
			t.Errorf("the script holds %q", v)
		}
	}
	if !strings.Contains(script, "$ks_id = '"+testID+"'") || !strings.Contains(script, "$ks_cap = 1073741824") {
		t.Error("the script does not set the ID and the cap")
	}
	lines := strings.Split(strings.TrimSuffix(string(input), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d input lines, want cmd.ps1, env, in and run.ps1", len(lines))
	}
	want := [][]byte{CmdPS(s.Command, true), mustEnvFile(t, s.Env), s.Stdin, RunPS(s.LogMax, 0)}
	for i, l := range lines {
		b, err := base64.StdEncoding.DecodeString(l)
		if err != nil || string(b) != string(want[i]) {
			t.Errorf("input line %d is %q, want %q", i, b, want[i])
		}
	}
	// without env or input, only cmd.ps1 is sent and only it is written
	s.Env, s.Stdin = nil, nil
	script, input, _ = StartScriptPS(s)
	if strings.Count(string(input), "\n") != 2 || strings.Contains(script, "'env'") || strings.Contains(script, "'in'") {
		t.Errorf("a start without env or input sends %q and writes env or in", input)
	}
}

func mustEnvFile(t *testing.T, vars []EnvVar) []byte {
	t.Helper()
	b, err := envFilePS(vars)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The env file holds one KEY=base64 line per value, so a value may hold
// anything (a newline, a quote, an equals sign).
func TestEnvFilePS(t *testing.T) {
	b := mustEnvFile(t, []EnvVar{{"A", "x=y\n'z'"}, {"B_2", ""}})
	want := "A=" + base64.StdEncoding.EncodeToString([]byte("x=y\n'z'")) + "\r\nB_2=\r\n"
	if string(b) != want {
		t.Errorf("env file %q, want %q", b, want)
	}
}

// cmd.ps1 is UTF-8 with a byte order mark (Windows PowerShell 5.1 reads a
// file without one in the ANSI code page); its first lines read env into
// $env: and delete the file before the command, also when reading fails,
// and a failed read stops the run before the command.
func TestCmdPS(t *testing.T) {
	c := string(CmdPS("Get-Date", true))
	if !strings.HasPrefix(c, "\ufeff") || !strings.HasSuffix(c, "\nGet-Date\n") {
		t.Errorf("cmd.ps1 %q", c)
	}
	read, del, cmd := strings.Index(c, "Get-Content"), strings.Index(c, "Remove-Item"), strings.Index(c, "Get-Date")
	if read < 0 || del < read || cmd < del || !strings.Contains(c, "finally") || !strings.Contains(c, "exit 125") {
		t.Errorf("cmd.ps1 does not read env, delete it in finally and stop on a failed read before the command:\n%s", c)
	}
	if c := string(CmdPS("Get-Date", false)); c != "\ufeffGet-Date\n" {
		t.Errorf("cmd.ps1 without env %q", c)
	}
}

// The order inside the start script: the free-space check before any
// folder is made; the ACL set and read back before any file is written.
func TestStartScriptPSOrder(t *testing.T) {
	script, _, _ := StartScriptPS(psStart())
	at := func(s string) int {
		i := strings.Index(script, s)
		if i < 0 {
			t.Fatalf("the script has no %q", s)
		}
		return i
	}
	steps := []string{"Get-PSDrive", "ks_dir $ks_r", "ks_dir $ks_s", "New-Item -ItemType Directory -Path $ks_d", "ks_own $ks_d 96", "icacls.exe $ks_d /inheritance:r", "ks_aclExact (Get-Acl", "Get-ChildItem -LiteralPath $ks_d", "ks_put 'cmd.ps1'", "ks_put 'env'", "ks_put 'in'", "'started'", "'out.log'", "Invoke-CimMethod", "'facts-end '"}
	for i := 1; i < len(steps); i++ {
		if at(steps[i-1]) > at(steps[i]) {
			t.Errorf("%q comes after %q", steps[i-1], steps[i])
		}
	}
}

// The ACL: inheritance removed, exactly the login user's SID and SYSTEM
// with full control for the folder and all below it, read back and
// compared as a set of two; any other result deletes the folder (exit
// ExitACL). komando and sessions: no reparse point, owned by the login
// user, and only the user, SYSTEM and Administrators may write.
func TestStartScriptPSFolderChecks(t *testing.T) {
	script, _, _ := StartScriptPS(psStart())
	for _, want := range []string{
		"/inheritance:r", "/grant:r", "ks_own $ks_d 96", "ks_own $p 90", "/setowner", "':(OI)(CI)F'", "'*S-1-5-18:(OI)(CI)F'",
		"ReparsePoint", "ks_fail 96",
		"if (Test-Path -LiteralPath $ks_d) { ks_fail 90 }", "whoami.exe /user /fo csv /nh",
		"if (-not (ks_aclExact (Get-Acl -LiteralPath $ks_d).Sddl $ks_sid)) { ks_fail 96 }",
		"if (@(Get-ChildItem -LiteralPath $ks_d -Force).Count -ne 0) { ks_fail 96 }",
		"if ((ks_owner $sd) -ne $ks_sid -or -not (ks_daclSafe $sd $ks_sid)) { ks_fail 90 }",
		"$ks_v.Free -lt ($ks_cap + ($ks_v.Used + $ks_v.Free) / 20)) { ks_fail 93 }",
		"if ($null -eq $l) { ks_fail 98 }",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the script has no %q", want)
		}
	}
}

// The golden text: one place to read the whole script.
func TestStartScriptPSGolden(t *testing.T) {
	script, _, err := StartScriptPS(psStart())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join("testdata", "start_ps_golden.txt")
	if os.Getenv("KOMANDO_GOLDEN_UPDATE") == "1" {
		if err := os.WriteFile(p, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != script {
		t.Error("the start script differs from testdata/start_ps_golden.txt (KOMANDO_GOLDEN_UPDATE=1 writes it)")
	}
}

// Each exit of the start script is its own error; a start that never
// reached the script (the bootstrap failed) is SESSION_START_DENIED when
// PowerShell names its language mode or a policy block, never a run
// without a session.
func TestReadStartPS(t *testing.T) {
	ok := psFacts("4242", "2026-11-25T10:00:00Z", "powershell.exe", goodCmdline)
	cases := []struct {
		name   string
		exit   int
		stdout string
		stderr string
		code   string
		noDir  bool
	}{
		{name: "prepared", exit: 0, stdout: ok},
		{name: "marker with a failed exit", exit: ExitStartFailed, stdout: ok + "failed late\n", code: "SESSION_START_FAILED"},
		{name: "no folder", exit: ExitNoFolder, noDir: true},
		{name: "unsafe", exit: ExitUnsafe, code: "SESSION_FOLDER_DENIED"},
		{name: "space", exit: ExitNoSpace, code: "SESSION_SPACE_DENIED"},
		{name: "acl", exit: ExitACL, code: "SESSION_ACL_FAILED"},
		{name: "denied by the script", exit: ExitDenied, stdout: "failed x\n", code: "SESSION_START_DENIED"},
		{name: "short input", exit: ExitShortInput, code: "SESSION_START_FAILED"},
		{name: "failed", exit: ExitStartFailed, stdout: "failed ItemExistsException boom\n", code: "SESSION_START_FAILED"},
		{name: "bootstrap in CLM", exit: 1, stderr: "Cannot invoke method. Method invocation is supported only on core types in this language mode.", code: "SESSION_START_DENIED"},
		{name: "bootstrap AppLocker", exit: 1, stderr: "This program is blocked by group policy.", code: "SESSION_START_DENIED"},
		{name: "exit 0 without the facts", exit: 0, stdout: "facts-begin other\n", code: "SESSION_START_FAILED"},
		{name: "other exit", exit: 3, code: "SESSION_START_FAILED"},
		{name: "language words with a script exit", exit: ExitNoFolder, stderr: "language mode", noDir: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ReadStartPS("web1", c.exit, c.stdout, c.stderr, testID)
			var e *out.Error
			switch {
			case c.noDir:
				if !errors.Is(err, ErrNoFolder) {
					t.Errorf("got %v, want ErrNoFolder", err)
				}
			case c.code == "":
				if err != nil {
					t.Errorf("got %v", err)
				}
			case !errors.As(err, &e) || e.Code != c.code:
				t.Errorf("got %v, want %s", err, c.code)
			case c.code == "SESSION_START_DENIED" && errors.Is(err, ErrNoFolder):
				t.Error("a blocked start falls back to a run without a session")
			}
		})
	}
}

// The reason of a failed start is shown, one line, at most 200 bytes.
func TestReadStartPSReason(t *testing.T) {
	_, err := ReadStartPS("web1", ExitStartFailed, "failed "+strings.Repeat("y", 500)+"\n", "", testID)
	if err == nil || !strings.Contains(err.Error(), "start (yyy") || len(err.Error()) > 320 {
		t.Errorf("got %v", err)
	}
}
