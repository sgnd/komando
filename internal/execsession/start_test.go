//go:build !windows

package execsession

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sshx"
)

// startRun is Start for a plain command: its feed piped into sh -c, as
// job start builds it for a run without sudo.
func startRun(inner string) string { return Feed(false) + " | sh -c " + sshx.Q(inner) + " & w=$!" }

// runStart runs the start script under sh (umask 022, as a login has)
// with HOME home and stdin in, and gives its output and exit code.
func runStart(t *testing.T, home string, s Start, in string, path ...string) (string, int) {
	t.Helper()
	text, err := StartScript(s)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "umask 022; "+text)
	cmd.Env = []string{"HOME=" + home, "PATH=" + strings.Join(append(path, os.Getenv("PATH")), ":")}
	cmd.Stdin = strings.NewReader(in)
	b, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(b), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), 0
}

func sessionDir(home string) string { return filepath.Join(home, ".komando", "sessions", testID) }

// waitFile waits up to 15 s for the session's file name, and gives its text.
func waitFile(t *testing.T, home, name string) string {
	t.Helper()
	p := filepath.Join(sessionDir(home), name)
	for range 150 {
		if b, err := os.ReadFile(p); err == nil {
			return string(b)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no %s after 15 s", name)
	return ""
}

func TestStartScriptChecksTheID(t *testing.T) {
	if _, err := StartScript(Start{ID: "../x", Run: startRun("true"), LogMax: 1 << 20}); err == nil {
		t.Fatal("a bad ID made shell text")
	}
	if _, err := StartScript(Start{ID: testID, Run: startRun("true")}); err == nil {
		t.Fatal("a start with no log cap made shell text")
	}
}

// The start prints the facts the record keeps, the run's output lands in
// out.log, and its exit code in exit. On a server with setsid the run
// leads its own process group, so a stop reaches all of it.
func TestStartScriptPrintsFacts(t *testing.T) {
	home := t.TempDir()
	got, code := runStart(t, home, Start{ID: testID, Shown: "echo hi", Run: startRun("echo hi"), LogMax: 1 << 20}, "")
	if code != 0 {
		t.Fatalf("exit %d, %q", code, got)
	}
	f, err := ParseFacts(got, testID)
	if err != nil {
		t.Fatalf("%v: %q", err, got)
	}
	if _, err := exec.LookPath("setsid"); err == nil && f.PGID != f.PID {
		t.Errorf("setsid is here, and the run does not lead its group: %+v", f)
	}
	if e := waitFile(t, home, "exit"); strings.TrimSpace(e) != "0" {
		t.Errorf("exit %q", e)
	}
	if o := waitFile(t, home, "out.log"); o != "hi\n" {
		t.Errorf("out.log %q", o)
	}
}

// U5: the folder is 0700 and every file in it 0600, whatever the login's
// umask; nothing of the plumbing is left after the run.
func TestStartScriptFilesPrivate(t *testing.T) {
	home := t.TempDir()
	if _, code := runStart(t, home, Start{ID: testID, Shown: "true", Run: startRun("echo x"), LogMax: 1 << 20}, ""); code != 0 {
		t.Fatalf("exit %d", code)
	}
	waitFile(t, home, "exit")
	d := sessionDir(home)
	if m := mode(t, d).Perm(); m != 0o700 {
		t.Errorf("folder mode %o", m)
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if m := mode(t, filepath.Join(d, e.Name())); !m.IsRegular() || m.Perm() != 0o600 {
			t.Errorf("%s: mode %v, want a 0600 file", e.Name(), m)
		}
	}
	if got := strings.Join(names, " "); got != "cmd exit out.log pid started" {
		t.Errorf("files: %s", got)
	}
}

// cmd holds the command as shown, never what was filled in for it.
func TestStartScriptCmdHoldsShownForm(t *testing.T) {
	home := t.TempDir()
	if _, code := runStart(t, home, Start{ID: testID, Shown: "deploy --token secret:api", Run: startRun("echo filled-value"), LogMax: 1 << 20}, ""); code != 0 {
		t.Fatalf("exit %d", code)
	}
	waitFile(t, home, "exit")
	b, err := os.ReadFile(filepath.Join(sessionDir(home), "cmd"))
	if err != nil || string(b) != "deploy --token secret:api\n" {
		t.Fatalf("cmd %q, %v", b, err)
	}
}

// The env exports and the input reach the command through files that are
// gone once the run ends.
func TestStartScriptFeedsAndDeletesInput(t *testing.T) {
	home := t.TempDir()
	env := "export K='vault-value'\n"
	inner := `eval "$(dd bs=1 count=` + strconv.Itoa(len(env)) + ` 2>/dev/null)"; printf '%s|' "$K"; cat`
	s := Start{ID: testID, Shown: "x", Run: startRun(inner), Env: len(env), Input: true, LogMax: 1 << 20}
	if _, code := runStart(t, home, s, env+"the input"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	waitFile(t, home, "exit")
	if o := waitFile(t, home, "out.log"); o != "vault-value|the input" {
		t.Errorf("out.log %q", o)
	}
	for _, n := range []string{"env", "in", "pw"} {
		if _, err := os.Lstat(filepath.Join(sessionDir(home), n)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there: %v", n, err)
		}
	}
}

// U16 (unit size): past the cap, output is dropped and counted, and the
// run goes on to its own end.
func TestStartScriptCapsTheLog(t *testing.T) {
	home := t.TempDir()
	const total, capBytes = 200000, 1024
	inner := `head -c ` + strconv.Itoa(total) + ` /dev/zero | tr '\0' a; exit 3`
	if _, code := runStart(t, home, Start{ID: testID, Shown: "x", Run: startRun(inner), LogMax: capBytes}, ""); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if e := waitFile(t, home, "exit"); strings.TrimSpace(e) != "3" {
		t.Errorf("exit %q, want the run's own 3", e)
	}
	if o := waitFile(t, home, "out.log"); len(o) != capBytes {
		t.Errorf("out.log holds %d bytes, want %d", len(o), capBytes)
	}
	n, err := strconv.Atoi(strings.TrimSpace(waitFile(t, home, "truncated")))
	if err != nil || n <= 0 || n > total-capBytes {
		t.Fatalf("truncated %d, %v; want 1 to %d", n, err, total-capBytes)
	}
	// GNU head reads no more than it writes, so the count is exact on Linux
	if runtime.GOOS == "linux" && n != total-capBytes {
		t.Errorf("truncated %d, want %d", n, total-capBytes)
	}
}

// U17: below the cap plus 5% of the disk the start refuses and makes no
// folder; a df that cannot tell does not stop it.
func TestStartScriptLowSpace(t *testing.T) {
	stub := t.TempDir()
	df := "#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted'\necho '/dev/x 1000000 990000 10000 99% /'\n"
	if err := os.WriteFile(filepath.Join(stub, "df"), []byte(df), 0o755); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	// 10000 KiB free; 5% of the disk alone is 50000 KiB
	got, code := runStart(t, home, Start{ID: testID, Run: startRun("true"), LogMax: 1 << 20}, "", stub)
	if code != ExitNoSpace {
		t.Fatalf("exit %d, %q; want %d", code, got, ExitNoSpace)
	}
	if _, err := os.Lstat(sessionDir(home)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a folder was made: %v", err)
	}
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "df"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, code := runStart(t, t.TempDir(), Start{ID: testID, Run: startRun("true"), LogMax: 1 << 20}, "", broken); code != 0 {
		t.Errorf("a df that fails stopped the start: exit %d, %q", code, got)
	}
}

// --timeout stops the run's whole group and says why; no exit code is
// written for a stopped run.
func TestStartScriptTimeout(t *testing.T) {
	home := t.TempDir()
	got, code := runStart(t, home, Start{ID: testID, Run: startRun("sleep 30"), Timeout: time.Second, LogMax: 1 << 20}, "")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	f, err := ParseFacts(got, testID)
	if err != nil {
		t.Fatal(err)
	}
	if k := waitFile(t, home, "killed"); strings.TrimSpace(k) != "TERM timeout" {
		t.Errorf("killed %q", k)
	}
	if !gone(f.PID) {
		t.Error("the run is still there")
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Lstat(filepath.Join(sessionDir(home), "exit")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a stopped run has an exit file: %v", err)
	}
}

// An unsafe folder refuses before anything is written or started.
func TestStartScriptUnsafeFolder(t *testing.T) {
	home := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(home, ".komando")); err != nil {
		t.Fatal(err)
	}
	if got, code := runStart(t, home, Start{ID: testID, Run: startRun("touch ran"), LogMax: 1 << 20}, ""); code != ExitUnsafe {
		t.Fatalf("exit %d, %q; want %d", code, got, ExitUnsafe)
	}
}

// fakeSetsid writes a setsid onto a new folder for PATH: body runs before it
// gives the command a new session (or, with group false, runs it in the
// caller's group, as a broken setsid would).
func fakeSetsid(t *testing.T, delay string, group bool) string {
	t.Helper()
	if _, err := exec.LookPath("perl"); group && err != nil {
		t.Skip("no perl to make a new session")
	}
	run := `exec "$@"`
	if group {
		run = `exec perl -e 'use POSIX qw(setsid); setsid() or die "setsid"; exec @ARGV or die "exec"' "$@"`
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nsleep " + delay + "\n" + run + "\n"
	if err := os.WriteFile(filepath.Join(dir, "setsid"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A setsid that is slow to make the group still gives a run that leads
// its own group: the start waits for it.
func TestStartScriptSlowSetsid(t *testing.T) {
	home := t.TempDir()
	got, code := runStart(t, home, Start{ID: testID, Run: startRun("echo hi"), LogMax: 1 << 20}, "", fakeSetsid(t, "0.3", true))
	if code != 0 {
		t.Fatalf("exit %d, %q", code, got)
	}
	f, err := ParseFacts(got, testID)
	if err != nil || f.PGID != f.PID {
		t.Fatalf("%+v, %v: want the run to lead its own group", f, err)
	}
	waitFile(t, home, "exit")
	if o := waitFile(t, home, "out.log"); o != "hi\n" {
		t.Errorf("out.log %q", o)
	}
}

// A setsid that gives no group of its own fails the start: no stop could
// reach the whole run. Nothing of the command runs, and no folder stays.
func TestStartScriptNoGroupFails(t *testing.T) {
	home := t.TempDir()
	mark := filepath.Join(home, "ran")
	got, code := runStart(t, home, Start{ID: testID, Run: startRun("touch " + sshx.Q(mark)), LogMax: 1 << 20}, "", fakeSetsid(t, "0", false))
	if code != ExitNoGroup {
		t.Fatalf("exit %d, %q; want %d", code, got, ExitNoGroup)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Lstat(mark); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the command ran: %v", err)
	}
	if _, err := os.Lstat(sessionDir(home)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the session folder stayed: %v", err)
	}
}
