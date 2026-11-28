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

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// startRun is Start for a plain command: its feed piped into sh -c, as
// exec builds it for a run without sudo.
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
	if _, code := runStart(t, home, Start{ID: testID, Shown: "deploy --token credential:api", Run: startRun("echo filled-value"), LogMax: 1 << 20}, ""); code != 0 {
		t.Fatalf("exit %d", code)
	}
	waitFile(t, home, "exit")
	b, err := os.ReadFile(filepath.Join(sessionDir(home), "cmd"))
	if err != nil || string(b) != "deploy --token credential:api\n" {
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

// --timeout stops the run's whole group and says why; the root still writes
// the run's exit code (T3), and killed decides how a read shows it.
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
	if e := strings.TrimSpace(waitFile(t, home, "exit")); e == "" || e == "0" {
		t.Errorf("exit %q after the timeout's TERM, want the run's code", e)
	}
}

// C652: a run its --timeout stopped keeps the output it printed before:
// the capper outlives the group's TERM and empties what it holds.
func TestStartScriptTimeoutKeepsOutput(t *testing.T) {
	home := t.TempDir()
	if got, code := runStart(t, home, Start{ID: testID, Run: startRun("echo a; sleep 30"), Timeout: time.Second, LogMax: 1 << 20}, "", fakeSetsid(t, "0", true)); code != 0 {
		t.Fatalf("exit %d, %q", code, got)
	}
	waitFile(t, home, "killed")
	for range 50 {
		if _, err := os.Lstat(filepath.Join(sessionDir(home), ".o")); errors.Is(err, os.ErrNotExist) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if o, _ := os.ReadFile(filepath.Join(sessionDir(home), "out.log")); string(o) != "a\n" {
		t.Errorf("out.log %q, want the output before the timeout", o)
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

// fakeBusyboxPs is a folder with a ps that, like busybox's, has no -p.
func fakeBusyboxPs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nfor a; do case $a in -p) echo 'ps: unrecognized option: p' >&2; exit 1;; esac; done\nexec /bin/ps \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ps"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// C653: where ps has no -p (busybox: Alpine, docker:dind) the run's group
// comes from /proc: the start does not fail, and the facts name the group.
func TestStartScriptBusyboxPs(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc here: ps -p is the only way to read a group")
	}
	home := t.TempDir()
	got, code := runStart(t, home, Start{ID: testID, Run: startRun("echo hi"), LogMax: 1 << 20}, "", fakeBusyboxPs(t))
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

// The root process runs nothing unless the start script let it go (.go):
// a start script cut off before that leaves a folder, never a run.
func TestWrapperWaitsForGo(t *testing.T) {
	home := session(t, nil)
	d := sessionDir(home)
	if err := exec.Command("mkfifo", filepath.Join(d, ".o")).Run(); err != nil {
		t.Fatal(err)
	}
	mark := filepath.Join(home, "ran")
	cmd := exec.Command("sh", "-c", wrapper(startRun("touch "+sshx.Q(mark)), 0, 1<<20), "sh", "022")
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "d=" + d}
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if _, err := os.Lstat(mark); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the command ran without .go: %v", err)
	}
}

func TestReadStart(t *testing.T) {
	facts := "warning ~/.komando was mode 755; now 700; earlier logs may have been read\n" +
		"facts-begin " + testID + "\npid 4242\npgid 4242\nstart proc 99\nfacts-end " + testID + "\n"
	f, warns, err := ReadStart("web1", 0, facts, testID)
	if err != nil || f.PID != 4242 || len(warns) != 1 || warns[0] != "~/.komando was mode 755; now 700; earlier logs may have been read" {
		t.Fatalf("got %+v %q %v", f, warns, err)
	}
	for _, tc := range []struct {
		name string
		exit int
		code string
	}{
		{"unsafe folder", ExitUnsafe, "SESSION_FOLDER_DENIED"},
		{"no space", ExitNoSpace, "SESSION_SPACE_DENIED"},
		{"no group", ExitNoGroup, "SESSION_START_FAILED"},
		{"anything else", 1, "SESSION_START_FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ReadStart("web1", tc.exit, "", testID)
			var oe *out.Error
			if !errors.As(err, &oe) || oe.Code != tc.code {
				t.Fatalf("exit %d gave %v, want %s", tc.exit, err, tc.code)
			}
		})
	}
	if _, _, err := ReadStart("web1", ExitNoFolder, "", testID); !errors.Is(err, ErrNoFolder) {
		t.Fatalf("exit %d gave %v, want ErrNoFolder", ExitNoFolder, err)
	}
	if _, _, err := ReadStart("web1", 0, "pid 1\n", testID); err == nil {
		t.Fatal("a start without facts was taken")
	}
}
