//go:build darwin || linux

package term

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The tests below run a screen in a child process on a pseudo-terminal,
// type into it the way a person does, and look at the terminal after the
// child is gone: every way out must leave it as it was before. Nothing
// here opens a window.

// TestScreenChild is the child process of the screen tests. It opens a
// screen on its terminal, says "ready", writes each key it reads to the
// report file, and ends the way KOMANDO_SCREEN_CHILD says.
func TestScreenChild(t *testing.T) {
	mode, ok := os.LookupEnv("KOMANDO_SCREEN_CHILD")
	if !ok {
		t.Skip("the screen tests run it")
	}
	report, _ := os.OpenFile(os.Getenv("KOMANDO_SCREEN_REPORT"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	say := func(f string, a ...any) { fmt.Fprintf(report, f+"\n", a...) }
	opt := ScreenOptions{MinWidth: 40, MinHeight: 10}
	if mode == "idle" {
		opt.Idle = 300 * time.Millisecond
	}
	// the job does not really stop: the terminal as it is at the moment
	// of the stop is reported, then the job goes on, as after fg
	stopJob = func() {
		tm, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), ioctlGetTermios)
		say("atstop %+v %v", tm, err)
	}
	s, err := OpenScreen(os.Stdin, os.Stdout, opt)
	if err != nil {
		say("open %v", err)
		os.Exit(3)
	}
	defer s.Restore()
	fmt.Fprint(os.Stdout, "ready")
	if mode == "panic" {
		panic("a bug inside the screen")
	}
	readKeys(s, mode, say)
	// the terminal as the screen left it, for a parent that cannot look
	// itself (macOS takes the terminal away when its session leader ends)
	s.Restore()
	tm, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), ioctlGetTermios)
	say("termios %+v %v", tm, err)
}

// readKeys reads keys until one ends the screen, reporting each.
func readKeys(s *Screen, mode string, say func(string, ...any)) {
	for {
		k, err := s.ReadKey()
		if err != nil {
			// the terminal as ReadKey left it, before anything else here
			// could put it back
			tm, terr := unix.IoctlGetTermios(int(os.Stdin.Fd()), ioctlGetTermios)
			say("errtermios %+v %v", tm, terr)
		}
		switch {
		case errors.Is(err, ErrIdle):
			say("end idle")
			return
		case errors.Is(err, ErrTooSmall):
			say("end too-small")
			return
		case err != nil:
			say("end error %v", err)
			return
		}
		switch k.Kind {
		case KeyRune:
			say("rune %c", k.Rune)
		case KeyPaste:
			say("paste %q toolong=%v", k.Text, k.TooLong)
		case KeySuspend:
			say("suspend")
			if err := s.Suspend(); err != nil {
				say("end suspend %v", err)
				return
			}
			fmt.Fprint(os.Stdout, "back")
		default:
			say("key %d", k.Kind)
		}
		switch k.Kind {
		case KeyEnter:
			say("end enter")
			return
		case KeyEsc:
			if mode != "keys" {
				say("end esc")
				return
			}
		case KeyInterrupt:
			say("end interrupt")
			return
		}
	}
}

// screenWait is how long a test waits for the child: far longer than it
// takes, so a busy machine does not fail the test.
const screenWait = 2 * time.Minute

type screenRun struct {
	t      *testing.T
	master *os.File
	tty    *os.File
	cmd    *exec.Cmd
	report string
	before *unix.Termios
	jobs   bool // the child has its own process group, and no controlling terminal
	mu     sync.Mutex
	screen bytes.Buffer
}

// startScreen runs the child in mode on a new pseudo-terminal of 80 by 24.
// jobs: the child gets its own process group in this session, so Ctrl-Z
// can stop it; otherwise its own session with the terminal as its
// controlling terminal, so a resize reaches it.
func startScreen(t *testing.T, mode string, jobs bool) *screenRun {
	t.Helper()
	m, tty, err := openPTY()
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	r := &screenRun{t: t, master: m, tty: tty, report: filepath.Join(t.TempDir(), "report"), jobs: jobs}
	r.resize(80, 24)
	if r.before, err = unix.IoctlGetTermios(int(tty.Fd()), ioctlGetTermios); err != nil {
		t.Fatal(err)
	}
	r.cmd = exec.Command(os.Args[0], "-test.run=^TestScreenChild$", "-test.timeout=10m")
	r.cmd.Env = append(os.Environ(), "KOMANDO_SCREEN_CHILD="+mode, "KOMANDO_SCREEN_REPORT="+r.report)
	r.cmd.Stdin, r.cmd.Stdout, r.cmd.Stderr = tty, tty, tty
	if jobs {
		r.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	} else {
		r.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	}
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := m.Read(b)
			r.mu.Lock()
			r.screen.Write(b[:max(n, 0)])
			r.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		if r.cmd.ProcessState == nil {
			_ = r.cmd.Process.Kill()
			_ = r.cmd.Wait()
		}
		m.Close()
		tty.Close()
	})
	r.waitFor("ready")
	return r
}

func (r *screenRun) shown() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.screen.String()
}

func (r *screenRun) waitFor(s string) {
	r.t.Helper()
	for end := time.Now().Add(screenWait); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if strings.Contains(r.shown(), s) {
			return
		}
	}
	r.t.Fatalf("%q never showed; the screen: %q", s, r.shown())
}

func (r *screenRun) typ(s string) {
	r.t.Helper()
	if _, err := r.master.WriteString(s); err != nil {
		r.t.Fatal(err)
	}
}

func (r *screenRun) resize(w, h int) {
	r.t.Helper()
	if err := unix.IoctlSetWinsize(int(r.master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(w), Row: uint16(h)}); err != nil {
		r.t.Fatal(err)
	}
}

// end waits for the child and returns how it ended.
func (r *screenRun) end() *os.ProcessState {
	r.t.Helper()
	done := make(chan struct{})
	go func() { _ = r.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(screenWait):
		r.t.Fatalf("the child did not end; the screen: %q", r.shown())
	}
	return r.cmd.ProcessState
}

// lines is what the child reported, without its termios line.
func (r *screenRun) lines() []string {
	b, _ := os.ReadFile(r.report)
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if !strings.HasPrefix(l, "termios ") && !strings.HasPrefix(l, "errtermios ") && !strings.HasPrefix(l, "atstop ") {
			out = append(out, l)
		}
	}
	return out
}

// termiosNow is the terminal's mode now: read here when the child had no
// controlling terminal, else as the child reported it after its screen.
func (r *screenRun) termiosNow() string {
	r.t.Helper()
	if r.jobs {
		tm, err := unix.IoctlGetTermios(int(r.tty.Fd()), ioctlGetTermios)
		return fmt.Sprintf("termios %+v %v", tm, err)
	}
	b, _ := os.ReadFile(r.report)
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "termios ") {
			return l
		}
	}
	r.t.Fatalf("the child reported no terminal mode: %q", b)
	return ""
}

// restored checks that the terminal is as it was before the child, and
// that the screen turned bracketed paste off and showed the cursor again
// after it turned them on.
func (r *screenRun) restored() {
	r.t.Helper()
	if now, want := r.termiosNow(), fmt.Sprintf("termios %+v %v", r.before, nil); now != want {
		r.t.Errorf("the terminal was not put back:\n before %s\n after  %s", want, now)
	}
	out := r.shown()
	on, off := strings.LastIndex(out, screenOn), strings.LastIndex(out, screenOff)
	if on < 0 || off < on {
		r.t.Errorf("bracketed paste on at %d, off at %d: the screen did not undo what it turned on; it wrote %q", on, off, out)
	}
}

// restoredAtError checks that ReadKey had put the terminal back by the
// time it returned its error.
func (r *screenRun) restoredAtError() {
	r.t.Helper()
	b, _ := os.ReadFile(r.report)
	want := fmt.Sprintf("errtermios %+v %v", r.before, nil)
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "errtermios ") {
			if l != want {
				r.t.Errorf("ReadKey returned its error with the terminal still raw:\n want %s\n got  %s", want, l)
			}
			return
		}
	}
	r.t.Errorf("the child reported no terminal mode at the error: %q", b)
}

func (r *screenRun) wantLines(want ...string) {
	r.t.Helper()
	if got := r.lines(); strings.Join(got, "|") != strings.Join(want, "|") {
		r.t.Errorf("the child reported %q, want %q", got, want)
	}
}

// Each key that ends a screen leaves the terminal as it was.
func TestScreenRestoresOnKeys(t *testing.T) {
	tests := []struct {
		name, mode, typed string
		want              []string
	}{
		{"enter", "keys", "\r", []string{"key 2", "end enter"}},
		{"esc", "esc", "\x1b", []string{"key 3", "end esc"}},
		{"ctrl-c", "keys", "\x03", []string{"key 17", "end interrupt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := startScreen(t, tt.mode, true)
			r.typ(tt.typed)
			if ps := r.end(); !ps.Success() {
				t.Errorf("the child ended with %v", ps)
			}
			r.wantLines(tt.want...)
			r.restored()
		})
	}
}

// A screen nobody touches ends by itself and puts the terminal back.
func TestScreenRestoresWhenIdle(t *testing.T) {
	r := startScreen(t, "idle", true)
	r.end()
	r.wantLines("end idle")
	r.restoredAtError()
	r.restored()
}

// SIGTERM and SIGHUP put the terminal back, then end the process of that
// signal, as a shell expects.
func TestScreenRestoresOnSignals(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			r := startScreen(t, "keys", true)
			if err := r.cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			ps := r.end()
			ws, _ := ps.Sys().(syscall.WaitStatus)
			if !ws.Signaled() || ws.Signal() != sig {
				t.Errorf("the child ended with %v, want killed by %v", ps, sig)
			}
			r.restored()
		})
	}
}

// A panic inside the screen still puts the terminal back: the caller's
// deferred Restore runs before the process dies.
func TestScreenRestoresOnPanic(t *testing.T) {
	r := startScreen(t, "panic", true)
	if ps := r.end(); ps.Success() {
		t.Errorf("the child did not panic: %v", ps)
	}
	r.restored()
}

// A window made smaller than the screen needs ends it and puts the
// terminal back; a resize that still fits only says so.
func TestScreenRestoresOnResize(t *testing.T) {
	r := startScreen(t, "keys", false)
	r.resize(100, 30)
	r.waitForReport("key 21")
	r.resize(20, 5)
	r.end()
	r.wantLines("key 21", "end too-small")
	r.restoredAtError()
	r.restored()
}

// waitForReport waits until the child reported line.
func (r *screenRun) waitForReport(line string) {
	r.t.Helper()
	for end := time.Now().Add(screenWait); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		for _, l := range r.lines() {
			if l == line {
				return
			}
		}
	}
	r.t.Fatalf("the child never reported %q; it reported %q", line, r.lines())
}

// Ctrl-Z puts the terminal back before the job stops, and brings raw
// mode back when it goes on; Enter then ends it and the terminal is as it
// was. The stop itself is stopJob, which the child replaces: how a job
// stops depends on the machine's process groups, which differ between
// this test's hosts.
func TestScreenSuspendAndResume(t *testing.T) {
	r := startScreen(t, "keys", true)
	r.typ("\x1a")
	r.waitFor("back")
	want := fmt.Sprintf("atstop %+v %v", r.before, nil)
	b, _ := os.ReadFile(r.report)
	at := ""
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "atstop ") {
			at = l
		}
	}
	if at != want {
		t.Errorf("the job stopped with the terminal not put back:\n want %s\n got  %s", want, at)
	}
	if now, err := unix.IoctlGetTermios(int(r.tty.Fd()), ioctlGetTermios); err != nil || now.Lflag&unix.ICANON != 0 {
		t.Errorf("raw mode did not come back after the job went on (%v)", err)
	}
	r.typ("x\r")
	r.end()
	r.wantLines("suspend", "rune x", "key 2", "end enter")
	r.restored()
	// bracketed paste: on, off before the stop, on after it, off at the end
	out := r.shown()
	on1 := strings.Index(out, screenOn)
	off1 := strings.Index(out, screenOff)
	on2 := strings.LastIndex(out, screenOn)
	if strings.Count(out, screenOn) != 2 || strings.Count(out, screenOff) != 2 || !(on1 < off1 && off1 < on2) {
		t.Errorf("bracketed paste was not turned off for the stop and on again after it; the screen wrote %q", out)
	}
}

// On a real terminal: a lone ESC is Esc only after its wait, a key sent
// at once is one key, a sequence komando does not know is dropped whole,
// and a paste over FieldMax comes back TooLong with nothing of it used.
func TestScreenKeysOnTerminal(t *testing.T) {
	r := startScreen(t, "keys", true)
	r.typ("\x1b")
	time.Sleep(10 * EscWait)
	r.typ("a\x1b[A\x1b[5nb")
	big := "\x1b[200~" + strings.Repeat("x", FieldMax+10) + "\x1b[201~"
	go func() { _, _ = r.master.WriteString(big) }() // the child reads as it comes
	r.waitForReport("paste \"\" toolong=true")
	r.typ("\x1b[200~ok\r\x1b[201~\r")
	r.end()
	r.wantLines("key 3", "rune a", "key 4", "rune b", "paste \"\" toolong=true", "paste \"ok\\n\" toolong=false", "key 2", "end enter")
	r.restored()
}
