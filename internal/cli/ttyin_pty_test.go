//go:build !windows

package cli

import (
	"bytes"
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
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/vault"
)

// The tests below run komando in a child process on a pseudo-terminal, the
// way a person's terminal runs it, and type into it: Ctrl-C, Ctrl-D, a
// paste. Agent detection is off in the child (TestMain), and the child says
// a person is at the terminal, so it asks.

// TestPTYChild is komando in the child process of the pty tests.
func TestPTYChild(t *testing.T) {
	args, ok := os.LookupEnv("KOMANDO_PTY_ARGS")
	if !ok {
		t.Skip("the pty tests run it")
	}
	interactive = func() bool { return true }
	switch os.Getenv("KOMANDO_PTY_AS") {
	case "person": // whatever TERM and CI the tests run with
		promptable = func(f string) bool { return promptGate(f, isAgent(), "", "xterm") }
	case "agent": // TestMain took the agent variables away
		os.Setenv("KOMANDO_AGENT", "1")
		resetApproval()
		interactive = func() bool { return false } // as the real one says for an agent
	}
	os.Args = append([]string{"komando"}, strings.Split(args, "\x1f")...)
	code := Execute()
	// the terminal as komando leaves it (the test cannot look itself: the
	// system takes the terminal away when this process ends)
	fd := int(os.Stdin.Fd())
	tm, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	echo := err == nil && tm.Lflag&unix.ECHO != 0 && tm.Lflag&unix.ICANON != 0
	left := -1
	if old, err := term.MakeRaw(fd); err == nil { // line mode counts only finished lines
		left = typedAhead(fd)
		_ = term.Restore(fd, old)
	}
	_ = os.WriteFile(os.Getenv("KOMANDO_PTY_REPORT"), fmt.Appendf(nil, "%v %d", echo, left), 0o600)
	os.Exit(code)
}

type ptyRun struct {
	t      *testing.T
	master *os.File // the side a terminal window holds: what is typed goes in here
	tty    *os.File // komando's terminal
	cmd    *exec.Cmd
	report string // where the child says how it left the terminal
	mu     sync.Mutex
	screen bytes.Buffer
}

// startPTY runs komando with args on a new pseudo-terminal.
func startPTY(t *testing.T, args ...string) *ptyRun {
	t.Helper()
	return startPTYEnv(t, nil, args...)
}

// startPTYEnv is startPTY with more environment for komando.
func startPTYEnv(t *testing.T, env []string, args ...string) *ptyRun {
	t.Helper()
	m, tty, err := openPTY()
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	p := &ptyRun{t: t, master: m, tty: tty, report: filepath.Join(t.TempDir(), "report")}
	p.cmd = exec.Command(os.Args[0], "-test.run=^TestPTYChild$")
	p.cmd.Env = append(append(environWithout("CI"), "KOMANDO_PTY_ARGS="+strings.Join(args, "\x1f"), "KOMANDO_PTY_REPORT="+p.report, "KOMANDO_OUTPUT=text"), env...)
	// this process took the passphrase out of its environment; the child
	// needs it for every command, as a person's own shell would give it
	if pass := vault.Passphrase(); pass != "" {
		p.cmd.Env = append(p.cmd.Env, "KOMANDO_VAULT_PASS="+pass)
	}
	p.cmd.Stdin, p.cmd.Stdout, p.cmd.Stderr = tty, tty, tty
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := m.Read(b)
			p.mu.Lock()
			p.screen.Write(b[:max(n, 0)])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		if p.cmd.ProcessState == nil {
			_ = p.cmd.Process.Kill()
			_ = p.cmd.Wait()
		}
		m.Close()
		tty.Close()
	})
	return p
}

func (p *ptyRun) shown() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.screen.String()
}

// waitFor waits until s is on the screen.
func (p *ptyRun) waitFor(s string) {
	p.t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if strings.Contains(p.shown(), s) {
			return
		}
	}
	p.t.Fatalf("%q never showed; the screen:\n%s", s, p.shown())
}

// answer waits for the question q, then types s.
func (p *ptyRun) answer(q, s string) {
	p.t.Helper()
	p.waitFor(q)
	time.Sleep(200 * time.Millisecond) // komando reads from here on
	if _, err := p.master.WriteString(s); err != nil {
		p.t.Fatal(err)
	}
}

// exit waits for komando to end and returns its exit code.
func (p *ptyRun) exit() int {
	p.t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
		p.t.Fatalf("komando went on waiting; the screen:\n%s", p.shown())
	}
	return p.cmd.ProcessState.ExitCode()
}

// leftTerminal says how komando left the terminal when it ended: back in
// line mode with echo on, and how many bytes still wait to be read (what
// the shell would read, and run, next).
func (p *ptyRun) leftTerminal() (echo bool, left int) {
	p.t.Helper()
	b, err := os.ReadFile(p.report)
	if err != nil {
		p.t.Fatalf("komando reported nothing: %v", err)
	}
	var e string
	if _, err := fmt.Sscan(string(b), &e, &left); err != nil {
		p.t.Fatalf("report %q: %v", b, err)
	}
	return e == "true", left
}

// sameLine: the line of the screen that holds s also holds q.
func sameLine(screen, q, s string) bool {
	for _, l := range strings.Split(screen, "\n") {
		if strings.Contains(l, s) {
			return strings.Contains(l, q)
		}
	}
	return false
}

func TestPTYCtrlCAtYesNo(t *testing.T) {
	for _, key := range []string{"\x03", "\x04"} { // Ctrl-C, Ctrl-D
		invHome(t)
		mustRun(t, "host", "add", "web", "u@10.0.0.1", "--protected")
		p := startPTY(t, "host", "rm", "web")
		p.answer("[y/N] ", key)
		if code := p.exit(); code != out.ExitPolicy {
			t.Errorf("%q: exit %d, want %d; the screen:\n%s", key, code, out.ExitPolicy, p.shown())
		}
		p.waitFor("Nothing was changed on web.")
		screen := p.shown()
		if !strings.Contains(screen, "Cancelled.") || sameLine(screen, "[y/N]", "Cancelled") || strings.Contains(screen, "Error:") {
			t.Errorf("%q: want 'cancelled' on a line of its own:\n%s", key, screen)
		}
		if echo, _ := p.leftTerminal(); !echo {
			t.Errorf("%q: echo stayed off", key)
		}
		mustRun(t, "host", "show", "web") // still there
	}
}

func TestPTYCtrlCAtHiddenPrompt(t *testing.T) {
	invHome(t)
	p := startPTY(t, "secret", "set", "s1")
	p.answer("(it stays hidden): ", "half-typed")
	time.Sleep(100 * time.Millisecond)
	p.master.WriteString("\x03")
	if code := p.exit(); code != out.ExitError {
		t.Errorf("exit %d, want %d; the screen:\n%s", code, out.ExitError, p.shown())
	}
	p.waitFor("Stopped (Ctrl-C)")
	screen := p.shown()
	if !strings.Contains(screen, "CANCELLED") || sameLine(screen, "hidden", "Stopped (Ctrl-C)") {
		t.Errorf("want CANCELLED on a line of its own:\n%s", screen)
	}
	if strings.Contains(screen, "half-typed") {
		t.Errorf("the hidden answer showed:\n%s", screen)
	}
	if echo, _ := p.leftTerminal(); !echo {
		t.Error("echo stayed off after Ctrl-C at a hidden prompt")
	}
	if _, err := vault.Get("s1"); err == nil {
		t.Error("a value was stored")
	}
}

func TestPTYMultiLinePaste(t *testing.T) {
	invHome(t)
	p := startPTY(t, "secret", "set", "s1")
	// a copied key: the last line often comes without a line break
	p.answer("(it stays hidden): ", "-----BEGIN KEY-----\nline-two\nline-three\n-----END KEY-----")
	if code := p.exit(); code != out.ExitUsage {
		t.Errorf("exit %d, want %d; the screen:\n%s", code, out.ExitUsage, p.shown())
	}
	p.waitFor("secret set NAME < FILE")
	screen := p.shown()
	if !strings.Contains(screen, "the value has more than one line, so nothing was stored") {
		t.Errorf("the screen:\n%s", screen)
	}
	if strings.Contains(screen, "line-") || strings.Contains(screen, "KEY") {
		t.Errorf("the pasted text showed:\n%s", screen)
	}
	if echo, left := p.leftTerminal(); !echo || left != 0 {
		t.Errorf("echo on %v; %d bytes of the paste are left for the shell to run", echo, left)
	}
	if _, err := vault.Get("s1"); err == nil {
		t.Error("a value was stored")
	}
}

// One line with a line break or a bracketed paste's end mark after it is
// one value, not a paste of several lines.
func TestPTYOneLinePaste(t *testing.T) {
	for _, typed := range []string{"s3cret\r", "s3cret\n\n", "\x1b[200~s3cret\n\x1b[201~"} {
		invHome(t)
		p := startPTY(t, "secret", "set", "s1")
		p.answer("(it stays hidden): ", typed)
		if code := p.exit(); code != 0 {
			t.Errorf("%q: exit %d; the screen:\n%s", typed, code, p.shown())
			continue
		}
		if v, err := vault.Get("s1"); err != nil || v != "s3cret" {
			t.Errorf("%q: stored %q %v", typed, v, err)
		}
		if echo, left := p.leftTerminal(); !echo || left != 0 {
			t.Errorf("%q: echo on %v, %d bytes left", typed, echo, left)
		}
	}
}

// environWithout is this process's environment without the named variables:
// a PTY test plays a person at a terminal, which a CI job's CI=true would
// turn into a script that is never asked anything.
func environWithout(names ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		keep := true
		for _, n := range names {
			if strings.HasPrefix(kv, n+"=") {
				keep = false
			}
		}
		if keep {
			env = append(env, kv)
		}
	}
	return env
}
