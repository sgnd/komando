package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/vault"
)

// The tests below run komando in a child process on a Windows pseudo
// console (ConPTY), the way Windows Terminal or a console window runs it,
// and type into it: an answer, Ctrl-C, a hidden value. They are the
// Windows side of the pty tests in ttyin_pty_test.go.

// TestConPTYChild is komando in the child process of the ConPTY tests. It
// opens the console itself (CONIN$, CONOUT$), so the std handles the test
// runner gave it do not matter.
func TestConPTYChild(t *testing.T) {
	args, ok := os.LookupEnv("KOMANDO_PTY_ARGS")
	if !ok {
		t.Skip("the ConPTY tests run it")
	}
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		os.Exit(90)
	}
	con, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		os.Exit(91)
	}
	os.Stdin, os.Stdout, os.Stderr = in, con, con
	promptW = con
	promptable = func(cl *call, f string) bool { return promptGate(f, cl.isAgent(), "", "xterm") }
	os.Args = append([]string{"komando"}, strings.Split(args, "\x1f")...)
	code := Execute()
	// how komando leaves the console: echo and line mode on again, and
	// nothing typed left for the shell
	var mode uint32
	_ = windows.GetConsoleMode(windows.Handle(in.Fd()), &mode)
	const want = windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	_ = os.WriteFile(os.Getenv("KOMANDO_PTY_REPORT"), fmt.Appendf(nil, "%v %d", mode&want == want, typedAhead(int(in.Fd()))), 0o600)
	os.Exit(code)
}

// conPTY is a komando child on a pseudo console.
type conPTY struct {
	t      *testing.T
	in     *os.File // what is typed goes in here
	hpc    windows.Handle
	proc   windows.Handle
	report string
	done   chan struct{} // the screen reader ended
	mu     sync.Mutex
	screen bytes.Buffer
}

// startConPTY runs komando with args on a new pseudo console.
func startConPTY(t *testing.T, args ...string) *conPTY {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &conPTY{t: t, in: inW, report: filepath.Join(t.TempDir(), "report"), done: make(chan struct{})}
	if err := windows.CreatePseudoConsole(windows.Coord{X: 160, Y: 50}, windows.Handle(inR.Fd()), windows.Handle(outW.Fd()), 0, &p.hpc); err != nil {
		t.Skipf("no pseudo console here: %v", err)
	}
	inR.Close() // the console holds its own copies
	outW.Close()
	go func() { // the console stops when its output is not read
		defer close(p.done)
		b := make([]byte, 4096)
		for {
			n, err := outR.Read(b)
			p.mu.Lock()
			p.screen.Write(b[:max(n, 0)])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		t.Fatal(err)
	}
	defer attrs.Delete()
	// the attribute's value is the console handle itself, not a pointer to it
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, *(*unsafe.Pointer)(unsafe.Pointer(&p.hpc)), unsafe.Sizeof(p.hpc)); err != nil {
		t.Fatal(err)
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si))

	env := append(os.Environ(), "KOMANDO_PTY_ARGS="+strings.Join(args, "\x1f"), "KOMANDO_PTY_REPORT="+p.report, "KOMANDO_OUTPUT=text")
	if pass := vault.Passphrase(); pass != "" {
		env = append(env, "KOMANDO_VAULT_PASS="+pass)
	}
	block := utf16.Encode([]rune(strings.Join(env, "\x00") + "\x00\x00"))
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{os.Args[0], "-test.run=^TestConPTYChild$"}))
	if err != nil {
		t.Fatal(err)
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, line, nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT, &block[0], nil, &si.StartupInfo, &pi); err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(pi.Thread)
	p.proc = pi.Process
	t.Cleanup(func() {
		_ = windows.TerminateProcess(p.proc, 1) // fails once it ended
		windows.CloseHandle(p.proc)
		windows.ClosePseudoConsole(p.hpc) // ends the output, and so the reader
		inW.Close()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
		}
		outR.Close()
	})
	return p
}

// shown is what komando wrote to the console, without the console's own
// escape sequences (cursor moves, colours, titles).
func (p *conPTY) shown() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return stripVT(p.screen.String())
}

// waitFor waits until s is on the screen.
func (p *conPTY) waitFor(s string) {
	p.t.Helper()
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if strings.Contains(p.shown(), s) {
			return
		}
	}
	p.t.Fatalf("%q never showed; the screen:\n%s", s, p.shown())
}

// answer waits for the question q, then types s (Enter is \r on a
// console).
func (p *conPTY) answer(q, s string) {
	p.t.Helper()
	p.waitFor(q)
	time.Sleep(300 * time.Millisecond) // komando reads from here on
	if _, err := p.in.WriteString(s); err != nil {
		p.t.Fatal(err)
	}
}

// exit waits for komando to end and returns its exit code.
func (p *conPTY) exit() int {
	p.t.Helper()
	if ev, err := windows.WaitForSingleObject(p.proc, 20000); err != nil || ev != windows.WAIT_OBJECT_0 {
		p.t.Fatalf("komando went on waiting (%v); the screen:\n%s", err, p.shown())
	}
	var code uint32
	if err := windows.GetExitCodeProcess(p.proc, &code); err != nil {
		p.t.Fatal(err)
	}
	return int(code)
}

// leftConsole says how komando left the console when it ended.
func (p *conPTY) leftConsole() (echo bool, left int) {
	p.t.Helper()
	b, err := os.ReadFile(p.report)
	if err != nil {
		p.t.Fatalf("komando reported nothing: %v; the screen:\n%s", err, p.shown())
	}
	var e string
	if _, err := fmt.Sscan(string(b), &e, &left); err != nil {
		p.t.Fatalf("report %q: %v", b, err)
	}
	return e == "true", left
}

// A yes typed at the [y/N] of a protected server runs the command.
func TestConPTYYesAtYesNo(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web", "u@10.0.0.1", "--protected")
	p := startConPTY(t, "host", "rm", "web")
	p.answer("[y/N]", "y\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("exit %d; the screen:\n%s", code, p.shown())
	}
	if echo, left := p.leftConsole(); !echo || left != 0 {
		t.Errorf("echo and line mode on %v, %d keys left", echo, left)
	}
	if st := mustState(t); st.Hosts["web"] != nil {
		t.Error("web is still there")
	}
}

// Ctrl-C at the [y/N] stops the command, and nothing changes.
func TestConPTYCtrlCAtYesNo(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web", "u@10.0.0.1", "--protected")
	p := startConPTY(t, "host", "rm", "web")
	p.answer("[y/N]", "\x03")
	if code := p.exit(); code != out.ExitPolicy {
		t.Errorf("exit %d, want %d; the screen:\n%s", code, out.ExitPolicy, p.shown())
	}
	p.waitFor("Nothing was changed on web.")
	if echo, _ := p.leftConsole(); !echo {
		t.Error("echo stayed off")
	}
	mustRun(t, "host", "show", "web") // still there
}

// A hidden answer is stored and never shows; the console gets its echo back.
func TestConPTYHiddenValue(t *testing.T) {
	invHome(t)
	p := startConPTY(t, "secret", "set", "s1")
	p.answer("(it stays hidden):", "s3cret\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("exit %d; the screen:\n%s", code, p.shown())
	}
	if strings.Contains(p.shown(), "s3cret") {
		t.Errorf("the hidden answer showed:\n%s", p.shown())
	}
	if v, err := vault.Get("s1"); err != nil || v != "s3cret" {
		t.Errorf("stored %q %v", v, err)
	}
	if echo, left := p.leftConsole(); !echo || left != 0 {
		t.Errorf("echo and line mode on %v, %d keys left", echo, left)
	}
}

// Ctrl-C at a hidden question stores nothing, and echo comes back.
func TestConPTYCtrlCAtHiddenPrompt(t *testing.T) {
	invHome(t)
	p := startConPTY(t, "secret", "set", "s1")
	p.answer("(it stays hidden):", "half-typed")
	time.Sleep(200 * time.Millisecond)
	if _, err := p.in.WriteString("\x03"); err != nil {
		t.Fatal(err)
	}
	if code := p.exit(); code != out.ExitError {
		t.Errorf("exit %d, want %d; the screen:\n%s", code, out.ExitError, p.shown())
	}
	if strings.Contains(p.shown(), "half-typed") {
		t.Errorf("the hidden answer showed:\n%s", p.shown())
	}
	if echo, _ := p.leftConsole(); !echo {
		t.Error("echo stayed off after Ctrl-C at a hidden prompt")
	}
	if _, err := vault.Get("s1"); err == nil {
		t.Error("a value was stored")
	}
}
