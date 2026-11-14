package engine

import (
	"context"
	"os/exec"
	"sync/atomic"
	"syscall"
)

// Platform is what the device komando runs on can do. On a computer it can
// do everything. An app that links the engine (the iPhone app) cannot
// start programs or open a terminal, and says so once, before its first
// call (SetPlatform). It is a capability, not a check of the operating
// system, so tests can close it on any computer and the Mac build an app's
// tests use behaves like the phone.
type Platform struct {
	// StartPrograms: komando may start other programs (a dump tool, a
	// browser, the keychain tool, its own background processes).
	StartPrograms bool
	// Terminal: a person can use an interactive terminal here (shell,
	// db shell).
	Terminal bool
}

// Need is one thing a command may need from the device, as
// NOT_ON_THIS_DEVICE's error.details.needs and `komando schema` name it.
type Need string

const (
	// NeedProgram: another program on this device (pg_dump, a kubeconfig's
	// credential plugin, a browser).
	NeedProgram Need = "program"
	// NeedTerminal: an interactive terminal.
	NeedTerminal Need = "terminal"
	// NeedSystemVPN: the operating system's own VPN settings.
	NeedSystemVPN Need = "system_vpn"
	// NeedBackground: a komando process that keeps running after the
	// command ends (a tunnel, a VPN session, a two-factor login).
	NeedBackground Need = "background"
)

// Needs is every Need, in the order the documentation lists them.
var Needs = []Need{NeedProgram, NeedTerminal, NeedSystemVPN, NeedBackground}

var platform atomic.Pointer[Platform]

func init() { platform.Store(&Platform{StartPrograms: true, Terminal: true}) }

// SetPlatform says what this device can do, for every call in the
// process. The CLI never calls it; an app calls it once, before its first
// call.
func SetPlatform(p Platform) { platform.Store(&p) }

// CurrentPlatform is what SetPlatform set (everything on a computer).
func CurrentPlatform() Platform { return *platform.Load() }

// Has reports whether this device can give n.
func Has(n Need) bool {
	p := CurrentPlatform()
	if n == NeedTerminal {
		return p.Terminal
	}
	// a background process, the system's VPN tools and any other program
	// are all programs komando would start
	return p.StartPrograms
}

// NotHereError is a step this device cannot take, whatever flag is given:
// the CLI shows it as NOT_ON_THIS_DEVICE (exit 8).
type NotHereError struct {
	Needs Need
	// What names the program or the part that is missing ("pg_dump", "a
	// terminal").
	What string
	// Hint is the way that works on this device, when there is one ("" for
	// the usual: run it on a computer with komando).
	Hint string
}

func (e *NotHereError) Error() string {
	return "this needs " + e.What + ", which this device cannot start"
}

// Require is nil when this device can give n, else a *NotHereError naming
// what.
func Require(n Need, what string) error {
	if Has(n) {
		return nil
	}
	return &NotHereError{Needs: n, What: what}
}

// StartProgram is the only place komando makes a program to run: it is
// exec.CommandContext (exec.Command when ctx is nil) on a device that can
// start programs, and a *NotHereError (needs program) on one that cannot.
// The caller sets the command's input, output and environment, and starts
// it. A test in this package fails when any other code calls exec.Command,
// exec.CommandContext, exec.LookPath, os.StartProcess or syscall.Exec.
func StartProgram(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	if err := Require(NeedProgram, name); err != nil {
		return nil, err
	}
	if ctx == nil {
		return exec.Command(name, args...), nil
	}
	return exec.CommandContext(ctx, name, args...), nil
}

// LookPath is exec.LookPath on a device that can start programs. On one
// that cannot, no program is found: a *NotHereError (needs program).
func LookPath(name string) (string, error) {
	if err := Require(NeedProgram, name); err != nil {
		return "", err
	}
	return exec.LookPath(name)
}

// ReplaceProcess replaces this process with the program argv0 (syscall.Exec),
// as ssh-gate does with the komando it runs. On a device that cannot start
// programs it returns a *NotHereError.
func ReplaceProcess(argv0 string, argv, env []string) error {
	if err := Require(NeedProgram, argv0); err != nil {
		return err
	}
	return syscall.Exec(argv0, argv, env)
}
