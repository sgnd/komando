package cli

import (
	"context"
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// tcl is the call the tests run komando's code in: the process's
// environment, input and output, as the komando program makes its call.
// Tests run one at a time, so they share it; resetApproval starts a new
// command in it.
var tcl = newCall(processCall(), nil)

// resetApproval starts a new command in tcl: the caller is read again from
// the environment (a test that sets CLAUDECODE becomes an agent), and no
// answer given so far counts.
func resetApproval() { tcl.begin(nil) }

// setCallerEnv sets the environment variable key to value for the rest of
// the test and reads tcl's caller again (a test that sets CLAUDECODE
// becomes an agent). When the test ends, the variable is restored first
// and the caller read again after it: cleanups run last-registered first,
// so the one that reads the caller is registered before t.Setenv's.
func setCallerEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Cleanup(resetApproval)
	t.Setenv(key, value)
	resetApproval()
}

// gateFlag is one of the four global flags that decide the safety gate.
type gateFlag int

const (
	gateDryRun gateFlag = iota
	gateYes
	gateAllowDangerous
	gateReveal
)

// setGate turns the gate flags fs of cl on or off, as the command line
// would, for the running command: it stores a changed copy of the gate,
// as the program never does after the command starts. It is the only way
// a test sets one (TestTestsWriteTheGateThroughHelpers).
func setGate(cl *call, on bool, fs ...gateFlag) {
	g := *cl.gate()
	for _, f := range fs {
		switch f {
		case gateDryRun:
			g.dryRun = on
		case gateYes:
			g.yes = on
		case gateAllowDangerous:
			g.allowDangerous = on
		case gateReveal:
			g.reveal = on
		default:
			panic("setGate: unknown gate flag")
		}
	}
	cl.g.Store(&g)
}

// savedFlags is every global flag of a call and its gate, as a test found
// them.
type savedFlags struct {
	cl *call
	f  globalFlags
	g  *gate
}

// saveFlags keeps cl's global flags and its gate for restore.
func saveFlags(cl *call) savedFlags { return savedFlags{cl: cl, f: cl.flags, g: cl.gate()} }

// restore puts back the global flags and the gate saveFlags kept.
func (s savedFlags) restore() {
	s.cl.flags = s.f
	s.cl.g.Store(s.g)
}

// clearFlags sets every global flag of cl to its default and turns the
// gate's four off; the caller stays.
func clearFlags(cl *call) {
	cl.flags = globalFlags{}
	setGate(cl, false, gateDryRun, gateYes, gateAllowDangerous, gateReveal)
}

// setTestCaller makes c the caller of cl, until the next command reads it
// again from the environment (begin). Tests only: the program reads the
// caller from the environment, and asAgent can only make it an agent.
func setTestCaller(cl *call, c engine.Caller) {
	g := *cl.gate()
	g.who = c
	cl.g.Store(&g)
}

// testCall is a new call made like tcl, apart from it.
func testCall() *call { return newCall(processCall(), nil) }

// executeArgs runs komando with args in tcl, as the program does, and
// closes the store after it (Windows cannot remove a file still open).
func executeArgs(args []string) int {
	defer store.Close()
	defer tcl.enter() // still running for the hooks (TestMain)
	defer endCommand()
	tcl.args = append([]string{"komando"}, args...)
	return execute(tcl, context.Background(), args)
}

// realRun is the printer of a real run, not a dry run, for a result's
// TextFor in a test that runs no command: tcl.out keeps what the last
// command of an earlier test set on it until the next command starts.
func realRun() *out.Printer { return &out.Printer{} }

// endCommand leaves tcl as it is between two commands: the global flags
// and the printer's settings of the command just run (--dry-run, masking
// ...), and its leave to look at an old copy of the store, are not in
// effect for code a later test calls without running a command. What the
// command recorded (tcl.out.Blocked ...) stays for the test to read; the
// next command forgets it (newRoot).
func endCommand() {
	clearFlags(tcl)
	tcl.oldCopy.Store(false)
	tcl.out.DryRun, tcl.out.Pretty, tcl.out.Mask, tcl.out.Personal, tcl.out.NoRedact = false, false, false, false, false
}
