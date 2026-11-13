package cli

import (
	"context"
	"testing"

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
func resetApproval() { tcl.begin() }

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

// testCall is a new call made like tcl, apart from it.
func testCall() *call { return newCall(processCall(), nil) }

// executeArgs runs komando with args in tcl, as the program does, and
// closes the store after it (Windows cannot remove a file still open).
func executeArgs(args []string) int {
	defer store.Close()
	defer tcl.enter() // still running for the hooks (TestMain)
	tcl.args = append([]string{"komando"}, args...)
	return tcl.execute(context.Background(), args)
}
