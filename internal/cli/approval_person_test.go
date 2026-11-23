package cli

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// TestApprovalWindowPerson shows the real macOS approval window, through
// the same steps as an agent's protected exec --script (guard, the panel,
// the device-owner check), with a 150-line dummy script, for a person to
// check by hand. Nothing runs: the host is a made-up one and no command
// follows the answer. It is skipped unless KOMANDO_WINDOW_PERSON=1, and it
// prints the answer at the end.
func TestApprovalWindowPerson(t *testing.T) {
	if os.Getenv("KOMANDO_WINDOW_PERSON") != "1" {
		t.Skip("shows a window for a person: set KOMANDO_WINDOW_PERSON=1 on a Mac")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	saved := tcl.args
	t.Cleanup(func() { tcl.args = saved; tcl.flags.yes = false; resetApproval() })
	setCallerEnv(t, "CLAUDECODE", "1")
	st := &store.State{Hosts: map[string]*store.Host{"window-check": {Name: "window-check", Address: "192.0.2.10", Protected: true}}}
	tcl.flags.yes = true
	tcl.args = []string{"komando", "exec", "window-check", "--script", "./window-check.sh", "--yes"}
	var body strings.Builder
	body.WriteString("#!/bin/sh\n# a dummy script for checking the approval window; it never runs\n")
	for i := 3; i <= 149; i++ {
		fmt.Fprintf(&body, "echo 'line %d of 150'\n", i)
	}
	body.WriteString("echo 'LAST LINE 150'\n")
	resetApproval()
	noteApprovalScript(tcl, scriptLabel("the script", "./window-check.sh"), []byte(body.String()))
	err := guard(tcl, st, []*store.Host{st.Hosts["window-check"]}, "sh -s", true)
	w := tcl.sess.Window()
	switch {
	case err == nil:
		fmt.Println("RESULT: ALLOWED (Allow once, then the device-owner check passed); nothing was run")
	case w.Why == "":
		fmt.Printf("RESULT: NO WINDOW: %v\n", err)
	default:
		fmt.Printf("RESULT: NOT ALLOWED (%s); nothing was run\n", w.Why)
	}
}
