package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// One server that fails gives what went wrong there, never a bare FAILED
// (C79): a command that exited non-zero is COMMAND_FAILED (exit 5), any
// other failure is that server's own error (code, exit and hint).
func TestOneServerFailureCode(t *testing.T) {
	printed := func(run func()) map[string]any {
		var buf bytes.Buffer
		saved, savedF := tcl.out.W, tcl.out.Format
		tcl.out.W, tcl.out.Format = &buf, "json"
		defer func() { tcl.out.W, tcl.out.Format = saved, savedF }()
		run()
		var m map[string]any
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("%v: %s", err, buf.String())
		}
		e, _ := m["error"].(map[string]any)
		return e
	}
	one := runSummary{fleetSummary: fleetSummary{Total: 1, Failed: 1, FailedHosts: []string{"web1"}}}
	var err error
	e := printed(func() {
		err = finishFleet(tcl, "exec", struct{}{}, one, out.ExitRemote, []hostFail{{host: "web1", reason: "exit 7"}})
	})
	if e["code"] != "COMMAND_FAILED" || err != exitCode(out.ExitRemote) {
		t.Errorf("non-zero exit: %v", e)
	}
	refused := out.Errf(out.ExitConnect, "CONNECTION_REFUSED", "h", "refused")
	e = printed(func() {
		err = finishFleet(tcl, "exec", struct{}{}, one, out.ExitConnect, []hostFail{{host: "web1", reason: "connection refused", err: refused}})
	})
	if e["code"] != "CONNECTION_REFUSED" || e["hint"] != "h" || err != exitCode(out.ExitConnect) {
		t.Errorf("own error: %v", e)
	}
	// key deploy and revoke: the server's own error too
	e = printed(func() {
		_ = finish(tcl, "key.deploy", struct{}{}, one.fleetSummary, out.ExitConnect, refused)
	})
	if e["code"] != "CONNECTION_REFUSED" {
		t.Errorf("finish: %v", e)
	}
}
