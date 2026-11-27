package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// A connection that breaks while the command runs is CONNECTION_LOST
// (exit 4), with the output that came before it, on each server; not a
// bare exit -1.
func TestExecConnectionLost(t *testing.T) {
	srv := startFakeServer(t)
	srv.reply("step 1 done\n", dropMark)
	var err error
	got := captureOutput(t, func() error {
		err = runRoot(t, "exec", "dev", "--read-only", "--", "uptime")
		return err
	})
	if code, ok := err.(exitCode); !ok || int(code) != 4 {
		t.Fatalf("want exit 4, got %v\n%s", err, got)
	}
	var env struct {
		Data struct {
			Results []struct {
				ExitCode int    `json:"exit_code"`
				Stdout   string `json:"stdout"`
				Error    struct {
					Code    string `json:"code"`
					Message string `json:"message"`
					Hint    string `json:"hint"`
				} `json:"error"`
			} `json:"results"`
		} `json:"data"`
		Error struct {
			Code string `json:"code"`
			Hint string `json:"hint"`
		} `json:"error"`
	}
	if e := json.Unmarshal([]byte(got), &env); e != nil {
		t.Fatalf("%v\n%s", e, got)
	}
	if env.Error.Code != "CONNECTION_LOST" || !strings.Contains(env.Error.Hint, "session") {
		t.Fatalf("top error: %+v", env.Error)
	}
	r := env.Data.Results[0]
	if r.Error.Code != "CONNECTION_LOST" || r.Stdout != "step 1 done\n" || r.ExitCode != -1 ||
		!strings.Contains(r.Error.Message, "may still be running") {
		t.Fatalf("result: %+v", r)
	}
}
