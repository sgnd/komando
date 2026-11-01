package netx

import (
	"os"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// A bad pid must never reach kill(2): -1 signals every process of the
// user, 0 the process group, 1 init.
func TestTerminateRefusesDangerousPids(t *testing.T) {
	for _, pid := range []int{-1, 0, 1, os.Getpid()} {
		if err := Terminate(pid); err == nil {
			t.Errorf("Terminate(%d) must refuse", pid)
		}
		if pid != os.Getpid() && Alive(pid) {
			t.Errorf("Alive(%d) must be false", pid)
		}
	}
	StopSession(&store.VpnSession{PID: -1}) // must do nothing (the test process survives)
	StopSession(&store.VpnSession{PID: 0})
}
