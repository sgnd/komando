package netx

import (
	"strconv"

	"golang.org/x/sys/unix"
)

// startTimesKnown: this system tells when a process started.
const startTimesKnown = true

// ProcessStart is when pid started, to the microsecond, as the kernel
// keeps it; "" when there is no such process.
func ProcessStart(pid int) string {
	if pid <= 0 {
		return ""
	}
	p, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || p == nil || int(p.Proc.P_pid) != pid {
		return ""
	}
	t := p.Proc.P_starttime
	return strconv.FormatInt(t.Sec, 10) + "." + strconv.FormatInt(int64(t.Usec), 10)
}
