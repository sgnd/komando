package netx

import (
	"os"
	"strconv"
)

// startTimesKnown: this system tells when a process started.
const startTimesKnown = true

// ProcessStart is when pid started, in clock ticks after the system
// booted (field 22 of /proc/PID/stat); "" when there is no such process.
func ProcessStart(pid int) string {
	if pid <= 0 {
		return ""
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	return statStart(string(b))
}
