package netx

import (
	"os"
	"strconv"
	"strings"
)

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
	// the program's name, in brackets, may hold spaces: count after it
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return ""
	}
	f := strings.Fields(s[i+1:])
	// after the name: state is field 3, start time field 22
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
