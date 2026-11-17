package netx

import "strings"

// statStart is the start time in a Linux /proc/PID/stat line: field 22,
// counted after the program's name, which is in brackets and may hold
// spaces and brackets itself. "" when the line is too short.
func statStart(line string) string {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return ""
	}
	f := strings.Fields(line[i+1:])
	// after the name: state is field 3, start time field 22
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
