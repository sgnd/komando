package execsession

import (
	"errors"
	"strconv"
	"strings"
)

// Facts are what the server says about a run's process when it starts:
// its PID, its process group, and when it started. They go to the record
// on this computer, and a stop checks the start again before it signals,
// so a PID the system gave to another process is never signalled.
type Facts struct {
	PID   int
	PGID  int
	Start string // "proc TICKS" (Linux, /proc/PID/stat field 22) or "ps LSTART"
}

// FactsScript defines two shell functions:
//
//	ks_start PID   prints the process's start, or nothing when it is gone
//	ks_facts PID   prints the lines ParseFacts reads
//
// ks_start reads field 22 of /proc/PID/stat, counted after the last ")"
// because the command name may hold spaces; without /proc it asks ps in
// the C locale.
const FactsScript = `ks_start() { if [ -r "/proc/$1/stat" ]; then ` +
	`t=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f20); [ -z "$t" ] || echo "proc $t"; ` +
	`else t=$(LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | sed 's/^ *//;s/ *$//'); [ -z "$t" ] || echo "ps $t"; fi; }; ` +
	`ks_facts() { echo "pid $1"; echo "pgid $(ps -o pgid= -p "$1" 2>/dev/null | tr -d ' ')"; echo "start $(ks_start "$1")"; }`

var errFacts = errors.New("the server did not give the process's pid, group and start")

// ParseFacts reads ks_facts's lines; other lines before them are skipped.
// PID and group 0 and 1 are refused: a signal to either would reach far
// more than one run.
func ParseFacts(s string) (Facts, error) {
	var f Facts
	var seen int
	for _, line := range strings.Split(s, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		v = strings.TrimSpace(v)
		var err error
		switch k {
		case "pid":
			f.PID, err = strconv.Atoi(v)
			seen |= 1
		case "pgid":
			f.PGID, err = strconv.Atoi(v)
			seen |= 2
		case "start":
			f.Start = v
			seen |= 4
		}
		if err != nil {
			return Facts{}, errFacts
		}
	}
	if seen != 7 || f.PID <= 1 || f.PGID <= 1 || f.Start == "" {
		return Facts{}, errFacts
	}
	return f, nil
}
