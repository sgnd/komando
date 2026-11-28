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
//	ks_pgid PID    prints the process's group
//	ks_facts PID ID   prints the lines ParseFacts reads, between markers
//	                  that carry the session ID
//
// ks_start reads field 22 of /proc/PID/stat and ks_pgid field 5, counted
// after the last ")" because the command name may hold spaces; without
// /proc they ask ps (in the C locale for the start). busybox ps has no -p,
// but busybox systems have /proc.
const FactsScript = `ks_start() { if [ -r "/proc/$1/stat" ]; then ` +
	`t=$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f20); [ -z "$t" ] || echo "proc $t"; ` +
	`else t=$(LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | sed 's/^ *//;s/ *$//'); [ -z "$t" ] || echo "ps $t"; fi; }; ` +
	`ks_pgid() { if [ -r "/proc/$1/stat" ]; then sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f3; ` +
	`else ps -o pgid= -p "$1" 2>/dev/null | tr -d ' '; fi; }; ` +
	`ks_facts() { echo "facts-begin $2"; echo "pid $1"; echo "pgid $(ks_pgid "$1")"; echo "start $(ks_start "$1")"; echo "facts-end $2"; }`

var errFacts = errors.New("the server did not give the process's pid, group and start")

// ParseFacts reads ks_facts's lines for session id. Only the lines between
// its markers count (a login banner or a profile script may print first),
// each fact once. PID and group 0 and 1 are refused: a signal to either
// would reach far more than one run.
func ParseFacts(s, id string) (Facts, error) {
	var f Facts
	var seen int
	inside, ended := false, false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "facts-begin "+id && !inside && !ended:
			inside = true
			continue
		case line == "facts-end "+id && inside:
			inside, ended = false, true
			continue
		case !inside:
			continue
		}
		k, v, _ := strings.Cut(line, " ")
		v = strings.TrimSpace(v)
		bit := map[string]int{"pid": 1, "pgid": 2, "start": 4}[k]
		if bit == 0 {
			continue
		}
		if seen&bit != 0 {
			return Facts{}, errFacts
		}
		seen |= bit
		var err error
		switch k {
		case "pid":
			f.PID, err = strconv.Atoi(v)
		case "pgid":
			f.PGID, err = strconv.Atoi(v)
		case "start":
			f.Start = v
		}
		if err != nil {
			return Facts{}, errFacts
		}
	}
	if !ended || seen != 7 || f.PID <= 1 || f.PGID <= 1 || f.Start == "" {
		return Facts{}, errFacts
	}
	return f, nil
}
