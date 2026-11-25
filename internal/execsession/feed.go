package execsession

import (
	"strconv"
	"time"
)

// Feed sends a run's env and input to its command, in that order,
// deleting each file once it is sent; a sudo password goes first (pw).
// The files are in $d.
func Feed(pw bool) string {
	f := `{ `
	if pw {
		f += `cat "$d/pw"; rm -f "$d/pw"; `
	}
	return f + `[ ! -f "$d/env" ] || { cat "$d/env"; rm -f "$d/env"; }; [ ! -f "$d/in" ] || { cat "$d/in"; rm -f "$d/in"; }; }`
}

// Wrapper is job start's root process: it runs start with the login's own
// umask ($1, so the run's environment gains no variable) and writes its
// exit code, unless the run was stopped (killed).
func Wrapper(start string, timeout time.Duration) string {
	watch, end := watcher(timeout)
	// the env (vault values), the input and the sudo password go once the
	// run ends, also when sudo refused it before they were sent and deleted
	return `umask "$1"; ` + start + `; umask 077; ` + watch + end + `[ -f "$d/killed" ] || echo $c > "$d/exit"; rm -f "$d/env" "$d/in" "$d/pw"`
}

// watcher is the wait for the run (w) that sets c to its exit code. With a
// timeout, a watcher stops the run after it, the whole process group
// (setsid) or else the command, and notes "TERM timeout" in killed.
func watcher(timeout time.Duration) (watch, end string) {
	end = `wait $w 2>/dev/null; c=$?; `
	if timeout > 0 {
		secs := strconv.Itoa(int((timeout + time.Second - 1) / time.Second))
		watch = `( trap 'kill $t 2>/dev/null; exit 0' TERM; sleep ` + secs + ` & t=$!; wait $t; ` +
			`kill -0 $w 2>/dev/null && { printf 'TERM timeout\n' > "$d/killed"; kill -TERM -$$ 2>/dev/null || kill -TERM $w; } ) & s=$!; `
		end += `kill $s 2>/dev/null; `
	}
	return watch, end
}
