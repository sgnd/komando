package cli

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// fetchStatus asks the server how a job is doing.
func fetchStatus(ctx context.Context, c *sshx.Client, j *store.Job, tail int) (*jobStatus, error) {
	// the end time is when the exit (or killed) file was written, so the
	// runtime of a finished job stays put
	script := `d="` + jobDir(j.ID) + `"; [ -d "$d" ] || { echo LOST; exit 0; }; end=$(date -u +%s); ` +
		`if [ -f "$d/exit" ]; then echo "EXIT $(cat "$d/exit")"; end=$(date -u -r "$d/exit" +%s 2>/dev/null || echo $end); ` +
		`elif ` + jobAlive(j.PID) + `; then echo RUNNING; ` +
		`elif [ -f "$d/killed" ]; then echo "KILLED $(cat "$d/killed")"; end=$(date -u -r "$d/killed" +%s 2>/dev/null || echo $end); ` +
		`else echo LOST; fi; ` +
		`wc -c < "$d/out.log" 2>/dev/null || echo 0; cat "$d/started" 2>/dev/null || echo 0; echo $end`
	if tail > 0 {
		script += `; echo ---TAIL---; tail -n ` + strconv.Itoa(tail) + ` "$d/out.log" 2>/dev/null`
	}
	// the last line says the answer is whole: a connection cut halfway leaves
	// it out, and half an answer must never read as "the job is lost"
	script += "; echo " + statusEnd
	o, _, err := sshx.Output(ctx, c, script, 30*time.Second)
	if err != nil {
		return nil, err
	}
	o, whole := strings.CutSuffix(strings.TrimRight(o, "\n"), statusEnd)
	if !whole {
		return nil, out.Errf(out.ExitConnect, "CONNECTION_LOST", "run it again; the job keeps running on the server", "the connection to %s broke while reading the job's status", j.Host)
	}
	head, tailOut, _ := strings.Cut(o, "---TAIL---\n")
	lines := strings.Split(strings.TrimSpace(head), "\n")
	s := &jobStatus{ID: j.ID, Host: j.Host, Command: j.Command, PID: j.PID, StartedAt: j.StartedAt.Format(time.RFC3339), Tail: tailOut}
	if len(lines) > 0 {
		switch {
		case lines[0] == "RUNNING":
			s.State = "running"
		case strings.HasPrefix(lines[0], "EXIT "):
			s.State = "exited"
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(lines[0], "EXIT "))); err == nil {
				s.ExitCode = &n
			}
		case strings.HasPrefix(lines[0], "KILLED"):
			s.State = "killed"
			// job kill writes the signal; job start --timeout "TERM timeout"
			f := strings.Fields(strings.TrimPrefix(lines[0], "KILLED"))
			if len(f) > 0 {
				s.Signal = f[0]
			}
			s.TimedOut = len(f) > 1 && f[1] == "timeout"
		default:
			s.State = "lost"
		}
	}
	if len(lines) >= 4 {
		s.LogBytes, _ = strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
		startU, _ := strconv.ParseInt(strings.TrimSpace(lines[2]), 10, 64)
		nowU, _ := strconv.ParseInt(strings.TrimSpace(lines[3]), 10, 64)
		if startU > 0 {
			s.RuntimeSec = nowU - startU
		}
	}
	noteJobEnd(j, s.State)
	return s, nil
}

// noteJobEnd remembers that a job ended, so Running now leaves it out
// without asking its server again. A failed save only costs that memory.
func noteJobEnd(j *store.Job, state string) {
	if state == "" || state == "running" || j.Ended == state {
		return
	}
	j.Ended = state
	_ = store.Update(func(st *store.State) error {
		if sj := st.Jobs[j.ID]; sj != nil {
			sj.Ended = state
		}
		return nil
	})
}
