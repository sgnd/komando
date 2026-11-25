package execsession

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// Reader runs a shell script on the server and gives its stdout and exit.
type Reader func(ctx context.Context, script string) (string, int, error)

// Follow reads a session's log from From on, through Lines, until the run
// ends or Wait passes. It only reads: it deletes nothing on the server.
type Follow struct {
	Host, ID string
	From     int64
	Wait     time.Duration // 0: one read
	Every    time.Duration // the pause after a read that found nothing new
	Lines    *Lines
	Show     func(string)
}

// Followed is where a follow stopped.
type Followed struct {
	Status   Status
	NextFrom int64 // the offset a later read starts from: always a line start
}

// Run follows the log. It ends with the run's status once the log is read
// to its end, or with SESSION_WAIT_TIMEOUT, whose hint names the attach
// that reads on from NextFrom.
func (f Follow) Run(ctx context.Context, read Reader) (Followed, error) {
	deadline := time.Now().Add(f.Wait)
	from := f.From
	pause := time.NewTimer(0)
	defer pause.Stop()
	<-pause.C
	for {
		script, err := ReadScript(f.ID, from)
		if err != nil {
			return Followed{NextFrom: from}, err
		}
		stdout, exit, err := read(ctx, script)
		if err != nil {
			return Followed{NextFrom: from}, err
		}
		if err := f.readExit(exit); err != nil {
			return Followed{NextFrom: from}, err
		}
		st, data, err := ParseRead(stdout, f.ID)
		if err != nil {
			return Followed{NextFrom: from}, fmt.Errorf("%s: %w", f.Host, err)
		}
		end := st.Ended() && from+int64(len(data)) >= st.Size
		text, used := f.Lines.Read(data, end)
		f.Show(text)
		from += int64(used)
		res := Followed{Status: st, NextFrom: from - int64(f.Lines.Open())}
		if end {
			return res, nil
		}
		if !time.Now().Before(deadline) {
			return res, out.Errf(out.ExitTimeout, "SESSION_WAIT_TIMEOUT",
				"it is still running: `komando exec "+f.Host+" --attach "+f.ID+" --offset "+strconv.FormatInt(res.NextFrom, 10)+"` reads on",
				"session %s on %s still running after %s", f.ID, f.Host, f.Wait)
		}
		if len(data) < ReadMax {
			pause.Reset(f.Every)
			select {
			case <-ctx.Done():
				return res, ctx.Err()
			case <-pause.C:
			}
		}
	}
}

func (f Follow) readExit(exit int) error {
	switch exit {
	case 0:
		return nil
	case ExitGone:
		return out.Errf(out.ExitNotFound, "SESSION_FOLDER_MISSING",
			"check the ID and the server: a session is removed once its starter read it to the end, or after 7 days; `komando audit` shows the exec that started it",
			"no session %s on %s", f.ID, f.Host)
	case ExitUnsafe:
		return folderDenied(f.Host)
	}
	return fmt.Errorf("%s: the session read failed (exit %d)", f.Host, exit)
}

// TruncatedNote says how much output past the log cap was dropped. The
// count is a lower bound: head may read past the cap into its buffer
// before the rest is counted.
func (s Status) TruncatedNote() string {
	if s.Truncated <= 0 {
		return ""
	}
	return "at least " + strconv.FormatInt(s.Truncated, 10) + " bytes past the log cap were dropped"
}
