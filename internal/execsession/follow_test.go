package execsession

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// fakeLog serves ReadScript calls from a log that grows by one piece per
// read; ended says the run is over once every piece is out.
type fakeLog struct {
	pieces []string
	log    string
	ended  bool
	exit   int // the read script's own exit, when not 0
	froms  []int64
}

func (f *fakeLog) read(_ context.Context, script string) (string, int, error) {
	if f.exit != 0 {
		return "", f.exit, nil
	}
	i := strings.Index(script, "tail -c +")
	n, _ := strconv.ParseInt(strings.Fields(script[i+len("tail -c +"):])[0], 10, 64)
	from := n - 1
	f.froms = append(f.froms, from)
	if len(f.pieces) > 0 {
		f.log += f.pieces[0]
		f.pieces = f.pieces[1:]
	}
	head := "read-begin " + testID + "\n"
	if f.ended && len(f.pieces) == 0 {
		head += "exit 3\n"
	}
	head += "size " + strconv.Itoa(len(f.log)) + "\nread-end " + testID + "\n"
	return head + f.log[min(int(from), len(f.log)):], 0, nil
}

func follow(from int64, wait time.Duration, agent bool, shown *strings.Builder) Follow {
	return Follow{Host: "web1", ID: testID, From: from, Wait: wait, Every: time.Millisecond,
		Lines: &Lines{Redact: hideTok, Agent: agent}, Show: func(s string) { shown.WriteString(s) }}
}

func TestFollowReadsToTheExit(t *testing.T) {
	f := &fakeLog{pieces: []string{"one\ntw", "o tok", "123\n", "last"}, ended: true}
	var shown strings.Builder
	res, err := follow(0, time.Second, false, &shown).Run(context.Background(), f.read)
	if err != nil || !res.Status.Ended() || res.Status.Exit != 3 {
		t.Fatalf("got %+v, %v", res, err)
	}
	if shown.String() != "one\ntwo [hidden]\nlast" || res.NextFrom != int64(len(f.log)) {
		t.Fatalf("shown %q, next_from %d", shown.String(), res.NextFrom)
	}
	// every read starts at a line start: the split token is read whole
	for _, from := range f.froms {
		if from != 0 && f.log[from-1] != '\n' {
			t.Fatalf("a read started inside a line at %d (%v)", from, f.froms)
		}
	}
}

func TestFollowFromAnOffset(t *testing.T) {
	f := &fakeLog{pieces: []string{"skip\nkeep\n"}, ended: true}
	var shown strings.Builder
	if _, err := follow(5, time.Second, false, &shown).Run(context.Background(), f.read); err != nil || shown.String() != "keep\n" {
		t.Fatalf("got %q, %v", shown.String(), err)
	}
}

func TestFollowWaitLimit(t *testing.T) {
	f := &fakeLog{pieces: []string{"a\nb"}}
	var shown strings.Builder
	res, err := follow(0, 30*time.Millisecond, false, &shown).Run(context.Background(), f.read)
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "SESSION_WAIT_TIMEOUT" || oe.Exit != out.ExitTimeout {
		t.Fatalf("got %v", err)
	}
	if res.NextFrom != 2 || !strings.Contains(oe.Hint, "`komando exec web1 --attach "+testID+" --offset 2`") {
		t.Fatalf("next_from %d, hint %q", res.NextFrom, oe.Hint)
	}
}

func TestFollowWaitZeroReadsOnce(t *testing.T) {
	f := &fakeLog{pieces: []string{"a\n", "b\n"}}
	var shown strings.Builder
	_, err := follow(0, 0, false, &shown).Run(context.Background(), f.read)
	if len(f.froms) != 1 || shown.String() != "a\n" || err == nil {
		t.Fatalf("reads %v, shown %q, err %v", f.froms, shown.String(), err)
	}
}

// next_from stays at the start of a line an agent is not shown.
func TestFollowNextFromAtALineStart(t *testing.T) {
	long := strings.Repeat("z", LineMax+1)
	f := &fakeLog{pieces: []string{"ok\n" + long}}
	var shown strings.Builder
	res, _ := follow(0, 20*time.Millisecond, true, &shown).Run(context.Background(), f.read)
	if res.NextFrom != 3 || shown.String() != "ok\n"+hiddenLine {
		t.Fatalf("next_from %d, shown %q", res.NextFrom, shown.String())
	}
}

func TestFollowRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit int
		code string
	}{
		{"gone", ExitGone, "SESSION_FOLDER_MISSING"},
		{"unsafe", ExitUnsafe, "SESSION_FOLDER_DENIED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var shown strings.Builder
			_, err := follow(0, time.Second, false, &shown).Run(context.Background(), (&fakeLog{exit: tc.exit}).read)
			var oe *out.Error
			if !errors.As(err, &oe) || oe.Code != tc.code {
				t.Fatalf("exit %d gave %v, want %s", tc.exit, err, tc.code)
			}
		})
	}
}

func TestTruncatedSaysAtLeast(t *testing.T) {
	if got := (Status{Truncated: 512}).TruncatedNote(); got != "at least 512 bytes past the log cap were dropped" {
		t.Fatalf("got %q", got)
	}
	if got := (Status{}).TruncatedNote(); got != "" {
		t.Fatalf("got %q with nothing dropped", got)
	}
}
