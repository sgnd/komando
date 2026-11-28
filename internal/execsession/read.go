package execsession

import (
	"errors"
	"strconv"
	"strings"
)

// ExitGone is the read script's exit when the session folder or its log
// is not there.
const ExitGone = 95

// Status is what a read says about the run.
type Status struct {
	Size      int64  // bytes in out.log when it was read
	Exit      int    // the run's exit code, once it ended on its own
	Killed    string // why the timeout watcher stopped it
	Truncated int64  // bytes dropped past the log cap
	Lost      bool   // the run's process died without writing exit or killed (a reboot, an OOM kill)
	ended     bool
}

// Ended says that the run is over: its exit code is written, or it was
// stopped, or found lost. Size is then final.
func (s Status) Ended() bool { return s.ended }

// ReadScript is the shell text that reads a session from byte from on: it
// checks on every read that ~/.komando, sessions, the session folder and
// its files are the login user's and not links (exit ExitUnsafe; a
// missing one exits ExitGone), prints the status between markers that
// carry the ID and then at most ReadMax bytes of out.log. The exit file is
// read before the size: the wrapper writes it only after the log is
// complete. It deletes nothing.
func ReadScript(id string, from int64) (string, error) {
	if err := CheckID(id); err != nil {
		return "", err
	}
	if from < 0 {
		return "", errors.New("session read: a negative offset")
	}
	return `r="$HOME/.komando"; s="$r/sessions"; d="$s/` + id + `"; ` +
		`ks_own() { if [ -L "$1" ]; then exit 90; fi; [ -e "$1" ] || exit 95; { [ -d "$1" ] && [ -O "$1" ]; } || exit 90; }; ` +
		`ks_own "$r"; ks_own "$s"; ks_own "$d"; ` +
		`for f in out.log exit killed truncated lost; do [ ! -L "$d/$f" ] || exit 90; done; [ -f "$d/out.log" ] || exit 95; ` +
		`echo "read-begin ` + id + `"; ` +
		`[ ! -f "$d/exit" ] || echo "exit $(head -c 16 "$d/exit" | tr -d '\r\n')"; ` +
		`[ ! -f "$d/killed" ] || echo "killed $(head -c 64 "$d/killed" | tr -d '\r\n')"; ` +
		`[ ! -f "$d/lost" ] || echo "lost"; ` +
		`[ ! -f "$d/truncated" ] || echo "truncated $(head -c 24 "$d/truncated" | tr -d '\r\n')"; ` +
		`echo "size $(wc -c < "$d/out.log" | tr -d ' ')"; echo "read-end ` + id + `"; ` +
		`tail -c +` + strconv.FormatInt(from+1, 10) + ` "$d/out.log" | head -c ` + strconv.Itoa(ReadMax), nil
}

var errRead = errors.New("the server did not give the session's status")

// ParseRead reads ReadScript's output for session id: the status lines
// between its markers, each once, and the log bytes after the end marker.
func ParseRead(s, id string) (Status, []byte, error) {
	begin, end := "read-begin "+id+"\n", "read-end "+id+"\n"
	i := strings.Index(s, begin)
	if i < 0 {
		return Status{}, nil, errRead
	}
	head, data, ok := strings.Cut(s[i+len(begin):], end)
	if !ok {
		return Status{}, nil, errRead
	}
	var st Status
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(head, "\n"), "\n") {
		k, v, _ := strings.Cut(line, " ")
		if seen[k] {
			return Status{}, nil, errRead
		}
		seen[k] = true
		var err error
		switch k {
		case "size":
			st.Size, err = strconv.ParseInt(v, 10, 64)
		case "exit":
			st.Exit, err = strconv.Atoi(v)
			st.ended = true
		case "killed": // the run can write it: only spaces are no mark
			if v = strings.TrimSpace(v); v != "" {
				st.Killed, st.ended = v, true
			}
		case "lost":
			st.Lost, st.ended = v == "", true
			if !st.Lost {
				err = errRead
			}
		case "truncated":
			st.Truncated, err = strconv.ParseInt(v, 10, 64)
		default:
			err = errRead
		}
		if err != nil {
			return Status{}, nil, errRead
		}
	}
	if !seen["size"] || st.Size < 0 {
		return Status{}, nil, errRead
	}
	return st, []byte(data), nil
}
