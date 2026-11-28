package execsession

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// ExitNoSpace is the start script's exit when the home file system has
// less free space than the log cap plus 5% of the disk.
const ExitNoSpace = 93

// ExitNoGroup is the start script's exit when the run would not lead its
// own process group (setsid gave none, or the root process never came up):
// nothing of the command ran, and the folder is gone.
const ExitNoGroup = 94

// Start is what one run in a session needs.
type Start struct {
	ID       string
	Shown    string        // the command as shown: the cmd file holds it
	Run      string        // the shell text that starts the run in the background and sets w to its PID (Feed piped into it)
	Env      int           // bytes of env exports at the head of the input
	Password int           // bytes of the sudo password after them
	Input    bool          // the rest of the input is the command's own
	Timeout  time.Duration // the run is stopped after it; 0: no limit
	LogMax   int64         // out.log's cap in bytes
}

// StartScript is the one shell call that starts a run in a session: it
// checks free space, makes the folder (FolderScript), saves the input in
// private files, starts the wrapper under setsid nohup (plain nohup where
// there is no setsid) and prints the run's facts (FactsScript). Its exit is
// ExitNoSpace, ExitUnsafe or ExitNoFolder when it starts nothing.
func StartScript(s Start) (string, error) {
	folder, err := FolderScript(s.ID)
	if err != nil {
		return "", err
	}
	if s.LogMax <= 0 {
		return "", errors.New("session start: no log cap")
	}
	capKiB := strconv.FormatInt((s.LogMax+1023)/1024, 10)
	// df -P: field 2 is the size, field 4 the free space, in KiB; a df that
	// cannot tell leaves the start to the log cap alone
	space := `df -Pk "$HOME" 2>/dev/null | awk -v cap=` + capKiB + ` 'NR == 2 && $4 + 0 < cap + $2 / 20 { exit 1 }' || exit ` + strconv.Itoa(ExitNoSpace) + `; `
	saves := ""
	if s.Env > 0 {
		saves += sshx.SaveInput(s.Env, `"$d/env"`) + ` && `
	}
	if s.Password > 0 {
		saves += sshx.SaveInput(s.Password, `"$d/pw"`) + ` && `
	}
	if s.Input {
		saves += `cat > "$d/in" && `
	}
	w := sshx.Q(wrapper(s.Run, s.Timeout, s.LogMax))
	noGroup := strconv.Itoa(ExitNoGroup)
	return `u=$(umask); ` + space + folder + `; ` +
		`{ ` + saves + `printf '%s\n' ` + sshx.Q(s.Shown) + ` > "$d/cmd" && date -u +%s > "$d/started" && : > "$d/out.log" && mkfifo "$d/.o"; } || { rm -rf "$d"; exit ` + strconv.Itoa(ExitNoFolder) + `; }; ` +
		`export d; if command -v setsid >/dev/null 2>&1; then setsid nohup sh -c ` + w + ` sh "$u" >/dev/null 2>&1 </dev/null & g=1; ` +
		`else nohup sh -c ` + w + ` sh "$u" >/dev/null 2>&1 </dev/null & g=; fi; ` +
		// the root process writes its own PID and waits for .go: the facts
		// are its own, and with setsid it must lead its own group before
		// anything of the command runs, or the start fails
		FactsScript + `; p=; i=0; while [ $i -lt 20 ]; do p=$(cat "$d/.w" 2>/dev/null); [ -n "$p" ] && break; sleep 0.1 2>/dev/null || sleep 1; i=$((i+1)); done; ` +
		`case "$p" in ''|*[!0-9]*) rm -rf "$d"; exit ` + noGroup + `;; esac; ` +
		`i=0; while [ -n "$g" ] && [ "$(ks_pgid "$p")" != "$p" ]; do ` +
		`[ $i -lt 10 ] || { kill -TERM "$p" 2>/dev/null; rm -rf "$d"; exit ` + noGroup + `; }; sleep 0.1 2>/dev/null || sleep 1; i=$((i+1)); done; ` +
		`echo "$p" > "$d/pid"; : > "$d/.go"; ks_facts "$p" ` + s.ID, nil
}

// wrapper is the session's root process. It first writes its PID to .w
// and waits up to 5 s for .go from the start script. Its output and the run's go
// through the fifo .o into the capper, which keeps the first max bytes in
// out.log and counts the rest into truncated; the capper starts before the
// login's umask comes back, so its files stay private. exit is written
// through exit.tmp once the capper is done (or 3 s after the run, when a
// child the run left still holds the output open), and after the input
// files and the fifo are gone: a reader that sees exit sees them gone. It
// is written also after a stop's killed mark, which a stop that signalled
// nothing takes back (the run ended on its own meanwhile).
func wrapper(start string, timeout time.Duration, max int64) string {
	watch, end := watcher(timeout)
	// the group's TERM (a stop, the timeout) ends the run, not its ending: the
	// root traps it and hands it to the run (without setsid only the root gets
	// it); the capper ignores it, so head writes what it holds
	return `trap '[ -z "$w" ] || kill -TERM $w 2>/dev/null' TERM; echo $$ > "$d/.w"; i=0; while [ ! -e "$d/.go" ] && [ $i -lt 50 ]; do sleep 0.1 2>/dev/null || sleep 1; i=$((i+1)); done; ` +
		`[ -e "$d/.go" ] || exit 0; rm -f "$d/.w" "$d/.go"; ` +
		`{ trap '' TERM; head -c ` + strconv.FormatInt(max, 10) + ` > "$d/out.log"; n=$(wc -c | tr -d ' '); [ "$n" = 0 ] || echo "$n" > "$d/truncated"; } < "$d/.o" & k=$!; ` +
		`exec > "$d/.o" 2>&1; umask "$1"; ` + start + `; umask 077; ` + watch + end +
		`exec > /dev/null 2>&1; i=0; while kill -0 $k 2>/dev/null && [ $i -lt 3 ]; do sleep 1; i=$((i+1)); done; ` +
		`rm -f "$d/env" "$d/in" "$d/pw" "$d/.o"; echo $c > "$d/exit.tmp" && mv "$d/exit.tmp" "$d/exit"`
}

// ErrNoFolder: no session folder can be made on the server (a read-only or
// full home). The start ran nothing of the command, but it read the input,
// so a run without a session sends the input again in a new call. Only
// this exit falls back: every other refusal stands.
var ErrNoFolder = errors.New("no session folder can be made in the login user's home")

// ReadStart reads what StartScript printed and its exit on host: the run's
// facts, and the "warning" lines the folder check printed before them.
func ReadStart(host string, exit int, stdout, id string) (Facts, []string, error) {
	switch exit {
	case 0:
	case ExitNoFolder:
		return Facts{}, nil, ErrNoFolder
	case ExitUnsafe:
		return Facts{}, nil, folderDenied(host)
	case ExitNoSpace:
		return Facts{}, nil, out.Errf(out.ExitRemote, "SESSION_SPACE_DENIED",
			"free space in the home folder, or give a smaller log cap: `komando host ssh exec TARGET --log-max 100MiB -- COMMAND`",
			"%s: the home file system has less free space than the log cap plus 5 percent of the disk; nothing ran", host)
	default:
		return Facts{}, nil, startFailed(host, "exit "+strconv.Itoa(exit))
	}
	f, err := ParseFacts(stdout, id)
	if err != nil {
		return Facts{}, nil, startFailed(host, err.Error())
	}
	var warns []string
	for _, line := range strings.Split(stdout, "\n") {
		if line == "facts-begin "+id {
			break
		}
		if w, ok := strings.CutPrefix(line, "warning "); ok {
			warns = append(warns, w)
		}
	}
	return f, warns, nil
}

func folderDenied(host string) error {
	return out.Errf(out.ExitRemote, "SESSION_FOLDER_DENIED",
		"look with `komando host ssh exec TARGET -- ls -ld ~/.komando ~/.komando/sessions`: each is to be a plain folder of the login user that only it can write (chmod 700)",
		"%s: ~/.komando or its sessions folder is a link, a file, not the login user's, or others can write it", host)
}

func startFailed(host, why string) error {
	return out.Errf(out.ExitRemote, "SESSION_START_FAILED",
		"the server needs nohup, ps and mkfifo: look with `komando host ssh exec TARGET -- command -v setsid nohup ps mkfifo`",
		"%s: the run in a session did not start (%s)", host, why)
}
