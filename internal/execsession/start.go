package execsession

import (
	"errors"
	"strconv"
	"time"

	"github.com/sgnd/komando/internal/sshx"
)

// ExitNoSpace is the start script's exit when the home file system has
// less free space than the log cap plus 5% of the disk.
const ExitNoSpace = 93

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
	return `u=$(umask); ` + space + folder + `; ` +
		`{ ` + saves + `printf '%s\n' ` + sshx.Q(s.Shown) + ` > "$d/cmd" && date -u +%s > "$d/started" && : > "$d/out.log" && mkfifo "$d/.o"; } || { rm -rf "$d"; exit ` + strconv.Itoa(ExitNoFolder) + `; }; ` +
		`export d; if command -v setsid >/dev/null 2>&1; then setsid nohup sh -c ` + w + ` sh "$u" >/dev/null 2>&1 </dev/null & g=1; ` +
		`else nohup sh -c ` + w + ` sh "$u" >/dev/null 2>&1 </dev/null & g=; fi; p=$!; echo $p > "$d/pid"; ` +
		FactsScript + `; ` +
		// setsid makes the group a moment after the start: wait for it, or a
		// stop would signal the PID alone
		`i=0; while [ -n "$g" ] && [ "$(ps -o pgid= -p $p 2>/dev/null | tr -d ' ')" != "$p" ] && [ $i -lt 20 ]; do sleep 0.1 2>/dev/null || sleep 1; i=$((i+1)); done; ` +
		`ks_facts $p`, nil
}

// wrapper is the session's root process. Its output and the run's go
// through the fifo .o into the capper, which keeps the first max bytes in
// out.log and counts the rest into truncated; the capper starts before the
// login's umask comes back, so its files stay private. exit is written
// through exit.tmp once the capper is done (or 3 s after the run, when a
// child the run left still holds the output open).
func wrapper(start string, timeout time.Duration, max int64) string {
	watch, end := watcher(timeout)
	return `{ head -c ` + strconv.FormatInt(max, 10) + ` > "$d/out.log"; n=$(wc -c | tr -d ' '); [ "$n" = 0 ] || echo "$n" > "$d/truncated"; } < "$d/.o" & k=$!; ` +
		`exec > "$d/.o" 2>&1; umask "$1"; ` + start + `; umask 077; ` + watch + end +
		`exec > /dev/null 2>&1; i=0; while kill -0 $k 2>/dev/null && [ $i -lt 3 ]; do sleep 1; i=$((i+1)); done; ` +
		`[ -f "$d/killed" ] || { echo $c > "$d/exit.tmp" && mv "$d/exit.tmp" "$d/exit"; }; rm -f "$d/env" "$d/in" "$d/pw" "$d/.o"`
}
