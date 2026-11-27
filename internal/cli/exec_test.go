package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/execsession"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// exec's session flags are part of exec: shown in help, taken as given.
func TestExecSessionFlagsShown(t *testing.T) {
	c, _, err := newRoot(tcl).Find([]string{"exec"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"attach", "offset", "wait", "log-max", "stop", "signal", "remove"} {
		f := c.Flags().Lookup(name)
		if f == nil || f.Hidden {
			t.Errorf("--%s: missing or hidden", name)
		}
	}
}

// A plain exec on one Unix server runs in a session, with no switch to
// turn on first.
func TestExecRunsInSessionByDefault(t *testing.T) {
	srv := startSessionServer(t, "up\n", true)
	_ = captureOutput(t, func() error { return runRoot(t, "exec", "dev", "--read-only", "--", "uptime") })
	if k := srv.kinds(); len(k) == 0 || k[0] != "start" {
		t.Fatalf("calls %v, want a session start first", k)
	}
}

// sessionServer answers exec's session scripts as a Unix server would:
// the start prints the run's facts (or exits begin), a read gives the
// status and out.log from its offset, anything else (remove, a run
// without a session) prints direct.
type sessionServer struct {
	*fakeServer
	begin int
	log   string
	ended bool
}

var (
	startID = regexp.MustCompile(`d="\$s/([a-z2-7]{52})"`)
	readID  = regexp.MustCompile(`read-begin ([a-z2-7]{52})`)
	readAt  = regexp.MustCompile(`tail -c \+([0-9]+)`)
)

func startSessionServer(t *testing.T, log string, ended bool) *sessionServer {
	t.Helper()
	s := &sessionServer{fakeServer: startFakeServer(t), log: log, ended: ended}
	s.answer = func(cmd string) (string, int) {
		if out, status, ok := sessionAnswer(cmd, s.log, s.ended, s.begin); ok {
			return out, status
		}
		return "direct\n", 0
	}
	return s
}

// sessionAnswer is a Unix server's reply to a session start (the run's
// facts, or nothing and begin as the exit) or a read (status and log from
// the offset); ok is false for any other call.
func sessionAnswer(cmd, log string, ended bool, begin int) (out string, status int, ok bool) {
	switch {
	case strings.Contains(cmd, "mkfifo"):
		if begin != 0 {
			return "", begin, true
		}
		id := startID.FindStringSubmatch(cmd)[1]
		return "facts-begin " + id + "\npid 4242\npgid 4242\nstart proc 99\nfacts-end " + id + "\n", 0, true
	case readID.MatchString(cmd):
		id := readID.FindStringSubmatch(cmd)[1]
		from, _ := strconv.Atoi(readAt.FindStringSubmatch(cmd)[1])
		head := "read-begin " + id + "\n"
		if ended {
			head += "exit 0\n"
		}
		return head + "size " + strconv.Itoa(len(log)) + "\nread-end " + id + "\n" + log[min(from-1, len(log)):], 0, true
	}
	return "", 0, false
}

// kinds sorts the server's execs: start, read, remove or other.
func (s *sessionServer) kinds() []string {
	var k []string
	for _, e := range s.take() {
		switch {
		case strings.Contains(e.cmd, "mkfifo"):
			k = append(k, "start")
		case readID.MatchString(e.cmd):
			k = append(k, "read")
		case strings.Contains(e.cmd, `rm -rf "$d"`):
			k = append(k, "remove")
		default:
			k = append(k, "other")
		}
	}
	return k
}

type sessionResult struct {
	Data struct {
		Results []struct {
			Session  *string `json:"session"`
			ExitCode int     `json:"exit_code"`
			Stdout   string  `json:"stdout"`
			Cut      bool    `json:"stdout_truncated"`
			NextFrom *int64  `json:"next_from"`
		} `json:"results"`
	} `json:"data"`
	Error struct{ Code, Hint string } `json:"error"`
	Meta  struct {
		Warnings []string `json:"warnings"`
	} `json:"meta"`
}

// runSession runs komando with stdout alone captured (warnings go to
// meta.warnings too) and splits it into the first line, when the command
// prints one, and the result.
func runSession(t *testing.T, args ...string) (first map[string]any, res sessionResult, err error) {
	t.Helper()
	var w bytes.Buffer
	savedW, savedErr := tcl.out.W, tcl.out.Err
	tcl.out.W, tcl.out.Err = &w, io.Discard
	err = runRoot(t, args...)
	tcl.out.W, tcl.out.Err = savedW, savedErr
	got := strings.TrimSpace(w.String())
	if line, rest, two := strings.Cut(got, "\n"); two {
		if e := json.Unmarshal([]byte(line), &first); e != nil {
			t.Fatalf("first line: %v\n%s", e, got)
		}
		got = rest
	}
	if e := json.Unmarshal([]byte(got), &res); e != nil {
		t.Fatalf("result: %v\n%s", e, got)
	}
	return first, res, err
}

// U2: the first JSON line names the session and the server, before any
// output; the run's log and exit code follow, and a run read to its end
// by the actor who started it is removed, record and folder.
func TestExecSessionFirstLine(t *testing.T) {
	srv := startSessionServer(t, "hello\n", true)
	first, res, err := runSession(t, "exec", "dev", "--read-only", "--", "uptime")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := first["session"].(string)
	if execsession.CheckID(id) != nil || first["host"] != "dev" || len(first) != 2 {
		t.Fatalf("first line %v", first)
	}
	r := res.Data.Results[0]
	if r.Session == nil || *r.Session != id || r.Stdout != "hello\n" || r.ExitCode != 0 {
		t.Fatalf("result %+v", r)
	}
	if k := srv.kinds(); !slices.Equal(k, []string{"start", "read", "remove"}) {
		t.Fatalf("calls %v", k)
	}
	if rt, _ := store.ReadRuntime(); rt.ExecSessions[id] != nil {
		t.Fatal("the record stayed after a full read")
	}
}

// --max-output holds when a session is read: the output stops there and
// the result says it was cut.
func TestExecSessionOutputLimit(t *testing.T) {
	startSessionServer(t, "0123456789abcdef\n", true)
	_, res, err := runSession(t, "exec", "dev", "--read-only", "--max-output", "8", "--", "uptime")
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Data.Results[0]; r.Stdout != "01234567" || !r.Cut {
		t.Fatalf("result %+v", r)
	}
}

// U3: a run still going at --wait is exit 7 with next_from and the attach
// hint; its record stays, with the facts the server gave.
func TestExecSessionWaitLimit(t *testing.T) {
	srv := startSessionServer(t, "step 1\nstep", false)
	first, res, err := runSession(t, "exec", "dev", "--read-only", "--sudo", "--wait", "1s", "--", "uptime")
	if code, ok := err.(exitCode); !ok || int(code) != 7 {
		t.Fatalf("want exit 7, got %v", err)
	}
	id := first["session"].(string)
	r := res.Data.Results[0]
	if res.Error.Code != "SESSION_WAIT_TIMEOUT" || !strings.Contains(res.Error.Hint, "--attach "+id+" --offset 7") ||
		r.NextFrom == nil || *r.NextFrom != 7 || r.Stdout != "step 1\n" {
		t.Fatalf("error %+v, result %+v", res.Error, r)
	}
	if k := srv.kinds(); slices.Contains(k, "remove") || k[0] != "start" {
		t.Fatalf("calls %v", k)
	}
	rt, _ := store.ReadRuntime()
	rec := rt.ExecSessions[id]
	if rec == nil || rec.Host != "dev" || rec.PID != 4242 || rec.PGID != 4242 || rec.ProcStart != "proc 99" ||
		!rec.Sudo || rec.Command != "uptime" || rec.Actor == "" || rec.StartedAt.IsZero() {
		t.Fatalf("record %+v", rec)
	}
}

// --wait 0 reads once and returns.
func TestExecSessionWaitZero(t *testing.T) {
	srv := startSessionServer(t, "", false)
	if _, _, err := runSession(t, "exec", "dev", "--read-only", "--wait", "0", "--", "uptime"); err == nil {
		t.Fatal("a running session ended the exec")
	}
	if k := srv.kinds(); !slices.Equal(k, []string{"start", "read"}) {
		t.Fatalf("calls %v", k)
	}
}

// U17: no folder can be made: the command runs without a session, in a
// new call that sends the input again, with session null and a warning.
func TestExecSessionNoFolderRunsDirect(t *testing.T) {
	srv := startSessionServer(t, "", false)
	srv.begin = execsession.ExitNoFolder
	first, res, err := runSession(t, "exec", "dev", "--read-only", "--", "uptime")
	if err != nil {
		t.Fatal(err)
	}
	execs := srv.take()
	if len(execs) != 2 || strings.Contains(execs[1].cmd, "mkfifo") || !strings.Contains(execs[1].cmd, "uptime") {
		t.Fatalf("execs %+v", execs)
	}
	if v, ok := first["session"]; !ok || v != nil || res.Data.Results[0].Session != nil || res.Data.Results[0].Stdout != "direct\n" {
		t.Fatalf("first %v, result %+v", first, res.Data.Results[0])
	}
	if len(res.Meta.Warnings) != 1 || !strings.Contains(res.Meta.Warnings[0], "without a session") {
		t.Fatalf("warnings %v", res.Meta.Warnings)
	}
}

// U17: too little space refuses; nothing runs after the start.
func TestExecSessionSpaceDenied(t *testing.T) {
	srv := startSessionServer(t, "", false)
	srv.begin = execsession.ExitNoSpace
	_, res, err := runSession(t, "exec", "dev", "--read-only", "--", "uptime")
	if code, ok := err.(exitCode); !ok || int(code) != 5 || res.Error.Code != "SESSION_SPACE_DENIED" {
		t.Fatalf("got %v, %+v", err, res.Error)
	}
	if k := srv.kinds(); !slices.Equal(k, []string{"start"}) {
		t.Fatalf("calls %v", k)
	}
}

// A group, --pty and the commands built on exec run without a session.
func TestExecSessionGroupStaysDirect(t *testing.T) {
	srv := startSessionServer(t, "", false)
	if err := store.Update(store.Save(), func(st *store.State) error {
		w := *st.Hosts["dev"]
		w.Name, w.OS = "win", store.OSWindows
		st.Hosts["win"] = &w
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"exec", "dev,prod", "--read-only", "--", "uptime"},
		{"exec", "dev", "--read-only", "--pty", "--", "uptime"},
		{"exec", "win", "--read-only", "--", "Get-Date"},
	} {
		_ = captureOutput(t, func() error { return runRoot(t, args...) })
		if k := srv.kinds(); slices.Contains(k, "start") || len(k) == 0 {
			t.Errorf("%v: calls %v", args, k)
		}
	}
}

// Only a plain exec on one Unix server without --pty gets a session.
func TestSessionForOneUnixServer(t *testing.T) {
	unix, win := &store.Host{Name: "a"}, &store.Host{Name: "w", OS: store.OSWindows}
	o := execOpts{session: &sessionOpts{}}
	pty := o
	pty.pty = true
	for _, tc := range []struct {
		name  string
		cmd   string
		hosts []*store.Host
		o     execOpts
		want  bool
	}{
		{"one unix server", "exec", []*store.Host{unix}, o, true},
		{"windows", "exec", []*store.Host{win}, o, false},
		{"two servers", "exec", []*store.Host{unix, unix}, o, false},
		{"pty", "exec", []*store.Host{unix}, pty, false},
		{"not exec", "logs", []*store.Host{unix}, o, false},
		{"no session flags", "exec", []*store.Host{unix}, execOpts{}, false},
	} {
		if got := sessionFor(nil, tc.cmd, tc.hosts, tc.o, "x") != nil; got != tc.want {
			t.Errorf("%s: session %v", tc.name, got)
		}
	}
}

// --log-max goes to the start as the log cap.
func TestExecLogMaxFlag(t *testing.T) {
	srv := startSessionServer(t, "", true)
	_ = captureOutput(t, func() error { return runRoot(t, "exec", "dev", "--read-only", "--log-max", "2MiB", "--", "uptime") })
	execs := srv.take()
	if len(execs) == 0 || !strings.Contains(execs[0].cmd, "head -c 2097152") {
		t.Fatalf("execs %+v", execs)
	}
}

// putRecord stores a session record as an exec on dev would.
func putRecord(t *testing.T, id, actor string, agent bool) {
	t.Helper()
	rec := &store.ExecSession{ID: id, Host: "dev", Command: "uptime", PID: 4242, PGID: 4242, ProcStart: "proc 99", Actor: actor, Agent: agent}
	if err := store.UpdateRuntime(store.Save(), func(s *store.State) error { s.ExecSessions[id] = rec; return nil }); err != nil {
		t.Fatal(err)
	}
}

const attachID = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"

// The start's sweep knows this server's records (the lost check), and
// the records of the sessions it swept are dropped: only those it names
// between the markers that carry the new session's ID, never a line a
// login banner printed before them.
func TestExecSessionSweepKnowsTheRecords(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inside  bool
		dropped bool
	}{
		{"between the markers", true, true},
		{"a banner line", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startSessionServer(t, "", true)
			putRecord(t, attachID, "alice", false)
			answer := srv.answer
			srv.answer = func(cmd string) (string, int) {
				o, code := answer(cmd)
				if m := sweepBegin.FindStringSubmatch(cmd); m != nil {
					line := "swept " + attachID + "\n"
					if tc.inside {
						o = "sweep-begin " + m[1] + "\n" + line + "sweep-end " + m[1] + "\n" + o
					} else {
						o = line + "sweep-begin " + m[1] + "\nsweep-end " + m[1] + "\n" + o
					}
				}
				return o, code
			}
			_ = captureOutput(t, func() error { return runRoot(t, "exec", "dev", "--read-only", "--", "uptime") })
			execs := srv.take()
			if len(execs) == 0 || !strings.Contains(execs[0].cmd, attachID+") [ \"$(ks_start 4242)\" != 'proc 99' ]") {
				t.Fatalf("start %+v", execs)
			}
			if rt, _ := store.ReadRuntime(); (rt.ExecSessions[attachID] == nil) != tc.dropped {
				t.Fatalf("record dropped: %v, want %v", rt.ExecSessions[attachID] == nil, tc.dropped)
			}
		})
	}
}

var sweepBegin = regexp.MustCompile(`echo "sweep-begin ([a-z2-7]{52})"`)

// U4: --attach reads from --offset on; it sweeps nothing (U12).
func TestExecAttachOffset(t *testing.T) {
	srv := startSessionServer(t, "line 1\nline 2\n", true)
	_, res, err := runSession(t, "exec", "dev", "--attach", attachID, "--offset", "7")
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Data.Results[0]; r.Stdout != "line 2\n" || r.Session == nil || *r.Session != attachID {
		t.Fatalf("result %+v", r)
	}
	for _, e := range srv.take() {
		if strings.Contains(e.cmd, "swept") || strings.Contains(e.cmd, "mkfifo") {
			t.Fatalf("attach ran %s", e.cmd)
		}
	}
}

// U19: an agent that reads a person's finished run to the end removes
// nothing; the person who started it does.
func TestExecAttachKeepsAnotherActorsSession(t *testing.T) {
	srv := startSessionServer(t, "done\n", true)
	t.Setenv("KOMANDO_ACTOR", "alice")
	t.Setenv("KOMANDO_AGENT", "1")
	putRecord(t, attachID, "alice", false)
	if _, _, err := runSession(t, "exec", "dev", "--attach", attachID); err != nil {
		t.Fatal(err)
	}
	if k := srv.kinds(); !slices.Equal(k, []string{"read"}) {
		t.Fatalf("calls %v", k)
	}
	for _, rec := range []*store.ExecSession{
		{ID: attachID, Host: "dev", Actor: "bob", Agent: true, PID: 4242, PGID: 4242, ProcStart: "proc 99"},
		{ID: attachID, Host: "prod", Actor: "alice", Agent: true, PID: 4242, PGID: 4242, ProcStart: "proc 99"},
	} {
		if err := store.UpdateRuntime(store.Save(), func(s *store.State) error { s.ExecSessions[attachID] = rec; return nil }); err != nil {
			t.Fatal(err)
		}
		if _, _, err := runSession(t, "exec", "dev", "--attach", attachID); err != nil {
			t.Fatal(err)
		}
		if k := srv.kinds(); !slices.Equal(k, []string{"read"}) {
			t.Fatalf("record %+v: calls %v", rec, k)
		}
	}
	putRecord(t, attachID, "alice", true)
	if _, _, err := runSession(t, "exec", "dev", "--attach", attachID); err != nil {
		t.Fatal(err)
	}
	if k := srv.kinds(); !slices.Equal(k, []string{"read", "remove"}) {
		t.Fatalf("calls %v", k)
	}
	if rt, _ := store.ReadRuntime(); rt.ExecSessions[attachID] != nil {
		t.Fatal("the record stayed")
	}
}

// U6: a bad ID, a command with --attach, a group, or --offset with
// several IDs is refused before any connection.
func TestExecAttachRefusals(t *testing.T) {
	srv := startSessionServer(t, "", true)
	for _, args := range [][]string{
		{"exec", "dev", "--attach", "../x"},
		{"exec", "dev", "--attach", attachID[1:]},
		{"exec", "dev", "--attach", attachID, "--", "uptime"},
		{"exec", "dev,prod", "--attach", attachID},
		{"exec", "dev", "--attach", attachID + "," + "b" + attachID[1:], "--offset", "3"},
		{"exec", "dev", "--offset", "3", "--", "uptime"},
		{"exec", "dev", "--offset", "3"},
	} {
		var oe *out.Error
		if err := runRoot(t, args...); !errors.As(err, &oe) || oe.Code != "USAGE" {
			t.Errorf("%v: got %v", args, err)
		}
	}
	if e := srv.take(); len(e) != 0 {
		t.Fatalf("connected: %+v", e)
	}
}

// exec holds the whole job: no job group is left. A long run is `exec`, its
// way back `exec --attach ID`, its stop `--stop`, its removal `--remove`.
func TestNoJobGroup(t *testing.T) {
	root := newRoot(tcl)
	for _, path := range [][]string{{"job"}, {"jobs"}, {"job", "kill"}, {"job", "rm"}, {"job", "start"}} {
		if c, _, _ := root.Find(path); c != nil && c != root {
			t.Errorf("%v: found %q, the job group is gone", path, c.CommandPath())
		}
	}
}
