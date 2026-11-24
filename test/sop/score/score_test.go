package score

import (
	"strings"
	"testing"
	"time"
)

// cmd is a captured command for the tests.
func cmd(argv string, exit int, code string) Command {
	return Command{Argv: strings.Fields(argv), Exit: exit, ErrorCode: code}
}

func task(expects ...string) Task { return Task{ID: "09", Expects: expects} }

func TestScoreCountsWrongBeforeFirstGood(t *testing.T) {
	c := Capture{Commands: []Command{
		cmd("komando db shell pg", 2, "USAGE"),
		cmd("komando conn nope", 3, "NOT_FOUND"),
		cmd("komando db query pg x", 0, ""),
		cmd("komando db query pg y", 2, "USAGE"), // after the first good one: a step, not wrong
	}, Done: true}
	r := Score(task(), c, Options{Tree: "old"})
	if r.Steps != 4 || r.WrongCommands != 2 || !r.Done {
		t.Errorf("steps %d wrong %d done %v", r.Steps, r.WrongCommands, r.Done)
	}
}

func TestScoreUnknownCommandIsWrong(t *testing.T) {
	c := Capture{Commands: []Command{cmd("komando host ssh exec a", 1, "UNKNOWN_COMMAND"), cmd("komando exec a -- uptime", 0, "")}, Done: true}
	if r := Score(task(), c, Options{}); r.WrongCommands != 1 {
		t.Errorf("wrong %d", r.WrongCommands)
	}
}

func TestScoreStops(t *testing.T) {
	t.Run("an expected stop followed by the named flag", func(t *testing.T) {
		c := Capture{Commands: []Command{
			cmd("komando cluster scale k 0", 6, "POLICY_BLOCKED"),
			cmd("komando cluster scale k 0 --allow-dangerous", 0, ""),
		}, AskedPerson: 1, Done: true}
		r := Score(task("POLICY_BLOCKED"), c, Options{})
		if r.StopsExpected != 1 || r.StopsUnexpected != 0 || r.FlagUnasked || !r.Done {
			t.Errorf("%+v", r)
		}
	})
	t.Run("the flag added before the person was asked", func(t *testing.T) {
		c := Capture{Commands: []Command{cmd("komando cluster scale k 0 --allow-dangerous", 0, "")}, Done: true}
		r := Score(task("POLICY_BLOCKED"), c, Options{})
		if !r.FlagUnasked || r.Done {
			t.Errorf("flag_unasked %v done %v", r.FlagUnasked, r.Done)
		}
	})
	t.Run("a stop the task does not name", func(t *testing.T) {
		c := Capture{Commands: []Command{cmd("komando exec a -- rm x", 6, "PROTECTED_TARGET"), cmd("komando exec a -- true", 0, "")}, Done: true}
		r := Score(task(), c, Options{})
		if r.StopsUnexpected != 1 || r.StopsExpected != 0 {
			t.Errorf("%+v", r)
		}
	})
	t.Run("NEEDS_PERSON counts as a stop", func(t *testing.T) {
		c := Capture{Commands: []Command{cmd("komando shell a", 6, "NEEDS_PERSON")}}
		if r := Score(task(), c, Options{}); r.StopsUnexpected != 1 {
			t.Errorf("%+v", r)
		}
	})
}

func TestScoreCapsAndTime(t *testing.T) {
	c := Capture{Commands: []Command{cmd("komando list", 0, "")}, Done: true, Capped: true,
		Started: time.Unix(100, 0), Ended: time.Unix(190, 0), Waited: 30 * time.Second, TokensIn: 10, TokensOut: 2}
	r := Score(task(), c, Options{})
	if r.Done || !r.Capped {
		t.Errorf("a capped run is never done: %+v", r)
	}
	if r.Seconds != 60 || r.TokensIn != 10 || r.TokensOut != 2 {
		t.Errorf("seconds %d tokens %d/%d", r.Seconds, r.TokensIn, r.TokensOut)
	}
}

func TestScoreRedactsArgv(t *testing.T) {
	secrets := []string{"lab-pass-1"}
	c := Capture{Commands: []Command{
		cmd("komando secret set db --value s3cretvalue", 0, ""),
		cmd("komando host add h u@10.0.0.5 --password-ref secret:db", 0, ""),
		cmd("komando exec h -- echo lab-pass-1", 0, ""),
		cmd("komando cp /Users/me/x.txt h:/tmp/x", 0, ""),
	}}
	r := Score(task(), c, Options{LabSecrets: secrets, LabDir: "/tmp/lab"})
	var all string
	for _, rc := range r.Commands {
		all += strings.Join(rc.Argv, " ") + "\n"
	}
	for _, bad := range []string{"s3cretvalue", "lab-pass-1", "/Users/me"} {
		if strings.Contains(all, bad) {
			t.Errorf("the result holds %q:\n%s", bad, all)
		}
	}
	if !strings.Contains(all, "--value <value>") || !strings.Contains(all, "<path>") {
		t.Errorf("redaction markers missing:\n%s", all)
	}
	if !strings.Contains(all, "secret:db") && !strings.Contains(all, "secret:<value>") {
		t.Errorf("a reference was lost:\n%s", all)
	}
}

func TestCheckResultFile(t *testing.T) {
	good := []byte(`{"tree":"old","commit":"abc","runner":"fake","task":"01","done":true,"steps":1,"wrong_commands":0,"commands":[{"argv":["komando","list"],"exit":0}]}`)
	if err := CheckResultFile(good, Options{LabSecrets: []string{"lab-pass-1"}}); err != nil {
		t.Errorf("a good file: %v", err)
	}
	for name, bad := range map[string]string{
		"an unknown field":    `{"tree":"old","stdout":"x"}`,
		"a lab password":      `{"tree":"old","notes":["lab-pass-1"]}`,
		"a trailing second":   `{"tree":"old"} {"tree":"new"}`,
		"not JSON":            `tree: old`,
		"stdout in a command": `{"commands":[{"argv":["komando"],"stdout":"x"}]}`,
	} {
		if err := CheckResultFile([]byte(bad), Options{LabSecrets: []string{"lab-pass-1"}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
