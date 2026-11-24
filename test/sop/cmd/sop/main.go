// Command sop runs and scores one task of the komando test SOP (vault note
// 2026-11-24-komando-v2-7-test-sop-design). It is a test tool, not part of
// komando: it lives under test/sop and nothing in the product imports it.
//
//	sop run scripted --task T --script S --answers A --tree old --out R
//	sop run agent --yes-cost --task T --model M --tree old --out R
//
// "run scripted" follows a list of steps against canned answers: no model,
// no lab, no key, no cost. "run agent" asks a model, and refuses to start
// without --yes-cost (the owner's yes to the cost) and a key in the
// environment (SOP_API_KEY; the harness opens no file for it).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/test/sop/runner"
	"github.com/sgnd/komando/test/sop/score"
)

func main() { os.Exit(mainRun(os.Args[1:], os.Getenv, os.Stderr)) }

// taskFile is a task as its file holds it.
type taskFile struct {
	ID         string
	Area       string
	Expects    []string
	CapSteps   int
	CapMinutes int
	Check      string
	Text       string
}

// parseTask reads a task file: a front matter of key: value lines, then
// the task text.
func parseTask(b []byte) (taskFile, error) {
	var t taskFile
	s := string(b)
	rest, ok := strings.CutPrefix(s, "---\n")
	if !ok {
		return t, errors.New("a task file starts with a --- front matter")
	}
	head, text, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		return t, errors.New("the front matter has no closing ---")
	}
	for _, line := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "id":
			t.ID = v
		case "area":
			t.Area = v
		case "check":
			t.Check = v
		case "cap_steps":
			t.CapSteps, _ = strconv.Atoi(v)
		case "cap_minutes":
			t.CapMinutes, _ = strconv.Atoi(v)
		case "expects":
			for _, e := range strings.Split(strings.Trim(v, "[]"), ",") {
				if e = strings.TrimSpace(e); e != "" {
					t.Expects = append(t.Expects, e)
				}
			}
		}
	}
	t.Text = strings.TrimSpace(text)
	return t, nil
}

func mainRun(args []string, getenv func(string) string, stderr io.Writer) int {
	if len(args) == 2 && args[0] == "check" {
		return checkFile(args[1], stderr)
	}
	if len(args) < 2 || args[0] != "run" || (args[1] != "scripted" && args[1] != "agent") {
		fmt.Fprintln(stderr, "usage: sop run scripted|agent --task FILE --tree old|new --out FILE [...]")
		return 2
	}
	fs := flag.NewFlagSet("sop run "+args[1], flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		taskPath    = fs.String("task", "", "the task file")
		tree        = fs.String("tree", "", "old or new")
		commit      = fs.String("commit", "", "the tree's commit")
		out         = fs.String("out", "", "the result file to write")
		script      = fs.String("script", "", "scripted: the steps")
		answers     = fs.String("answers", "", "scripted: canned answers, 'line => exit CODE'")
		model       = fs.String("model", "", "agent: the model")
		yesCost     = fs.Bool("yes-cost", false, "agent: the owner said yes to the cost")
		labDir      = fs.String("lab-dir", "", "paths under this folder stay in the result")
		checkPassed = fs.Bool("check-passed", false, "the task's lab check passed (set by run.sh after it ran the check)")
		secrets     multi
	)
	fs.Var(&secrets, "lab-secret", "a lab password that must never appear in a result (repeatable)")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	if *taskPath == "" || *out == "" || (*tree != "old" && *tree != "new") {
		fmt.Fprintln(stderr, "sop: --task, --out and --tree old|new are needed")
		return 2
	}
	b, err := os.ReadFile(*taskPath)
	if err != nil {
		fmt.Fprintln(stderr, "sop:", err)
		return 1
	}
	tk, err := parseTask(b)
	if err != nil {
		fmt.Fprintf(stderr, "sop: %s: %v\n", *taskPath, err)
		return 1
	}
	var (
		m      runner.Model
		sh     runner.Shell
		person runner.Person
		who    string
	)
	switch args[1] {
	case "scripted":
		m, sh, err = scriptedSetup(*script, *answers)
		person, who = func(string) string { return "yes, run it with the flag you named" }, "scripted"
	case "agent":
		m, sh, err = agentSetup(*model, *yesCost, getenv)
		person, who = func(string) string { return "yes, run it with the flag you named" }, *model
	}
	if err != nil {
		fmt.Fprintln(stderr, "sop:", err)
		return 1
	}
	lim := runner.Limits{Steps: tk.CapSteps, Output: 150000, Time: time.Duration(tk.CapMinutes) * time.Minute}
	c, err := runner.Run0With(context.Background(), m, sh, person, lim, tk.Text)
	if err != nil {
		fmt.Fprintln(stderr, "sop:", err)
		return 1
	}
	// done comes from the task's lab check (run.sh sets --check-passed). A
	// scripted run has no lab, so it takes a run that finished as done.
	c.Done = *checkPassed || (args[1] == "scripted" && !c.Capped && !c.GaveUp)
	r := score.Score(score.Task{ID: tk.ID, Expects: tk.Expects}, c, score.Options{Tree: *tree, Commit: *commit, Runner: who, LabSecrets: secrets, LabDir: *labDir})
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "sop:", err)
		return 1
	}
	if err := score.CheckResultFile(data, score.Options{LabSecrets: secrets}); err != nil {
		fmt.Fprintln(stderr, "sop:", err)
		return 1
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o600); err != nil {
		fmt.Fprintln(stderr, "sop:", err)
		return 1
	}
	return 0
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// scriptedSetup reads the steps and the canned answers.
func scriptedSetup(script, answers string) (runner.Model, runner.Shell, error) {
	if script == "" {
		return nil, nil, errors.New("run scripted needs --script")
	}
	f, err := os.Open(script)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var steps []runner.Step
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		verb, rest, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		switch verb {
		case "run":
			steps = append(steps, runner.Run(rest))
		case "ask":
			steps = append(steps, runner.Ask(rest))
		case "say":
			steps = append(steps, runner.Say(rest))
		case "giveup":
			steps = append(steps, runner.GiveUp(rest))
		case "":
		default:
			return nil, nil, fmt.Errorf("script: unknown step %q", verb)
		}
	}
	canned := cannedShell{}
	if answers != "" {
		af, err := os.Open(answers)
		if err != nil {
			return nil, nil, err
		}
		defer af.Close()
		as := bufio.NewScanner(af)
		for as.Scan() {
			line, ans, ok := strings.Cut(as.Text(), " => ")
			if !ok {
				continue
			}
			code, name, _ := strings.Cut(strings.TrimSpace(ans), " ")
			n, _ := strconv.Atoi(code)
			canned[line] = runner.Answer{Exit: n, ErrorCode: name}
		}
	}
	return &runner.Scripted{Steps: steps}, canned, nil
}

// cannedShell answers a command line from a table; any other line is ok.
type cannedShell map[string]runner.Answer

func (c cannedShell) Run(_ context.Context, argv []string) (runner.Answer, error) {
	if a, ok := c[strings.Join(argv, " ")]; ok {
		return a, nil
	}
	return runner.Answer{}, nil
}

// agentSetup makes the API model and the lab shell. It sends nothing until
// the owner's yes (--yes-cost) and a key in the environment are both there.
func agentSetup(model string, yes bool, getenv func(string) string) (runner.Model, runner.Shell, error) {
	if !yes {
		return nil, nil, errors.New("a model run costs money: pass --yes-cost only after the owner said yes to the cost")
	}
	if model == "" {
		return nil, nil, errors.New("run agent needs --model")
	}
	m, err := runner.NewAPIModel(model, getenv)
	if err != nil {
		return nil, nil, err
	}
	return m, labShell{}, nil
}

// labShell runs the komando on PATH. In the lab that is the tree's binary
// with the lab's home (test/sop/run.sh sets it); the harness itself names
// no home folder.
type labShell struct{}

func (labShell) Run(ctx context.Context, argv []string) (runner.Answer, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var buf strings.Builder
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	ans := runner.Answer{Output: buf.String()}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		ans.Exit = ee.ExitCode()
	case err != nil:
		return ans, err
	}
	ans.ErrorCode = errorCodeOf(ans.Output)
	return ans, nil
}

// errorCodeOf reads "code" from the error envelope komando prints.
func errorCodeOf(out string) string {
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &env) == nil {
		return env.Error.Code
	}
	return ""
}

// checkFile refuses a result file with a field of output or trailing data.
func checkFile(path string, stderr io.Writer) int {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(stderr, "sop:", err)
		return 1
	}
	if err := score.CheckResultFile(b, score.Options{}); err != nil {
		fmt.Fprintf(stderr, "sop: %s: %v\n", path, err)
		return 1
	}
	return 0
}
