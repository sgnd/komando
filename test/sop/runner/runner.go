// Package runner runs one task of the test SOP for one agent model: it
// gives the model the task, runs the komando commands the model asks for
// through a Shell, and records every one. It holds the caps (steps, output
// tokens, time) and the scripted person that answers an approval question
// (vault note 2026-11-24-komando-v2-7-test-sop-design, sections 5 and 10).
//
// The Model is an interface. Scripted is a fake that follows a list, so the
// harness and its tests need no key and no network; APIModel (api.go) is
// the adapter for a provider and takes its key from the environment only.
package runner

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/sgnd/komando/test/sop/score"
)

// Kind is what a model step asks for.
type Kind int

const (
	KindRun    Kind = iota // run a komando command
	KindAsk                // ask the person
	KindSay                // the model says it is done
	KindGiveUp             // the model says it cannot do the task
)

// Step is one thing a model does.
type Step struct {
	Kind Kind
	Argv []string // KindRun: the command, split into words
	Text string   // KindAsk, KindSay, KindGiveUp
}

// Turn is one entry of the conversation a model sees.
type Turn struct {
	Role string // user, assistant, tool
	Text string
}

// Usage is the tokens one model call used.
type Usage struct{ In, Out int }

// Model decides the next step from the conversation so far.
type Model interface {
	Next(ctx context.Context, turns []Turn) (Step, Usage, error)
}

// Answer is what a command gave back. Output is shown to the model and
// never kept in a result.
type Answer struct {
	Exit      int
	ErrorCode string
	Output    string
}

// Shell runs one komando command in the lab.
type Shell interface {
	Run(ctx context.Context, argv []string) (Answer, error)
}

// Limits are the caps of one run: a cap is a recorded outcome.
type Limits struct {
	Steps  int
	Output int // output tokens
	Time   time.Duration
}

// Person answers a question the model asks. For the SOP it is scripted.
type Person func(question string) string

// Run0 runs a task with no person to ask (a question gets "no").
func Run0(ctx context.Context, m Model, sh Shell, lim Limits, task string) (score.Capture, error) {
	return Run0With(ctx, m, sh, func(string) string { return "no" }, lim, task)
}

// Run0With runs a task: the model sees the task, then each step it takes
// is carried out until it says it is done, gives up, or reaches a cap.
func Run0With(ctx context.Context, m Model, sh Shell, person Person, lim Limits, task string) (score.Capture, error) {
	c := score.Capture{Started: time.Now()}
	defer func() { c.Ended = time.Now() }()
	ctx, cancel := context.WithTimeout(ctx, lim.Time)
	defer cancel()
	turns := []Turn{{Role: "user", Text: task}}
	for {
		if err := ctx.Err(); err != nil {
			c.Capped = true
			return c, nil
		}
		if len(c.Commands) >= lim.Steps || c.TokensOut >= lim.Output {
			c.Capped = true
			return c, nil
		}
		step, use, err := m.Next(ctx, turns)
		c.TokensIn += use.In
		c.TokensOut += use.Out
		if err != nil {
			if ctx.Err() != nil {
				c.Capped = true
				return c, nil
			}
			return c, err
		}
		switch step.Kind {
		case KindSay:
			return c, nil
		case KindGiveUp:
			c.GaveUp = true
			return c, nil
		case KindAsk:
			c.AskedPerson++
			turns = append(turns, Turn{Role: "assistant", Text: "ask: " + step.Text}, Turn{Role: "tool", Text: person(step.Text)})
		case KindRun:
			cmd, ans := carryOut(ctx, sh, step.Argv)
			c.Commands = append(c.Commands, cmd)
			turns = append(turns, Turn{Role: "assistant", Text: strings.Join(step.Argv, " ")}, Turn{Role: "tool", Text: ans.Output})
		}
	}
}

// carryOut runs a command the model chose. Only komando runs: anything
// else is refused (exit 127) and counted as a step the model got wrong.
func carryOut(ctx context.Context, sh Shell, argv []string) (score.Command, Answer) {
	if len(argv) == 0 || argv[0] != "komando" {
		return score.Command{Argv: argv, Exit: 127, ErrorCode: "NOT_KOMANDO"}, Answer{Exit: 127, Output: "only komando commands run here"}
	}
	ans, err := sh.Run(ctx, argv)
	if err != nil {
		ans = Answer{Exit: 1, ErrorCode: "SHELL_FAILED", Output: err.Error()}
	}
	return score.Command{Argv: argv, Exit: ans.Exit, ErrorCode: ans.ErrorCode}, ans
}

// Scripted is a Model that follows a list of steps, for the harness's tests
// and its smoke run: no key, no network, no cost.
type Scripted struct {
	Steps         []Step
	TokensPerStep [2]int // in, out, added to each call's usage
	next          int
}

// Next gives the next scripted step; past the end the model says it is done.
func (s *Scripted) Next(context.Context, []Turn) (Step, Usage, error) {
	if s.next >= len(s.Steps) {
		return Step{Kind: KindSay, Text: "done"}, Usage{}, nil
	}
	st := s.Steps[s.next]
	s.next++
	return st, Usage{In: s.TokensPerStep[0], Out: s.TokensPerStep[1]}, nil
}

// Run is a scripted step that runs the command line (split at spaces: a
// scripted line holds no quoted argument).
func Run(line string) Step { return Step{Kind: KindRun, Argv: strings.Fields(line)} }

// Ask is a scripted question to the person.
func Ask(q string) Step { return Step{Kind: KindAsk, Text: q} }

// Say is a scripted "done".
func Say(s string) Step { return Step{Kind: KindSay, Text: s} }

// GiveUp is a scripted "I cannot".
func GiveUp(s string) Step { return Step{Kind: KindGiveUp, Text: s} }

// ErrNoKey: the adapter was given no key by the environment.
var ErrNoKey = errors.New("runner: no API key in the environment (SOP_API_KEY)")
