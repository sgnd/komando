package term

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// Interrupted is the CANCELLED stop of a command or a question that Ctrl-C
// or a signal ended. Agents branch on the code and the exit; a person reads
// the text. None of them may change.
func TestInterrupted(t *testing.T) {
	e := Interrupted()
	if e.Code != "CANCELLED" || e.Message != "interrupted" || e.Exit != out.ExitError {
		t.Errorf("code %q, message %q, exit %d", e.Code, e.Message, e.Exit)
	}
	if want := "it stopped before the end (Ctrl-C or a signal); check what it left, then run it again"; e.Hint != want {
		t.Errorf("hint %q, want %q", e.Hint, want)
	}
	if want := "Stopped (Ctrl-C) before the end; what already ran stays as it is"; e.TextMessage() != want {
		t.Errorf("text message %q, want %q", e.TextMessage(), want)
	}
	if want := "check what it left, then run it again"; e.TextHint() != want {
		t.Errorf("text hint %q, want %q", e.TextHint(), want)
	}
}

// Each call gives its own error: a caller that changes the one it got
// (PlainHint, Details) does not change the next one.
func TestInterruptedFresh(t *testing.T) {
	a, b := Interrupted(), Interrupted()
	if a == b {
		t.Fatal("Interrupted returned the same *out.Error twice")
	}
	a.PlainHint()
	if b.TextHint() != "check what it left, then run it again" {
		t.Errorf("changing one error changed the other: %q", b.TextHint())
	}
}
