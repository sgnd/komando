package cli

import (
	"errors"
	"strings"
	"testing"
)

// promptFake answers questions from a script and keeps what was drawn.
func promptFake(t *testing.T, answers ...string) *strings.Builder {
	t.Helper()
	var drawn strings.Builder
	savedW, savedRead, savedOn := promptW, promptRead, promptOn
	promptW, promptOn = &drawn, true
	promptRead = func(label string) (string, error) {
		drawn.WriteString(label)
		if len(answers) == 0 {
			return "", errPromptCancel // as Ctrl-C
		}
		a := answers[0]
		answers = answers[1:]
		drawn.WriteString(a + "\n")
		return a, nil
	}
	t.Cleanup(func() { promptW, promptRead, promptOn = savedW, savedRead, savedOn })
	return &drawn
}

// Each condition alone stops every question.
func TestAskGate(t *testing.T) {
	if !promptGate("", false, "", "xterm-256color") || !promptGate("text", false, "false", "xterm") || !promptGate("auto", false, "0", "screen") {
		t.Error("a person at a terminal is not asked")
	}
	for name, ok := range map[string]bool{
		"agent":     promptGate("", true, "", "xterm"),
		"CI":        promptGate("", false, "true", "xterm"),
		"CI=1":      promptGate("", false, "1", "xterm"),
		"TERM=dumb": promptGate("", false, "", "dumb"),
		"-o json":   promptGate("json", false, "", "xterm"),
		"-o csv":    promptGate("csv", false, "", "xterm"),
	} {
		if ok {
			t.Errorf("%s: komando would ask", name)
		}
	}
}

// A question asked where nobody may be asked is a bug, never a hang.
func TestAskNeverWithoutAPerson(t *testing.T) {
	promptOn = false
	defer func() {
		if recover() == nil {
			t.Error("a question was asked without a person")
		}
	}()
	_, _ = askText(promptQ{label: "CONN"})
}

func TestAskText(t *testing.T) {
	drawn := promptFake(t, "?", "", "abc", "42")
	v, err := askText(promptQ{label: "--limit", help: "How many rows.", check: func(v string) string { return formValueProblem("int", v) }})
	if err != nil || v != "42" {
		t.Fatalf("%q %v", v, err)
	}
	for _, want := range []string{"--limit: ", "How many rows.", "this one is needed", "type a whole number"} {
		if !strings.Contains(drawn.String(), want) {
			t.Errorf("%q not shown:\n%s", want, drawn)
		}
	}
	promptFake(t, "")
	if v, _ := askText(promptQ{label: "--since", def: "1h"}); v != "1h" {
		t.Errorf("Enter on a default: %q", v)
	}
	promptFake(t, "", "", "")
	if _, err := askText(promptQ{label: "SQL"}); !errors.Is(err, errPromptCancel) {
		t.Errorf("three empty answers: %v", err)
	}
	promptFake(t) // Ctrl-C
	if _, err := askText(promptQ{label: "SQL"}); !errors.Is(err, errPromptCancel) {
		t.Errorf("Ctrl-C: %v", err)
	}
}

func TestAskPick(t *testing.T) {
	rows := []menuRow{{label: "db-pass", value: "db-pass"}, {label: "web-1", detail: "10.0.0.5", value: "web-1"}, {label: "web-2", detail: "10.0.0.6", value: "web-2"}}
	for _, c := range []struct {
		answers []string
		free    bool
		want    string
	}{
		{[]string{"2"}, false, "web-1"},
		{[]string{"web-2"}, false, "web-2"},
		{[]string{"10.0.0.6"}, false, "web-2"}, // narrows to one row
		{[]string{"web", "2"}, false, "web-2"}, // narrows to two, then the second of those
		{[]string{"db"}, true, "db"},           // a new name is taken as typed
		{[]string{"@web"}, true, "@web"},       // so is a selector
		{[]string{"9", "nothing", "1"}, false, "db-pass"},
	} {
		drawn := promptFake(t, c.answers...)
		got, err := askPick(promptQ{label: "TARGET"}, rows, c.free)
		if err != nil || got != c.want {
			t.Errorf("%v: %q %v\n%s", c.answers, got, err, drawn)
		}
	}
	drawn := promptFake(t, "")
	if got, _ := askPick(promptQ{label: "--via", optional: true}, rows, true); got != "" {
		t.Errorf("Enter on an optional pick: %q", got)
	}
	if !strings.Contains(drawn.String(), " 1  db-pass") || !strings.Contains(drawn.String(), " 2  web-1    10.0.0.5") {
		t.Errorf("the list:\n%s", drawn)
	}
}

func TestAskRunAndTypeName(t *testing.T) {
	for answer, want := range map[string]string{"y": "y", "YES": "y", "d": "d", "": "n", "x": "n"} {
		promptFake(t, answer)
		if got, _ := askRun(); got != want {
			t.Errorf("Run it? %q: %q, want %q", answer, got, want)
		}
	}
	promptFake(t, "old-box")
	if ok, _ := askTypeName("old-box", "the name old-box"); !ok {
		t.Error("the right name is a no")
	}
	promptFake(t, "old")
	if ok, _ := askTypeName("old-box", "the name old-box"); ok {
		t.Error("a wrong name is a yes")
	}
}

// A CI job is never a person, even on a terminal.
func TestCIRunIsNoPerson(t *testing.T) {
	for v, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true} {
		t.Setenv("CI", v)
		if ciRun() != want {
			t.Errorf("CI=%q: %v", v, !want)
		}
	}
}

// On a console without escape sequences (an old Windows console) a masked
// line is redrawn with spaces and backspaces over what is left.
func TestMaskedRedraw(t *testing.T) {
	for _, c := range []struct {
		shown string
		drawn int
		want  string
	}{
		{"URL: post", 0, "URL: post"},
		{"URL: pos", 9, "URL: pos \b"},
		{"URL: ", 9, "URL:     \b\b\b\b"},
		{"URL: é", 6, "URL: é"},
	} {
		if got := maskedRedraw(c.shown, c.drawn); got != c.want {
			t.Errorf("maskedRedraw(%q, %d) = %q, want %q", c.shown, c.drawn, got, c.want)
		}
	}
}

// No colour where escape sequences would show as text.
func TestColorNeedsVT(t *testing.T) {
	saved := vtOK
	t.Cleanup(func() { vtOK = saved })
	vtOK = false
	if colorOK() {
		t.Error("colour on a console that shows escape sequences as text")
	}
}
