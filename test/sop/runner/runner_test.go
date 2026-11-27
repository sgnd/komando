package runner

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeShell runs no process: it answers each command line from a table.
type fakeShell struct {
	answers map[string]Answer
	ran     []string
}

func (f *fakeShell) Run(_ context.Context, argv []string) (Answer, error) {
	line := strings.Join(argv, " ")
	f.ran = append(f.ran, line)
	if a, ok := f.answers[line]; ok {
		return a, nil
	}
	return Answer{Exit: 0}, nil
}

func script(steps ...Step) *Scripted { return &Scripted{Steps: steps} }

func TestRunFollowsTheScript(t *testing.T) {
	sh := &fakeShell{answers: map[string]Answer{
		"komando db shell pg": {Exit: 2, ErrorCode: "USAGE", Output: "bad"},
	}}
	m := script(Run("komando db shell pg"), Run("komando db query pg x"), Say("done"))
	cap, err := Run0(context.Background(), m, sh, Limits{Steps: 10, Output: 1000, Time: time.Minute}, "read a table")
	if err != nil {
		t.Fatal(err)
	}
	if len(cap.Commands) != 2 || cap.Commands[0].ErrorCode != "USAGE" || cap.Commands[1].Exit != 0 {
		t.Errorf("commands %+v", cap.Commands)
	}
	if cap.Capped || cap.GaveUp {
		t.Errorf("capped %v gave up %v", cap.Capped, cap.GaveUp)
	}
	if got := strings.Join(sh.ran, "|"); got != "komando db shell pg|komando db query pg x" {
		t.Errorf("ran %q", got)
	}
}

func TestRunCaps(t *testing.T) {
	loop := make([]Step, 20)
	for i := range loop {
		loop[i] = Run("komando list")
	}
	t.Run("steps", func(t *testing.T) {
		cap, err := Run0(context.Background(), script(loop...), &fakeShell{}, Limits{Steps: 3, Output: 1000, Time: time.Minute}, "x")
		if err != nil || !cap.Capped || len(cap.Commands) != 3 {
			t.Errorf("capped %v commands %d err %v", cap.Capped, len(cap.Commands), err)
		}
	})
	t.Run("output tokens", func(t *testing.T) {
		m := &Scripted{Steps: loop, TokensPerStep: [2]int{10, 400}}
		cap, _ := Run0(context.Background(), m, &fakeShell{}, Limits{Steps: 50, Output: 1000, Time: time.Minute}, "x")
		if !cap.Capped || cap.TokensOut < 1000 || cap.TokensOut > 1400 {
			t.Errorf("capped %v out %d", cap.Capped, cap.TokensOut)
		}
	})
	t.Run("time", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		time.Sleep(5 * time.Millisecond)
		cap, _ := Run0(ctx, script(loop...), &fakeShell{}, Limits{Steps: 50, Output: 1000, Time: time.Minute}, "x")
		if !cap.Capped {
			t.Error("a run past its time was not capped")
		}
	})
}

func TestRunGaveUp(t *testing.T) {
	cap, _ := Run0(context.Background(), script(GiveUp("cannot")), &fakeShell{}, Limits{Steps: 5, Output: 100, Time: time.Minute}, "x")
	if !cap.GaveUp || cap.Capped {
		t.Errorf("%+v", cap)
	}
}

func TestRunAskPerson(t *testing.T) {
	asked := ""
	m := script(Run("komando cluster scale k 0"), Ask("may I scale k to 0?"), Run("komando cluster scale k 0 --allow-dangerous"), Say("done"))
	sh := &fakeShell{answers: map[string]Answer{"komando cluster scale k 0": {Exit: 6, ErrorCode: "POLICY_BLOCKED"}}}
	person := func(q string) string { asked = q; return "yes, run it with the flag you named" }
	cap, err := Run0With(context.Background(), m, sh, person, Limits{Steps: 10, Output: 1000, Time: time.Minute}, "scale")
	if err != nil {
		t.Fatal(err)
	}
	if cap.AskedPerson != 1 || asked != "may I scale k to 0?" || len(cap.Commands) != 2 {
		t.Errorf("asked %d %q commands %d", cap.AskedPerson, asked, len(cap.Commands))
	}
}

func TestRunOnlyKomando(t *testing.T) {
	sh := &fakeShell{}
	cap, err := Run0(context.Background(), script(Run("rm -rf /"), Say("done")), sh, Limits{Steps: 5, Output: 100, Time: time.Minute}, "x")
	if err != nil || len(sh.ran) != 0 || len(cap.Commands) != 1 || cap.Commands[0].Exit == 0 {
		t.Errorf("ran %v commands %+v err %v", sh.ran, cap.Commands, err)
	}
}

// The model adapter gets its key from the environment of the job and from
// nowhere else: no file is named, opened or read for it.
func TestAdapterKeyComesFromTheEnvironment(t *testing.T) {
	t.Setenv("SOP_API_KEY", "")
	if _, err := NewAPIModel("m", os.Getenv); err == nil || !errors.Is(err, ErrNoKey) {
		t.Fatalf("a missing key: %v", err)
	}
	m, err := NewAPIModel("m", func(k string) string {
		if k == "SOP_API_KEY" {
			return "k-from-env"
		}
		return ""
	})
	if err != nil || m == nil {
		t.Fatalf("key in the environment: %v", err)
	}
}

// No code path of the harness opens a key file: the packages never call a
// file-reading function with a name that has to do with a key, and the
// model adapter imports no file-reading package.
func TestNoCodePathReadsAKeyFile(t *testing.T) {
	root := filepath.Join("..")
	reading := map[string]bool{"ReadFile": true, "Open": true, "OpenFile": true, "ReadDir": true, "Getenv": false}
	checked := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		checked++
		f, perr := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if perr != nil {
			return perr
		}
		src, _ := os.ReadFile(p)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !reading[sel.Sel.Name] {
				return true
			}
			// a file-reading call: its text and its arguments must say nothing about a key
			start, end := call.Pos()-f.Pos(), call.End()-f.Pos()
			text := strings.ToLower(string(src[start:end]))
			for _, w := range []string{"key", "token", "secret", "credential", "api", ".env"} {
				if strings.Contains(text, w) {
					t.Errorf("%s reads a file with %q in the call: %s", p, w, text)
				}
			}
			return true
		})
		if strings.Contains(string(src), "godotenv") || strings.Contains(string(src), ".env") {
			t.Errorf("%s names a dotenv file", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 3 {
		t.Fatalf("only %d files checked: the test is looking in the wrong place", checked)
	}
}
