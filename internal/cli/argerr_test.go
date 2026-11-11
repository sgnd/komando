package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// envErr runs komando through Execute and returns the exit code and the
// error of its JSON envelope.
func envErr(t *testing.T, args ...string) (int, string, string, string) {
	t.Helper()
	code, s := runMain(t, args...)
	var env struct {
		Error struct{ Code, Message, Hint string }
	}
	if err := json.Unmarshal([]byte(s), &env); err != nil {
		t.Fatalf("%v: not one JSON envelope: %q", args, s)
	}
	return code, env.Error.Code, env.Error.Message, env.Error.Hint
}

// A command without sub-commands says it takes no arguments, not "unknown
// command" with a list of commands it does not have.
func TestStrayArgument(t *testing.T) {
	invHome(t)
	code, c, msg, hint := envErr(t, "version", "foo")
	if code != 2 || c != "USAGE" || msg != `komando version takes no arguments (got "foo")` || strings.Contains(hint, "list of commands") {
		t.Errorf("version foo: %d %s %q %q", code, c, msg, hint)
	}
	if _, _, msg, hint := envErr(t, "job", "list", "web1"); !strings.Contains(msg, "takes no arguments") || !strings.Contains(hint, "--target web1") {
		t.Errorf("job list web1: %q %q", msg, hint)
	}
	if _, _, msg, _ := envErr(t, "host", "lst"); !strings.HasPrefix(msg, `unknown command "lst"`) {
		t.Errorf("a group keeps its unknown command: %q", msg)
	}
}

// Piped, a command that needs a sub-command or an argument prints one
// USAGE envelope, never its help text.
func TestBareGroupsPiped(t *testing.T) {
	invHome(t)
	for _, args := range [][]string{{"login"}, {"completion"}, {"completion", "tcsh"}} {
		if code, c, _, _ := envErr(t, args...); code != 2 || c != "USAGE" {
			t.Errorf("%v: exit %d, %s", args, code, c)
		}
	}
}

func TestSchemaLookups(t *testing.T) {
	invHome(t)
	if d := mustRun(t, "schema", "db query"); len(d["commands"].([]any)) != 1 {
		t.Errorf("schema 'db query': %v", d["commands"])
	}
	wantCode(t, "COMMAND_NOT_FOUND", "schema", "completion")
	wantCode(t, "COMMAND_NOT_FOUND", "schema", "help")
}
