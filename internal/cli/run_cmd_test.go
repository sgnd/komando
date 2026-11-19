package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// TestRunChild is the program `komando run` starts in these tests: it
// prints its environment and arguments and exits with RUN_CHILD_EXIT.
func TestRunChild(t *testing.T) {
	if os.Getenv("RUN_CHILD") != "1" {
		t.Skip("helper for the run tests")
	}
	fmt.Printf("TOKEN=%s\nPLAIN=%s\n", os.Getenv("TOKEN"), os.Getenv("PLAIN"))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KOMANDO_") {
			fmt.Println("leaked " + kv)
		}
	}
	fmt.Println("args " + strings.Join(os.Args[1:], " "))
	code, _ := strconv.Atoi(os.Getenv("RUN_CHILD_EXIT"))
	os.Exit(code)
}

// runOut runs komando with args and returns what it printed, its exit
// code and its error code.
func runOut(t *testing.T, args ...string) (string, int, string) {
	t.Helper()
	closeStoreAtEnd(t)
	t.Cleanup(endCommand)
	var buf bytes.Buffer
	root := newRoot(tcl)
	root.SetArgs(append([]string{"-o", "json"}, args...))
	savedW, savedErr := tcl.out.W, tcl.out.Err
	tcl.out.W, tcl.out.Err = &buf, &buf
	defer func() { tcl.out.W, tcl.out.Err = savedW, savedErr }()
	_, err := root.ExecuteC()
	var ec exitCode
	if errors.As(err, &ec) {
		return buf.String(), int(ec), ""
	}
	if err != nil {
		e := toErr(err)
		return buf.String(), e.Exit, e.Code
	}
	return buf.String(), 0, ""
}

func runHome(t *testing.T) {
	t.Helper()
	invHome(t)
	t.Setenv("RUN_CHILD", "1")
	t.Setenv("KOMANDO_RUN_TEST", "x")
	if err := vault.Set(store.Save(), "tok", "s3cr3t-value-123"); err != nil {
		t.Fatal(err)
	}
}

func childArgs(extra ...string) []string {
	return append([]string{"--", os.Args[0], "-test.run=^TestRunChild$"}, extra...)
}

func TestRunInjectsAndMasks(t *testing.T) {
	runHome(t)
	text, exit, code := runOut(t, append([]string{"run", "--env", "TOKEN=secret:tok", "--env", "PLAIN=hello"}, childArgs()...)...)
	if exit != 0 {
		t.Fatalf("exit %d %s: %q", exit, code, text)
	}
	if strings.Contains(text, "s3cr3t-value-123") || !strings.Contains(text, "TOKEN=[secret:tok]") || !strings.Contains(text, "PLAIN=hello") {
		t.Errorf("output: %q", text)
	}
	if strings.Contains(text, "leaked KOMANDO_RUN_TEST") {
		t.Errorf("KOMANDO_* reached the program: %q", text)
	}
	rec := auditText(t)
	if strings.Contains(rec, "s3cr3t-value-123") || !strings.Contains(rec, `"command":"run"`) || !strings.Contains(rec, "secret:tok") {
		t.Errorf("audit: %s", rec)
	}
}

func TestRunExitCode(t *testing.T) {
	runHome(t)
	t.Setenv("RUN_CHILD_EXIT", "42")
	if _, exit, code := runOut(t, append([]string{"run"}, childArgs()...)...); exit != 42 || code != "" {
		t.Fatalf("want exit 42, got %d %s", exit, code)
	}
}

func TestRunDryRunReadsNoValue(t *testing.T) {
	runHome(t)
	d := mustRun(t, append([]string{"--dry-run", "run", "-e", "TOKEN=secret:missing", "-e", "PLAIN=hello"}, childArgs()...)...)
	env := d["env"].(map[string]any)
	if env["TOKEN"] != "secret:missing" || env["PLAIN"] != "[value]" || d["program"] == "" {
		t.Errorf("dry run: %v", d)
	}
}

func TestRunAgentNeedsYes(t *testing.T) {
	runHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	wantCode(t, "SECRET_DESTINATION", append([]string{"run", "-e", "TOKEN=secret:tok"}, childArgs()...)...)
	d := mustRun(t, append([]string{"--dry-run", "run", "-e", "TOKEN=secret:tok"}, childArgs()...)...)
	if need := fmt.Sprint(d["_meta"].(map[string]any)["would_need"]); !strings.Contains(need, "--yes") {
		t.Errorf("would_need: %v", d["_meta"])
	}
	texts := windowText(t, true)
	text, exit, _ := runOut(t, append([]string{"run", "-e", "TOKEN=secret:tok", "--yes"}, childArgs()...)...)
	if exit != 0 || len(*texts) != 1 || !strings.Contains((*texts)[0], "secret:tok") || !strings.Contains((*texts)[0], "on this computer") {
		t.Fatalf("exit %d %q %q", exit, text, *texts)
	}
	if strings.Contains(text, "s3cr3t-value-123") {
		t.Errorf("value shown to the agent: %q", text)
	}
}

func TestRunRefusals(t *testing.T) {
	runHome(t)
	wantCode(t, "RESERVED_SECRET", append([]string{"run", "-e", "K=secret:" + approvalSecret}, childArgs()...)...)
	wantCode(t, "USAGE", append([]string{"run"}, childArgs("secret:tok")...)...)
	wantCode(t, "USAGE", "run", "web1", "--", "uptime")
}

func TestRunAgentLoaderEnv(t *testing.T) {
	runHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	for _, k := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "BASH_ENV", "PYTHONSTARTUP"} {
		wantCode(t, "USAGE", append([]string{"run", "--yes", "-e", k + "=/tmp/x", "-e", "TOKEN=secret:tok"}, childArgs()...)...)
	}
	if !loadsCode("ld_preload") || loadsCode("AWS_REGION") || loadsCode("PATH") {
		t.Error("loadsCode")
	}
}

func TestRunWindowNamesPlainKeys(t *testing.T) {
	runHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	texts := windowText(t, true)
	if _, exit, _ := runOut(t, append([]string{"run", "-e", "TOKEN=secret:tok", "-e", "REGION=x", "--yes"}, childArgs()...)...); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "REGION") {
		t.Errorf("window: %q", *texts)
	}
}
