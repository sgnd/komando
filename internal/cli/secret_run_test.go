package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// TestRunChild is the program `komando secret run` starts in these tests: it
// prints its environment and arguments and exits with RUN_CHILD_EXIT.
func TestRunChild(t *testing.T) {
	if os.Getenv("RUN_CHILD") != "1" {
		t.Skip("helper for the run tests")
	}
	fmt.Printf("TOKEN=%s\nPLAIN=%s\nPAGER=%s\nPATH=%s\nHOME=%s\n", os.Getenv("TOKEN"), os.Getenv("PLAIN"), os.Getenv("PAGER"), os.Getenv("PATH"), os.Getenv("HOME"))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KOMANDO_") {
			fmt.Println("leaked " + kv)
		}
	}
	fmt.Println("args " + strings.Join(os.Args[1:], " "))
	if os.Getenv("RUN_CHILD_BG") == "1" { // a background child keeps stdout open
		bg := exec.Command("sleep", "30")
		bg.Stdout = os.Stdout
		if err := bg.Start(); err != nil {
			fmt.Println("no sleep:", err)
		}
	}
	if os.Getenv("RUN_CHILD_KILL") == "1" {
		p, _ := os.FindProcess(os.Getpid())
		p.Signal(syscall.SIGTERM)
		time.Sleep(10 * time.Second)
	}
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
	text, exit, code := runOut(t, append([]string{"secret", "run", "--env", "TOKEN=credential:tok", "--env", "PLAIN=hello"}, childArgs()...)...)
	if exit != 0 {
		t.Fatalf("exit %d %s: %q", exit, code, text)
	}
	if strings.Contains(text, "s3cr3t-value-123") || !strings.Contains(text, "TOKEN=[credential:tok]") || !strings.Contains(text, "PLAIN=hello") {
		t.Errorf("output: %q", text)
	}
	if strings.Contains(text, "leaked KOMANDO_RUN_TEST") {
		t.Errorf("KOMANDO_* reached the program: %q", text)
	}
	rec := auditText(t)
	if strings.Contains(rec, "s3cr3t-value-123") || !strings.Contains(rec, `"command":"secret.run"`) || !strings.Contains(rec, "credential:tok") {
		t.Errorf("audit: %s", rec)
	}
}

func TestRunExitCode(t *testing.T) {
	runHome(t)
	t.Setenv("RUN_CHILD_EXIT", "42")
	if _, exit, code := runOut(t, append([]string{"secret", "run"}, childArgs()...)...); exit != 42 || code != "" {
		t.Fatalf("want exit 42, got %d %s", exit, code)
	}
}

func TestRunDryRunReadsNoValue(t *testing.T) {
	runHome(t)
	d := mustRun(t, append([]string{"--dry-run", "secret", "run", "-e", "TOKEN=credential:missing", "-e", "PLAIN=hello"}, childArgs()...)...)
	env := d["env"].(map[string]any)
	if env["TOKEN"] != "credential:missing" || env["PLAIN"] != "[value]" || d["program"] == "" {
		t.Errorf("dry run: %v", d)
	}
}

func TestRunAgentNeedsYes(t *testing.T) {
	runHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	wantCode(t, "SECRET_DESTINATION", append([]string{"secret", "run", "-e", "TOKEN=credential:tok"}, childArgs()...)...)
	d := mustRun(t, append([]string{"--dry-run", "secret", "run", "-e", "TOKEN=credential:tok"}, childArgs()...)...)
	if need := fmt.Sprint(d["_meta"].(map[string]any)["would_need"]); !strings.Contains(need, "--yes") {
		t.Errorf("would_need: %v", d["_meta"])
	}
	texts := windowText(t, true)
	text, exit, _ := runOut(t, append([]string{"secret", "run", "-e", "TOKEN=credential:tok", "--yes"}, childArgs()...)...)
	if exit != 0 || len(*texts) != 1 || !strings.Contains((*texts)[0], "credential:tok") || !strings.Contains((*texts)[0], "on this computer") {
		t.Fatalf("exit %d %q %q", exit, text, *texts)
	}
	if strings.Contains(text, "s3cr3t-value-123") {
		t.Errorf("value shown to the agent: %q", text)
	}
}

func TestRunRefusals(t *testing.T) {
	runHome(t)
	wantCode(t, "RESERVED_SECRET", append([]string{"secret", "run", "-e", "K=credential:" + approvalSecret}, childArgs()...)...)
	wantCode(t, "USAGE", append([]string{"secret", "run"}, childArgs("credential:tok")...)...)
	wantCode(t, "USAGE", "secret", "run", "web1", "--", "uptime")
}

func TestRunAgentLoaderEnv(t *testing.T) {
	runHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	for _, k := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "BASH_ENV", "PYTHONSTARTUP"} {
		wantCode(t, "USAGE", append([]string{"secret", "run", "--yes", "-e", k + "=/tmp/x", "-e", "TOKEN=credential:tok"}, childArgs()...)...)
	}
	if !loadsCode("ld_preload") || loadsCode("AWS_REGION") || loadsCode("PATH") {
		t.Error("loadsCode")
	}
}

func TestRunWindowNamesPlainKeys(t *testing.T) {
	runHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	texts := windowText(t, true)
	if _, exit, _ := runOut(t, append([]string{"secret", "run", "-e", "TOKEN=credential:tok", "-e", "REGION=x", "--yes"}, childArgs()...)...); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "REGION") {
		t.Errorf("window: %q", *texts)
	}
}

func TestRunAgentEnvAllowlist(t *testing.T) {
	runHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	t.Setenv("PAGER", "/tmp/agent-pager")
	t.Setenv("PATH", "/tmp/agent-bin:"+os.Getenv("PATH"))
	texts := windowText(t, true)
	text, exit, _ := runOut(t, append([]string{"secret", "run", "-e", "RUN_CHILD=1", "-e", "TOKEN=credential:tok", "--yes"}, childArgs()...)...)
	if exit != 0 {
		t.Fatalf("exit %d %q", exit, text)
	}
	if strings.Contains(text, "agent-pager") || strings.Contains(text, "agent-bin") || !strings.Contains(text, systemPath) {
		t.Errorf("the agent's environment reached the program: %q", text)
	}

	if len(*texts) != 1 || !strings.Contains((*texts)[0], "RUN_CHILD=1") {
		t.Errorf("window does not show the plain value: %q", *texts)
	}
}

func TestRunPersonKeepsEnv(t *testing.T) {
	runHome(t)
	t.Setenv("PAGER", "/tmp/my-pager")
	text, exit, _ := runOut(t, append([]string{"secret", "run", "-e", "TOKEN=credential:tok"}, childArgs()...)...)
	if exit != 0 || !strings.Contains(text, "PAGER=/tmp/my-pager") {
		t.Errorf("exit %d %q", exit, text)
	}
}

// The test binary that plays the program sets its own HOME as it starts,
// so the account's HOME is checked on the environment komando builds.
func TestRunAgentHomeFromAccount(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if runtime.GOOS == "linux" && !inPasswd(passwdPath, u.Uid) {
		t.Skip("account not in /etc/passwd")
	}
	env, cleanup := agentBaseEnv(tcl, []string{"HOME=/tmp/agent-home", "USER=agent", "LOGNAME=agent", "PAGER=less", "LANG=C"})
	defer cleanup()
	got := strings.Join(env, "\n")
	if strings.Contains(got, "agent") || !slices.Contains(env, "HOME="+u.HomeDir) || !slices.Contains(env, "LANG=C") || strings.Contains(got, "PAGER") {
		t.Errorf("environment for an agent's run: %q", env)
	}
}

func TestInPasswd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte("root:x:0:0:root:/root:/bin/sh\nann:x:1000:1000::/home/ann:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !inPasswd(path, "1000") || inPasswd(path, "1001") || inPasswd(path, "100") || inPasswd(filepath.Join(path, "none"), "0") {
		t.Error("inPasswd")
	}
	dir, cleanup := freshHome(tcl)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Fatalf("fresh home %s: %v %v", dir, fi, err)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("fresh home left behind: %v", err)
	}
}

func TestRunArgRefsRefused(t *testing.T) {
	for _, a := range []string{"credential:x", "env:PW", "--pw=vault:kv/db#pw", "op://v/i/f", "bw://i/f", "file:/x", "aws-sm:db"} {
		if !argHasRef(a) {
			t.Errorf("%q not refused", a)
		}
	}
	for _, a := range []string{"-h", "http://example.com", "plain"} {
		if argHasRef(a) {
			t.Errorf("%q refused", a)
		}
	}
}

func TestRunExitAfterSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no signals")
	}
	runHome(t)
	t.Setenv("RUN_CHILD_KILL", "1")
	if _, exit, code := runOut(t, append([]string{"secret", "run"}, childArgs()...)...); exit != 128+15 {
		t.Errorf("exit %d %s, want 143", exit, code)
	}
}

func TestRunDryRunAsksNobody(t *testing.T) {
	runHome(t)
	texts := windowText(t, true)
	d := mustRun(t, append([]string{"--dry-run", "secret", "run", "-e", "TOKEN=credential:tok", "--yes"}, childArgs()...)...)
	if len(*texts) != 0 || d["dry_run"] != true {
		t.Errorf("a dry run opened the window: %q %v", *texts, d)
	}
}

func TestRunSecondStopEndsProgram(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no sleep program")
	}
	c := exec.Command("sleep", "30")
	if err := c.Start(); err != nil {
		t.Skip(err)
	}
	forget := runningPrograms.add(c.Process)
	defer forget()
	runningPrograms.killAll()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the program still runs after killAll")
	}
}

func TestRunCtrlCNotSentTwice(t *testing.T) {
	if runtime.GOOS != "windows" && slices.Contains(forwardedSignals, os.Interrupt) {
		t.Error("Ctrl-C reaches the program from the terminal; forwarding it makes a second one")
	}
	if argHasRef("file:///tmp/plan.json") || !argHasRef("--password=env:PW") || !argHasRef("file:token") {
		t.Error("argHasRef")
	}
}

func TestRunAgentMayNotOverrideBase(t *testing.T) {
	runHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	for _, kv := range []string{"HOME=/tmp/x", "path=/x", "PAGER=x", "PSQL_PAGER=x", "PSQLRC=x", "GIT_ASKPASS=x", "SSH_AUTH_SOCK=x", "https_proxy=x", "XDG_CONFIG_HOME=x", "LANG=C",
		"KUBECONFIG=x", "DOCKER_CONFIG=x", "PIP_CONFIG_FILE=x", "NPM_CONFIG_FILE=x", "AWS_SHARED_CREDENTIALS_FILE=x", "AWS_CONFIG_FILE=x", "AWS_WEB_IDENTITY_TOKEN_FILE=x",
		"GOFLAGS=x", "CARGO_HOME=x", "RUSTC_WRAPPER=x", "JAVA_HOME=x", "CC=x", "cxx=x"} {
		wantCode(t, "USAGE", append([]string{"secret", "run", "--yes", "-e", kv, "-e", "PGPASSWORD=credential:tok"}, childArgs()...)...)
	}
	windowText(t, true)
	if _, exit, code := runOut(t, append([]string{"secret", "run", "--yes", "-e", "RUN_CHILD=1", "-e", "PGHOST=db1", "-e", "PGPASSWORD=credential:tok"}, childArgs()...)...); exit != 0 {
		t.Errorf("PGHOST refused: exit %d %s", exit, code)
	}
	for _, k := range []string{"AWS_REGION", "TF_VAR_name", "PGHOST", "CLOUDFLARE_ACCOUNT_ID"} {
		if loadsCode(k) || baseSets(k) {
			t.Errorf("%s refused", k)
		}
	}
}

// A background child that keeps the program's output open must not hold
// komando after the program exits.
func TestRunBackgroundChildDoesNotHold(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep")
	}
	runHome(t)
	t.Setenv("RUN_CHILD_BG", "1")
	saved := outputWait
	outputWait = 200 * time.Millisecond
	t.Cleanup(func() { outputWait = saved })
	start := time.Now()
	if _, exit, code := runOut(t, append([]string{"secret", "run"}, childArgs()...)...); exit != 0 {
		t.Errorf("exit %d %s", exit, code)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("komando waited %v for the background child", d)
	}
}
