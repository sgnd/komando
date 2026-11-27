package runner

import (
	"slices"
	"strings"
	"testing"
)

// E1: the shell tool's environment is an allowlist: the key, GITHUB_TOKEN
// and every ACTIONS_*/GITHUB_* variable never reach a command the model
// asks for.
func TestToolEnvIsAnAllowlist(t *testing.T) {
	runnerEnv := []string{
		"PATH=/usr/bin", "HOME=/lab/home", "KOMANDO_HOME=/lab/home/.komando", "KOMANDO_KEYCHAIN=off",
		"CLAUDECODE=1", "KOMANDO_NO_DIALOG=1",
		"SOP_API_KEY=k-secret", "SOP_MODEL=m", "GITHUB_TOKEN=ghs_x", "GITHUB_REPOSITORY=a/b",
		"ACTIONS_RUNTIME_TOKEN=t", "ACTIONS_ID_TOKEN_REQUEST_URL=u", "ANTHROPIC_API_KEY=k2",
		"AWS_SECRET_ACCESS_KEY=s", "RANDOM_THING=1",
	}
	got := ToolEnv(runnerEnv)
	for _, bad := range []string{"SOP_API_KEY", "SOP_MODEL", "GITHUB_TOKEN", "GITHUB_REPOSITORY", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY", "RANDOM_THING"} {
		if slices.ContainsFunc(got, func(e string) bool { return strings.HasPrefix(e, bad+"=") }) {
			t.Errorf("the tool's environment holds %s", bad)
		}
	}
	for _, want := range []string{"PATH=/usr/bin", "HOME=/lab/home", "KOMANDO_HOME=/lab/home/.komando", "KOMANDO_KEYCHAIN=off", "CLAUDECODE=1", "KOMANDO_NO_DIALOG=1"} {
		if !slices.Contains(got, want) {
			t.Errorf("the tool's environment lacks %s", want)
		}
	}
}

// The container command is built to hold the rules of Audit E1: an internal
// network, no Docker socket, no host mount beyond the run folder, no
// privileges, an environment passed one variable at a time.
func TestToolContainerArgs(t *testing.T) {
	args := ToolContainerArgs(ToolContainer{Name: "sop-shell-1", Network: "sop-internal", RunDir: "/run/sop", Image: "komando-lab", Env: []string{"PATH=/usr/bin", "KOMANDO_NO_DIALOG=1"}}, []string{"komando", "list"})
	line := strings.Join(args, " ")
	for _, must := range []string{"--network sop-internal", "--cap-drop ALL", "--security-opt no-new-privileges", "--read-only", "-v /run/sop:/run/sop", "-e PATH=/usr/bin", "-e KOMANDO_NO_DIALOG=1", "komando-lab", "komando list"} {
		if !strings.Contains(line, must) {
			t.Errorf("the command lacks %q:\n%s", must, line)
		}
	}
	for _, bad := range []string{"docker.sock", "--privileged", "--network host", "-v /:", "--pid host", "--env-file", "SOP_API_KEY", "GITHUB_TOKEN"} {
		if strings.Contains(line, bad) {
			t.Errorf("the command holds %q:\n%s", bad, line)
		}
	}
	if n := strings.Count(line, " -v "); n != 1 {
		t.Errorf("%d host mounts, want exactly the run folder", n)
	}
}

// The network is made internal: no route out. The harness makes it, with
// the flag, and the tool never can.
func TestNetworkCreateArgsAreInternal(t *testing.T) {
	line := strings.Join(NetworkCreateArgs("sop-internal"), " ")
	if !strings.Contains(line, "--internal") || !strings.Contains(line, "sop-internal") {
		t.Errorf("%s", line)
	}
}

// Only the harness drives the link cut (task 8): the tool's argv can never
// reach docker. A command line that starts with anything but komando is
// refused (TestRunOnlyKomando), and the container has no docker binary or
// socket; this pins the first half at the argument builder.
func TestToolCannotNameDocker(t *testing.T) {
	args := ToolContainerArgs(ToolContainer{Name: "n", Network: "net", RunDir: "/r", Image: "img"}, []string{"docker", "network", "disconnect", "x"})
	if args[0] == "docker" && slices.Contains(args, "disconnect") && !slices.Contains(args, "run") {
		t.Error("the tool's command became a docker command of the host")
	}
	if !slices.Contains(args, "run") {
		t.Errorf("the tool's command is not wrapped in a container: %v", args)
	}
}
