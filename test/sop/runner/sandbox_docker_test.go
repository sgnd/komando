package runner

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Audit E1, inside the real tool: run three commands in a tool container
// and expect each to fail. It needs Docker and the image named by
// SOP_TOOL_IMAGE (the CI smoke job sets both); anywhere else it is skipped,
// never counted as a pass.
func TestToolContainerBoundary(t *testing.T) {
	image := os.Getenv("SOP_TOOL_IMAGE")
	if image == "" {
		t.Skip("SOP_TOOL_IMAGE not set: this runs in the CI smoke job, where Docker is")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	net := "sop-internal-" + strings.ReplaceAll(t.Name(), "/", "-")
	if out, err := exec.CommandContext(ctx, NetworkCreateArgs(net)[0], NetworkCreateArgs(net)[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("network: %v\n%s", err, out)
	}
	defer exec.Command("docker", "network", "rm", net).Run()
	// the runner's environment holds secrets; the tool must not see them
	runnerEnv := []string{"PATH=/usr/bin:/bin", "SOP_API_KEY=k-must-not-leak", "GITHUB_TOKEN=ghs_must_not_leak", "ACTIONS_RUNTIME_TOKEN=t"}
	tc := ToolContainer{Name: "sop-boundary", Network: net, RunDir: t.TempDir(), Image: image, Env: ToolEnv(runnerEnv)}
	run := func(argv ...string) (string, error) {
		a := ToolContainerArgs(tc, argv)
		out, err := exec.CommandContext(ctx, a[0], a[1:]...).CombinedOutput()
		return string(out), err
	}
	if out, err := run("env"); err != nil || strings.Contains(out, "k-must-not-leak") || strings.Contains(out, "GITHUB_") || strings.Contains(out, "ACTIONS_") {
		t.Errorf("env in the tool: %v\n%s", err, out)
	}
	if out, err := run("curl", "-sS", "--max-time", "5", "https://example.com"); err == nil {
		t.Errorf("curl reached the internet from the tool:\n%s", out)
	}
	if out, err := run("ls", "/var/run/docker.sock"); err == nil {
		t.Errorf("the Docker socket is visible in the tool:\n%s", out)
	}
}
