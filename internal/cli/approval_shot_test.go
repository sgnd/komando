package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestApprovalWindowShot shows the real window for a screenshot on a
// GitHub runner (approval-window.yml) and lets it time out after 20 s: a no. It never
// runs anywhere else, so no window opens on a person's computer.
func TestApprovalWindowShot(t *testing.T) {
	shotRunner(t)
	t.Setenv("HOME", t.TempDir())
	savedGive, savedMac := windowGiveUp, macWindowTimeout
	windowGiveUp, macWindowTimeout = 20*time.Second, 20*time.Second
	t.Cleanup(func() { windowGiveUp, macWindowTimeout = savedGive, savedMac })

	v := shotView()
	var allowed bool
	switch runtime.GOOS {
	case "darwin":
		// osascript directly, so its exit code and stderr reach the CI log
		ctx, cancel := context.WithTimeout(context.Background(), macWindowTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/bin/osascript", macArgs(v)...).CombinedOutput()
		t.Logf("osascript: err %v, output %q", err, out)
		allowed, _ = macAnswer(out)
	case "windows":
		_, allowed, _, _ = approvalWindow(v, false)
	}
	if allowed {
		t.Fatal("nobody clicked, but the window allowed")
	}
}

// ciAtStart is CI as the runner set it: TestMain takes CI out of the
// environment, and package variables are set before TestMain runs.
var ciAtStart = os.Getenv("CI")

// shotRunner skips when KOMANDO_WINDOW_SHOT is not 1. With it set, it
// fails unless this is a macOS or Windows GitHub runner, naming why.
func shotRunner(t *testing.T) {
	if os.Getenv("KOMANDO_WINDOW_SHOT") != "1" {
		t.Skip("for the window screenshots: set KOMANDO_WINDOW_SHOT=1 on a macOS or Windows GitHub runner")
	}
	want := map[string]string{"darwin": "macOS", "windows": "Windows"}[runtime.GOOS]
	var bad []string
	if ciAtStart != "true" {
		bad = append(bad, fmt.Sprintf("CI=%q, want \"true\"", ciAtStart))
	}
	if want == "" {
		bad = append(bad, fmt.Sprintf("GOOS=%q has no approval window to capture", runtime.GOOS))
	} else if got := os.Getenv("RUNNER_OS"); got != want {
		bad = append(bad, fmt.Sprintf("RUNNER_OS=%q, want %q", got, want))
	}
	if len(bad) > 0 {
		t.Fatalf("KOMANDO_WINDOW_SHOT=1, but not on a matching GitHub runner: %s", strings.Join(bad, "; "))
	}
}

// TestApprovalWindowShotText writes the sample's text to
// KOMANDO_SHOT_TEXT, for the "before" picture drawn by the old dialog.
func TestApprovalWindowShotText(t *testing.T) {
	shotRunner(t)
	if err := os.WriteFile(os.Getenv("KOMANDO_SHOT_TEXT"), []byte(shotView().text()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// shotView is the screenshots' sample: example hosts, a made-up script.
func shotView() approvalView {
	return testView("Claude Code", []string{"--allow-dangerous", "--yes"}, "",
		[]string{"it runs on web-1.example.test (protected)", protWhy([]string{"web-1.example.test"}), "[R-7] rm -rf deletes files"},
		"komando exec web-1.example.test --script ./deploy.sh --allow-dangerous --yes",
		"It also sends the script ./deploy.sh (98 bytes, 4 lines, SHA-256 9f2c), all of it:\n\n  1  #!/bin/sh\n  2  set -e\n"+
			"  3  systemctl stop app && rm -rf /srv/app/cache && tar -xzf /tmp/release.tgz -C /srv/app && systemctl start app\n  4  echo done\n")
}
