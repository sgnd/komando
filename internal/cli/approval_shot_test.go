package cli

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// TestApprovalWindowShot shows the real window for a screenshot on a
// GitHub runner (approval-window.yml) and lets it time out: a no. It never
// runs anywhere else, so no window opens on a person's computer.
func TestApprovalWindowShot(t *testing.T) {
	shotRunner(t)
	t.Setenv("HOME", t.TempDir())
	savedGive, savedMac := windowGiveUp, macWindowTimeout
	windowGiveUp, macWindowTimeout = 10*time.Second, 10*time.Second
	t.Cleanup(func() { windowGiveUp, macWindowTimeout = savedGive, savedMac })

	v := shotView
	var allowed bool
	switch runtime.GOOS {
	case "darwin":
		allowed, _, _ = askMac(v)
	case "windows":
		_, allowed, _, _ = approvalWindow(v, false)
	}
	if allowed {
		t.Fatal("nobody clicked, but the window allowed")
	}
}

// shotRunner skips unless this is a macOS or Windows GitHub runner with
// KOMANDO_WINDOW_SHOT=1.
func shotRunner(t *testing.T) {
	runner := map[string]string{"darwin": "macOS", "windows": "Windows"}[runtime.GOOS]
	if os.Getenv("CI") != "true" || os.Getenv("KOMANDO_WINDOW_SHOT") != "1" || runner == "" || os.Getenv("RUNNER_OS") != runner {
		t.Skip("for the window screenshots: only on a macOS or Windows GitHub runner with KOMANDO_WINDOW_SHOT=1")
	}
}

// TestApprovalWindowShotText writes the sample's text to
// KOMANDO_SHOT_TEXT, for the "before" picture drawn by the old dialog.
func TestApprovalWindowShotText(t *testing.T) {
	shotRunner(t)
	if err := os.WriteFile(os.Getenv("KOMANDO_SHOT_TEXT"), []byte(shotView.text()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// shotView is the screenshots' sample: example hosts, a made-up script.
var shotView = approvalView{Agent: "Claude Code", Head: "wants to change web-1.example.test (protected)", Target: "web-1.example.test (protected)",
	Line: "komando exec web-1.example.test --script ./deploy.sh --allow-dangerous --yes",
	Body: "It also sends the script ./deploy.sh (98 bytes, 4 lines, SHA-256 9f2c), all of it:\n\n  1  #!/bin/sh\n  2  set -e\n" +
		"  3  systemctl stop app && rm -rf /srv/app/cache && tar -xzf /tmp/release.tgz -C /srv/app && systemctl start app\n  4  echo done\n",
	Reasons: []string{"a change on protected host web-1.example.test", "[R-7] rm -rf deletes files"},
	Flags:   []string{"--allow-dangerous", "--yes"}}
