package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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

	v := shotCaseView(t)
	var allowed bool
	switch runtime.GOOS {
	case "darwin":
		// osascript directly, so its exit code and stderr reach the CI log
		ctx, cancel := context.WithTimeout(context.Background(), macWindowTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/bin/osascript", macArgs(v)...).CombinedOutput()
		t.Logf("osascript: err %v, output %q", err, out)
		allowed = macAnswer(out) == macAllowed
	case "windows":
		_, allowed, _, _ = approvalWindow(v, false)
	}
	if allowed {
		t.Fatal("nobody clicked, but the window allowed")
	}
}

// TestApprovalWindowKey shows the real panel in a debug run on a macOS
// GitHub runner while approval-window.yml presses one key (KOMANDO_KEY)
// in it (C238). It keeps the run in KOMANDO_KEY_OUT as <case>-<key>.log
// (the debug log), .stderr (osascript's own) and .exit (its exit code, -1
// for a signal), and stops the panel after 15 s. The workflow judges it.
func TestApprovalWindowKey(t *testing.T) {
	shotRunner(t)
	if runtime.GOOS != "darwin" {
		t.Skip("the key run is macOS only")
	}
	key, out := os.Getenv("KOMANDO_KEY"), os.Getenv("KOMANDO_KEY_OUT")
	if !regexp.MustCompile(`^[a-z][a-z-]*$`).MatchString(key) || out == "" {
		t.Fatalf("KOMANDO_KEY=%q (lowercase with hyphens) and KOMANDO_KEY_OUT=%q (a folder) are both needed", key, out)
	}
	if os.Getenv(approvalDebugEnv) == "" {
		t.Fatalf("%s is not set: the key run is a debug run", approvalDebugEnv)
	}
	t.Setenv("HOME", t.TempDir())
	saved := macWindowTimeout
	macWindowTimeout = 15 * time.Second
	t.Cleanup(func() { macWindowTimeout = saved })

	v := shotCaseView(t)
	r := macPanelRun(v, true)
	var log bytes.Buffer
	macDebugLog(&log, v, r)
	code := "0"
	var ee *exec.ExitError
	if errors.As(r.err, &ee) {
		code = strconv.Itoa(ee.ExitCode())
	} else if r.err != nil {
		code = "did not start"
	}
	base := filepath.Join(out, os.Getenv("KOMANDO_SHOT_CASE")+"-"+key)
	for ext, b := range map[string][]byte{".log": log.Bytes(), ".stderr": r.errOut, ".exit": []byte(code + "\n")} {
		if err := os.WriteFile(base+ext, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("\n" + log.String())
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

// shotView is the 4-line script sample the window golden and the box
// scroll test share: example hosts, a made-up script.
func shotView() approvalView {
	return testView("Claude Code", []string{"--allow-dangerous", "--yes"}, "",
		[]string{"it runs on web-1.example.test (protected)", protWhy([]string{"web-1.example.test"}), "[rm-system-dir] deletes a system folder recursively"},
		"komando host ssh exec web-1.example.test --script ./deploy.sh --allow-dangerous --yes",
		"It also sends the script ./deploy.sh (98 bytes, 4 lines, SHA-256 9f2c), all of it:\n\n  1  #!/bin/sh\n  2  set -e\n"+
			"  3  systemctl stop app && rm -rf /srv/app/cache && tar -xzf /tmp/release.tgz -C /srv/app && systemctl start app\n  4  echo done\n")
}

// shotCase is one screenshot case: its name goes in KOMANDO_SHOT_CASE
// and in the PNG's name, so it stays lowercase with hyphens.
type shotCase struct {
	name string
	view func() approvalView
}

// The long-lines and tall-script cases start with "# LINEONEMARK": the
// workflow reads it back from the screenshot to prove line 1 shows at open.

// shotCases are the windows approval-window.yml captures, one per case.
// Keep the names in step with the workflow's matrix.
var shotCases = []shotCase{
	{"short", func() approvalView {
		return testView("Claude Code", []string{"--yes"}, "", []string{"it runs on web-1.example.test"},
			"komando host ssh exec web-1.example.test --yes -- systemctl restart app", "")
	}},
	{"script", func() approvalView {
		var body strings.Builder
		body.WriteString("It also sends the script ./migrate.sh (1210 bytes, 24 lines, SHA-256 4be1), all of it:\n\n")
		lines := []string{"#!/bin/sh", "set -eu", "cat > /etc/app/release.env <<'EOF'", "APP_PORT=8080", "APP_MODE=production", "EOF",
			"systemctl stop app", "cd /srv/app", "tar -xzf /tmp/release.tgz", "for f in migrations/*.sql; do", "  psql -d app -f \"$f\"", "done",
			"chown -R deploy:deploy /srv/app", "systemctl start app", "for i in 1 2 3 4 5; do", "  curl -fsS http://127.0.0.1:8080/health && break",
			"  sleep 2", "done", "journalctl -u app -n 20 --no-pager", "rm -f /tmp/release.tgz", "echo migrated", "date -u", "uptime", "exit 0"}
		for i, l := range lines {
			fmt.Fprintf(&body, "  %2d  %s\n", i+1, l)
		}
		return testView("Codex", []string{"--yes"}, "", []string{"it runs on web-1.example.test"},
			"komando host ssh exec web-1.example.test --script ./migrate.sh --yes", body.String())
	}},
	{"sudo", func() approvalView {
		return testView("Claude Code", []string{"--yes"}, "", []string{"it runs on web-1.example.test", "sudo runs the command as root"},
			"komando host ssh exec web-1.example.test --sudo --yes -- apt-get install -y nginx", "")
	}},
	{"hosts", func() approvalView {
		hosts := []string{"web-1.example.test", "web-2.example.test", "db-2.example.test", "203.0.113.10"}
		return testView("Claude Code", []string{"--yes"}, "", []string{"it runs on " + strings.Join(hosts, ", "), protWhy(hosts[2:3])},
			"komando host ssh exec web-1.example.test,web-2.example.test,db-2.example.test,203.0.113.10 --yes -- systemctl reload nginx", "")
	}},
	{"destructive", func() approvalView {
		return testView("Codex", []string{"--allow-dangerous", "--yes"}, "", []string{"it runs on db-2.example.test (protected)", protWhy([]string{"db-2.example.test"}),
			"[rm-system-dir,db-drop] deletes a system folder recursively; drops a database"},
			"komando host ssh exec db-2.example.test --allow-dangerous --yes -- rm -rf /srv && psql -d app -c 'DROP DATABASE app'", "")
	}},
	{"db-query", func() approvalView {
		return testView("Claude Code", []string{"--allow-dangerous"}, "", []string{"it runs on db-2.example.test", "--write lets the query change data"},
			"komando db query db-2.example.test --write --allow-dangerous -- \"UPDATE orders SET status = 'cancelled' WHERE created_at < now() - interval '30 days'\"", "")
	}},
	{"long-lines", func() approvalView {
		// 13 lines of 300 base64 characters: the window must stay on the
		// screen with its buttons, the script scrolling (C207)
		lines := []string{"# LINEONEMARK", "base64 -d > /tmp/blob <<'EOF'"}
		for i := range 10 {
			lines = append(lines, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte('a' + i), 0xfb, 0x10}, 75)))
		}
		lines = append(lines, "EOF")
		return testView("Claude Code", []string{"--yes"}, "", []string{"it runs on web-1.example.test"},
			"komando host ssh exec web-1.example.test --script ./blob.sh --yes", shotScript("./blob.sh", "77c0", lines))
	}},
	{"tall-script", func() approvalView {
		// 40 lines, the most a window shows: all of it, by scrolling
		var lines []string
		for i := range 40 {
			lines = append(lines, fmt.Sprintf("echo step %d && systemctl status app-%d --no-pager", i+1, i+1))
		}
		lines[0] = "# LINEONEMARK"
		return testView("Codex", []string{"--yes"}, "", []string{"it runs on web-1.example.test"},
			"komando host ssh exec web-1.example.test --script ./steps.sh --yes", shotScript("./steps.sh", "c3d4", lines))
	}},
	{"indonesian", func() approvalView {
		return testView("Claude Code", []string{"--yes"}, "", []string{"it runs on web-1.example.test", "pengguna minta: hapus cache lama sebelum rilis"},
			"komando host ssh exec web-1.example.test --yes -- echo 'Membersihkan cache aplikasi, mohon tunggu' && rm -r /srv/app/cache/lama", "")
	}},
}

// shotScript is the body approval_body.go writes for a script: its
// head, then each line numbered.
func shotScript(name, sum string, lines []string) string {
	var b strings.Builder
	n := 0
	for _, l := range lines {
		n += len(l) + 1
	}
	fmt.Fprintf(&b, "It also sends the script %s (%d bytes, %d lines, SHA-256 %s), all of it:\n\n", name, n, len(lines), sum)
	for i, l := range lines {
		fmt.Fprintf(&b, "  %2d  %s\n", i+1, l)
	}
	return b.String()
}

// shotCaseView is the case KOMANDO_SHOT_CASE names; it fails on an unknown name.
func shotCaseView(t *testing.T) approvalView {
	name := os.Getenv("KOMANDO_SHOT_CASE")
	for _, c := range shotCases {
		if c.name == name {
			return c.view()
		}
	}
	t.Fatalf("KOMANDO_SHOT_CASE=%q: not a screenshot case", name)
	return approvalView{}
}
