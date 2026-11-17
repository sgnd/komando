package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The e2e lab runs komando on the developer's computer. It must never
// reach that person's home folder, login keychain or desktop keyring: an
// AI agent's call keeps the store's change count in the default keychain
// whatever KOMANDO_KEYCHAIN says (internal/vault/keychain.go, countOff),
// and on macOS no variable moves that keychain. So test/e2e/lab_env.sh
// gives every call a fresh HOME, leaves no keyring bus and no ssh-agent,
// and run.sh refuses to start a lab on macOS. Nothing here starts Docker
// or touches a keychain: the scripts run with stand-in tools first in PATH.
func TestE2ELabKeepsAwayFromThePersonsHome(t *testing.T) {
	unixOnly(t, "the lab's scripts are bash")
	root := filepath.Join("..", "..", "test", "e2e")
	bin := t.TempDir()
	for name, script := range map[string]string{
		"uname":    "#!/bin/sh\necho Linux\n",
		"security": "#!/bin/sh\necho \"security $*\" >> \"$LAB_TOOL_LOG\"\nexit 1\n",
		// never a real lab: a run.sh that does not stop would only reach these
		"docker": "#!/bin/sh\necho \"docker $*\" >> \"$LAB_TOOL_LOG\"\nexit 1\n",
		"go":     "#!/bin/sh\necho \"go $*\" >> \"$LAB_TOOL_LOG\"\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	toolLog := filepath.Join(t.TempDir(), "tools")
	realHome := t.TempDir()
	env := []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + realHome, "LAB_TOOL_LOG=" + toolLog,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/bus", "SSH_AUTH_SOCK=/tmp/agent.sock", "XDG_CONFIG_HOME=" + realHome + "/.config"}

	// the lab's environment, as lib.sh sets it before the first call
	c := exec.Command("bash", "-c", `. "$1/lab_env.sh" && lab_env && env`, "bash", root)
	c.Env = env
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("lab_env: %v\n%s", err, out)
	}
	got := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			got[k] = v
		}
	}
	if h := got["HOME"]; h == "" || h == realHome || !filepath.IsAbs(h) {
		t.Errorf("HOME = %q: the lab keeps the person's home (%s)", h, realHome)
	}
	for _, k := range []string{"USERPROFILE", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"} {
		if !strings.HasPrefix(got[k], got["HOME"]) || got["HOME"] == "" {
			t.Errorf("%s = %q, not inside the lab's HOME %q", k, got[k], got["HOME"])
		}
	}
	for _, k := range []string{"DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK"} {
		if v, ok := got[k]; ok {
			t.Errorf("%s=%s is left: a desktop keyring or the person's ssh-agent is reachable", k, v)
		}
	}

	// on macOS the lab does not start, and says why
	if err := os.WriteFile(filepath.Join(bin, "uname"), []byte("#!/bin/sh\necho Darwin\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c = exec.Command("bash", filepath.Join(root, "run.sh"))
	c.Env = append(env, "AREA=core")
	out, err = c.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "login keychain") {
		t.Errorf("run.sh on macOS: %v\n%s", err, out)
	}
	// listing the areas starts nothing, so it works on a Mac too
	c = exec.Command("bash", filepath.Join(root, "run.sh"), "--list")
	c.Env = env
	if out, err = c.CombinedOutput(); err != nil || !strings.Contains(string(out), "core") {
		t.Errorf("run.sh --list on macOS: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(toolLog); len(b) > 0 {
		t.Errorf("a keychain tool, docker or go was run: %s", b)
	}
}
