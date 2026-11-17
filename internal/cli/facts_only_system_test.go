package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// runFactsOnly runs the --only script in a real sh, with /etc/os-release
// replaced by osRelease ("" keeps the real one).
func runFactsOnly(t *testing.T, osRelease string, sections ...string) (string, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	script, _, err := factsOnly(sections)
	if err != nil {
		t.Fatal(err)
	}
	if osRelease != "" {
		p := filepath.Join(t.TempDir(), "os-release")
		if err := os.WriteFile(p, []byte(osRelease), 0o600); err != nil {
			t.Fatal(err)
		}
		script = strings.ReplaceAll(script, "/etc/os-release", p)
	}
	b, err := exec.Command("sh", "-c", script).Output()
	return string(b), err
}

// A server without /proc/uptime or /etc/os-release (macOS, BSD, a masked
// container) still answers: the script ends well whatever the order of
// the sections, and says what it can.
func TestFactsOnlySystemRunsAnywhere(t *testing.T) {
	for _, secs := range [][]string{{"system"}, {"load", "system"}, {"system", "mem"}, {"mem"}} {
		got, err := runFactsOnly(t, "", secs...)
		if err != nil {
			t.Errorf("--only %v: %v (output %q)", secs, err, got)
		}
		if secs[0] != "mem" && !strings.Contains(got, "os=") {
			t.Errorf("--only %v: no os= in %q", secs, got)
		}
	}
	got, _ := runFactsOnly(t, "", "system")
	if !strings.Contains(got, "uptime_sec=") || !strings.Contains(got, "os_version=") {
		t.Errorf("this computer gives no uptime or version: %q", got)
	}
}

// A broken or odd /etc/os-release costs only its own values: the other
// sections still answer, its variables do not reach them, and a value
// cannot add a line of its own.
func TestFactsOnlySystemOsRelease(t *testing.T) {
	got, err := runFactsOnly(t, "ID=x\nPRETTY_NAME=\"unterminated\n", "system", "load")
	if err != nil || !strings.Contains(got, "cpus=") {
		t.Errorf("broken os-release: %v, %q", err, got)
	}
	got, err = runFactsOnly(t, "ID=x\nPATH=/nope\n", "system", "load")
	if err != nil || !strings.Contains(got, "os=x\n") || strings.Contains(got, "cpus=\n") {
		t.Errorf("os-release PATH reached the next section: %v, %q", err, got)
	}
	got, _ = runFactsOnly(t, "ID=x\nPRETTY_NAME=\"A\\nuptime_sec=5\"\n", "system")
	if strings.Contains(got, "\nuptime_sec=5\n") {
		t.Errorf("a value wrote its own line: %q", got)
	}
}

// Values keep their type: a name is a string whatever it looks like, and
// one the server does not have is null, not "".
func TestFactsOnlySystemTypes(t *testing.T) {
	_, keys, _ := factsOnly([]string{"system"})
	d, err := factsOnlyParse(keys)(&store.Host{Name: "web"}, "os=true\nos_version=\nos_pretty=2024\n")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	if want := `{"os":"true","os_pretty":"2024","os_version":null,"uptime_sec":null}`; string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

// -o text shows the system section too.
func TestFactsOnlySystemText(t *testing.T) {
	code := 0
	d := probeData{Results: []probeRow{{Host: "web", OK: true, ExitCode: &code, Data: map[string]any{
		"os": "ubuntu", "os_version": "24.04", "os_pretty": "Ubuntu 24.04.1 LTS", "uptime_sec": int64(90000)}}}}
	got := factsOnlyText(d)
	if !strings.Contains(got, "Ubuntu 24.04.1 LTS") || !strings.Contains(got, "up 25h") {
		t.Errorf("text %q", got)
	}
}
