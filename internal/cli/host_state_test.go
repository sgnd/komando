package cli

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sshx"
)

func readHostState(s string) hostState {
	var hs hostState
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			hs.line(k, v)
		}
	}
	return hs
}

func TestHostStateLines(t *testing.T) {
	// needrestart says a newer kernel waits: that is a reboot, even when
	// /var/run/reboot-required is not there
	hs := readHostState("failed_checked=yes\nreboot=no\nrestart_checked=yes\nsvc=nginx.service\nsvc=nginx.service\nksta=3\n")
	if hs.Reboot == nil || !*hs.Reboot || !slicesHas(hs.RebootPackages, "kernel") {
		t.Errorf("ksta=3: %+v", hs)
	}
	if !hs.FailedChecked || len(hs.Failed) != 0 || !hs.RestartChecked || len(hs.NeedRestart) != 1 {
		t.Errorf("lists: %+v", hs)
	}
	if hs := readHostState("ksta=1\n"); hs.Reboot != nil {
		t.Errorf("ksta=1 is the running kernel: %+v", hs)
	}
	if hs := readHostState("hostname=web1\n"); hs.Reboot != nil || hs.FailedChecked || hs.RestartChecked {
		t.Errorf("other keys: %+v", hs)
	}
	var h hostState
	if h.line("hostname", "x") {
		t.Error("hostname is not a hoststate key")
	}
}

// facts on a dnf server: needs-restarting -s lists the services, like
// pkg security does.
func TestFactsHostStateDnf(t *testing.T) {
	f := map[string]any{}
	hostStateFacts(f, readHostState("reboot=yes\nrestart_checked=yes\nsvc=sshd.service\n"))
	if f["reboot_required"] != true || len(f["services_need_restart"].([]string)) != 1 || len(f["reboot_packages"].([]string)) != 0 {
		t.Errorf("facts: %v", f)
	}
	f = map[string]any{}
	hostStateFacts(f, hostState{})
	if f["reboot_required"] != nil || f["services_need_restart"] != nil || f["failed_units"] != nil {
		t.Errorf("nothing known: %v", f)
	}
}

// pkg security on an OS past end of life warns that an empty list is not
// safety; on a supported one it says nothing.
func TestPkgSecSupport(t *testing.T) {
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	sup, w := pkgSecSupport("os=amzn\nos_version=2\nos_pretty=Amazon Linux 2\n", now)
	if sup.Status != "unsupported" || !strings.Contains(w, "end of life") || !strings.Contains(w, "empty list") {
		t.Errorf("amzn 2: %+v %q", sup, w)
	}
	if sup, w := pkgSecSupport("os=rocky\nos_version=9.6\nos_pretty=Rocky Linux 9.6\n", now); sup.Status != "supported" || w != "" {
		t.Errorf("rocky 9: %+v %q", sup, w)
	}
	out := "#komando:pm\nyum\n#komando:os\nos=amzn\nos_version=2\nos_pretty=Amazon Linux 2\n#komando:before\npending=0\nsecurity=0\n#komando:security\n"
	r := pkgSecParse(tcl, "al2", &sshx.RunResult{Stdout: out}, false, false)
	if !r.OK || r.OSSupport == nil || r.OSSupport.Status != "unsupported" || len(r.Warnings) != 1 {
		t.Errorf("row: %+v", r)
	}
}

// The shared shell is valid sh, and the scripts that use it too.
func TestHostStateShellParses(t *testing.T) {
	unixOnly(t, "checks a server's sh script with sh -n")
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for name, s := range map[string]string{"facts": factsScript, "pkg security": pkgSecScript(true, true, true)} {
		if o, err := exec.Command(sh, "-n", "-c", s).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", name, err, o)
		}
	}
}
