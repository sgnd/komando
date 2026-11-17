package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// doctor's JSON names the fix as words to run, next to the prose: a
// program never has to take a command out of text.
func TestDoctorFixIsStructured(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "db1", "postgres://app@10.0.0.5/app")
	mustRun(t, "conn", "add", "db2", "postgres://app@10.0.0.5/app")
	d, _ := invRun(t, "doctor")
	b, _ := json.Marshal(d)
	var r struct {
		Checks, Inventory, Security []struct {
			Name, Detail string
			Fix          []string
		}
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"conn:db2": "komando conn rm db2",
	}
	seen := map[string]bool{}
	for _, c := range append(append(r.Checks, r.Inventory...), r.Security...) {
		if len(c.Fix) > 0 {
			if c.Fix[0] != "komando" {
				t.Errorf("%s: a fix is a komando command: %q", c.Name, c.Fix)
			}
			// the prose shows the same command
			if !strings.Contains(c.Detail, "`"+strings.Join(c.Fix, " ")+"`") {
				t.Errorf("%s: detail %q does not show the fix %q", c.Name, c.Detail, c.Fix)
			}
		}
		if w, ok := want[c.Name]; ok && strings.Join(c.Fix, " ") == w {
			seen[c.Name] = true
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s has no fix %q: %s", name, want[name], b)
		}
	}
}

// Names and details are safe to show in JSON as on the terminal; the
// words of a fix stay exact.
func TestDoctorReportSafe(t *testing.T) {
	r := doctorReport{
		Checks:    []doctorCheck{{Name: "vpn:x\x1b]0;t\x07", Detail: "a\u202eb"}},
		Inventory: []securityCheck{{Name: "conn:a", Detail: "runs `x\x1b[2J`", Fix: []string{"komando", "conn", "rm", "a\x1b"}}},
		Security:  []securityCheck{{Name: "security:x", Detail: "ok\tfine"}},
	}
	r.safe()
	b, _ := json.Marshal(r)
	var back struct {
		Checks, Inventory, Security []struct {
			Name, Detail string
			Fix          []string
		}
	}
	json.Unmarshal(b, &back)
	for _, c := range append(append(back.Checks, back.Inventory...), back.Security...) {
		if strings.ContainsAny(c.Name+c.Detail, "\x1b\x07\u202e") {
			t.Errorf("%q / %q", c.Name, c.Detail)
		}
	}
	if back.Inventory[0].Fix[3] != "a\x1b" || back.Security[0].Detail != "ok\tfine" {
		t.Errorf("changed what must stay: %+v", back)
	}
}

func TestDoctorSecurityFixes(t *testing.T) {
	invHome(t)
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	st.Settings.Audit, st.Settings.HostKeyPolicy = false, "off"
	got := map[string]string{}
	for _, c := range securityChecks(tcl, st) {
		got[c.Name] = strings.Join(c.Fix, " ")
	}
	if got["security:audit"] != "komando config set audit on" || got["security:host_keys"] != "komando config set host_key_policy accept-new" {
		t.Errorf("fixes: %v", got)
	}
	if fixText(komandoFix("conn", "rm", "a b; rm -rf ~")) != "`komando conn rm 'a b; rm -rf ~'`" {
		t.Errorf("quoting: %s", fixText(komandoFix("conn", "rm", "a b; rm -rf ~")))
	}
}
