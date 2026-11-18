package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// doctor's JSON names the fix as words to run, next to the prose: a
// program never has to take a command out of text. A fix is offered only
// when it asks nothing and is right whatever else is true.
func TestDoctorFixIsStructured(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "db", "u@10.0.0.5", "--protected")
	mustRun(t, "conn", "add", "db1", "postgres://app@10.0.0.5/app", "--label", "host=db")
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
	fixes := map[string]string{}
	for _, c := range append(append(r.Checks, r.Inventory...), r.Security...) {
		if len(c.Fix) == 0 {
			continue
		}
		fixes[c.Name] = strings.Join(c.Fix, " ")
		if c.Fix[0] != "komando" || !strings.Contains(c.Detail, "`"+strings.Join(c.Fix, " ")+"`") {
			t.Errorf("%s: fix %q, detail %q", c.Name, c.Fix, c.Detail)
		}
	}
	if fixes["conn:db1"] != "komando conn edit db1 --protected" {
		t.Errorf("conn:db1: %q (all: %v)", fixes["conn:db1"], fixes)
	}
	// a duplicate may not be one: no fix, the prose names the way
	if _, ok := fixes["conn:db2"]; ok {
		t.Errorf("conn:db2 got a fix: %v", fixes)
	}
}

// A name that could be read as a flag, or holds a control character,
// gives no fix at all.
func TestKomandoFixRefusesFlagsAndControls(t *testing.T) {
	for _, w := range []string{"--yes", "-o", "", "a\x1b", "a b", "a\u202e"} {
		if f := komandoFix("conn", "rm", w); f != nil {
			t.Errorf("%q: %q", w, f)
		}
	}
	if f := withFlag(komandoFix("conn", "edit", "db-1.prod"), "--protected"); strings.Join(f, " ") != "komando conn edit db-1.prod --protected" {
		t.Errorf("%q", f)
	}
	if withFlag(komandoFix("conn", "edit", "--x"), "--protected") != nil {
		t.Error("withFlag of nil")
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
}
