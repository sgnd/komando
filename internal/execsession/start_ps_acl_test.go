package execsession

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// psOutput runs script in the PowerShell psParserFor finds and gives its
// output; it skips without one, and fails without one in CI.
func psOutput(t *testing.T, script string) string {
	t.Helper()
	ps, err := psParserFor(exec.LookPath, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if ps == "" {
		t.Skip("no PowerShell (powershell or pwsh) here; CI runs this check")
	}
	f := filepath.Join(t.TempDir(), "s.ps1")
	if err := os.WriteFile(f, []byte(bom+script), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := exec.Command(ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", f).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return strings.ReplaceAll(string(b), "\r", "")
}

const aclSID = "S-1-5-21-1-2-3-1001"

// psACLCase is one SDDL and what a check must say about it.
type psACLCase struct {
	name, sddl string
	want       bool
}

// runACL runs fn (ks_daclSafe or ks_aclExact) over each case as one
// PowerShell call and checks each answer. The SDDL goes in as a quoted
// literal: test data, not the start script's.
func runACL(t *testing.T, fn string, cases []psACLCase) {
	t.Helper()
	var b strings.Builder
	b.WriteString(psStartHead + "\n")
	for i, c := range cases {
		b.WriteString("Write-Output ('" + string(rune('a'+i)) + "=' + (" + fn + " '" + c.sddl + "' '" + aclSID + "'))\n")
	}
	got := psOutput(t, b.String())
	for i, c := range cases {
		line := string(rune('a'+i)) + "="
		want := line + "False"
		if c.want {
			want = line + "True"
		}
		if !strings.Contains(got, want+"\n") {
			t.Errorf("%s %s: want %s in %q", fn, c.name, want, got)
		}
	}
}

// A-447-1 and A-447-2: a parent folder is safe only when every ACE is
// read in full and none lets anyone else write, inherit-only ones too.
func TestDACLSafe(t *testing.T) {
	base := "O:" + aclSID + "G:" + aclSID + "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + aclSID + ")"
	runACL(t, "ks_daclSafe", []psACLCase{
		{"a profile folder", base, true},
		{"everyone reads", base + "(A;;FR;;;WD)", true},
		{"everyone writes", base + "(A;OICI;FA;;;WD)", false},
		{"inherit-only write", base + "(A;OICIIO;GW;;;WD)", false},
		{"conditional ACE", base + `(XA;;FA;;;WD;(@User.Project == "x"))`, false},
		{"conditional ACE with six fields inside", base + "(XA;;FA;;;WD;(a;b;c;d;e;f))", false},
		{"deny for everyone", base + "(D;;FA;;;WD)", true},
		{"hex write", base + "(A;;0x1301bf;;;BU)", false},
		{"hex read", base + "(A;;0x120089;;;BU)", true},
		{"unknown right", base + "(A;;ZZ;;;BU)", false},
		{"unbalanced", "D:(A;;FA;;;SY", false},
		{"text between ACEs", "D:P(A;;FA;;;SY)x(A;;FA;;;BA)", false},
		{"no DACL", "O:" + aclSID, false},
		{"null DACL", "O:" + aclSID + "D:NO_ACCESS_CONTROL", false},
		{"with a SACL", base + "S:AI(AU;SA;FA;;;WD)", true},
	})
}

// A-447-1: the session folder's DACL is, as text, protected and exactly
// the two entries, nothing left over.
func TestACLExact(t *testing.T) {
	o := "O:" + aclSID + "G:" + aclSID
	user, sys := "(A;OICI;FA;;;"+aclSID+")", "(A;OICI;FA;;;SY)"
	runACL(t, "ks_aclExact", []psACLCase{
		{"protected", o + "D:PAI" + user + sys, true},
		{"either order", o + "D:P" + sys + user, true},
		{"not protected", o + "D:AI" + user + sys, false},
		{"a third entry", o + "D:PAI" + user + sys + "(A;;FR;;;BU)", false},
		{"a conditional entry", o + "D:PAI" + user + sys + `(XA;;FA;;;WD;(@User.x == "y"))`, false},
		{"one entry", o + "D:PAI" + user, false},
		{"owner Administrators", "O:BAG:BAD:PAI" + user + sys, false},
		{"rights not full", o + "D:PAI(A;OICI;FR;;;" + aclSID + ")" + sys, false},
	})
}
