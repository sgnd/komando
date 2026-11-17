package out

import (
	"bytes"
	"strings"
	"testing"
)

// Text-mode hints are hidden and made safe like the message next to them
// (a hint can carry the command line).
func TestTextHintIsRedactedAndSafe(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{Format: "text", Mask: true, W: &bytes.Buffer{}, Err: &buf,
		Secrets: func() map[string]string { return map[string]string{"DB_PASS": "Vault-Value-123"} }}
	hint := "run: komando exec web -- 'mysql --password=hunter2abcdef Vault-Value-123' '\x1b]52;c;ZXZpbA==\a' '\x1b[8mhidden\x1b[0m' 'cover\rup'"
	for name, run := range map[string]func(){
		"fail": func() { p.Fail("exec", &Error{Code: "POLICY_BLOCKED", Message: "m", Hint: hint, Exit: ExitPolicy}) },
		"soft": func() { p.Print("exec", nil, &Error{Code: "PARTIAL", Message: "m", Hint: hint}) },
		"dry-run": func() {
			p.DryRun = true
			p.blocked = &Error{Code: "POLICY_BLOCKED", Message: "m", Hint: hint}
			p.Print("exec", nil, nil)
			p.DryRun, p.blocked = false, nil
		},
	} {
		buf.Reset()
		run()
		_, got, ok := strings.Cut(buf.String(), "Hint: ")
		if !ok {
			t.Fatalf("%s: no hint printed: %q", name, buf.String())
		}
		for _, bad := range []string{"Vault-Value-123", "hunter2abcdef", "\x1b", "\a", "\r"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: hint shows %q: %q", name, bad, got)
			}
		}
		if !strings.Contains(got, `\e[8mhidden`) || !strings.Contains(got, `cover\rup`) {
			t.Errorf("%s: conceal and carriage return are not shown as escapes: %q", name, got)
		}
		if !strings.Contains(got, "[secret:DB_PASS]") {
			t.Errorf("%s: hint lost the vault label: %q", name, got)
		}
	}
}
