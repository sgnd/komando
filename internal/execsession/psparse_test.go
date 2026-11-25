package execsession

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requirePSEnv set to 1 makes a missing PowerShell parser fail the tests
// instead of skipping them. CI sets it: both its runners ship pwsh, and
// the Windows one Windows PowerShell 5.1 as well.
const requirePSEnv = "KOMANDO_REQUIRE_PWSH"

// psParserFor is the program that parses PowerShell: Windows PowerShell
// (the servers' own, on a Windows runner) before pwsh. "" means there is
// none and the check is skipped; with requirePSEnv set to 1 a missing one
// is an error.
func psParserFor(look func(string) (string, error), getenv func(string) string) (string, error) {
	for _, name := range []string{"powershell", "pwsh"} {
		if p, err := look(name); err == nil {
			return p, nil
		}
	}
	if getenv(requirePSEnv) == "1" {
		return "", fmt.Errorf("%s=1, and neither powershell nor pwsh is on the PATH", requirePSEnv)
	}
	return "", nil
}

// psParseCheck parses the file named by its argument (UTF-8) and prints
// one line per problem: "error" for a parse error, "newer" for a construct
// only PowerShell 7 reads (pipeline chains, the ternary, ??, ??=, ?. and
// ?[]), because the servers run Windows PowerShell 5.1. It exits 1 when it
// printed any. The script under test is data: it is never run.
const psParseCheck = `param([string]$Path)
$text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
$tokens = $null
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errs)
foreach ($e in $errs) { [Console]::Out.WriteLine('error line ' + $e.Extent.StartLineNumber + ': ' + $e.Message) }
$newer = @($ast.FindAll({
    param($n)
    $t = $n.GetType().Name
    if ($t -eq 'PipelineChainAst' -or $t -eq 'TernaryExpressionAst') { return $true }
    if (($t -eq 'BinaryExpressionAst' -or $t -eq 'AssignmentStatementAst') -and @('QuestionQuestion', 'QuestionQuestionEquals') -contains $n.Operator.ToString()) { return $true }
    return ($t -match 'MemberExpressionAst$|^IndexExpressionAst$') -and $n.NullConditional
}, $true))
foreach ($n in $newer) { [Console]::Out.WriteLine('newer line ' + $n.Extent.StartLineNumber + ': ' + $n.Extent.Text) }
if ($errs.Count -gt 0 -or $newer.Count -gt 0) { exit 1 }
exit 0
`

// psProblems parses script as Windows PowerShell 5.1 reads it and gives
// psParseCheck's lines; it skips t when no parser is here (see
// psParserFor).
func psProblems(t *testing.T, script string) []string {
	t.Helper()
	ps, err := psParserFor(exec.LookPath, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if ps == "" {
		t.Skip("no PowerShell parser (powershell or pwsh) here; CI runs this check")
	}
	dir := t.TempDir()
	check, target := filepath.Join(dir, "check.ps1"), filepath.Join(dir, "target.ps1")
	if err := os.WriteFile(check, []byte(psParseCheck), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", check, target)
	b, err := cmd.CombinedOutput()
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	var ee *exec.ExitError
	switch {
	case err == nil && len(lines) == 0:
		return nil
	case errors.As(err, &ee) && ee.ExitCode() == 1 && len(lines) > 0:
		return lines
	}
	t.Fatalf("the parse check did not run: %v: %s", err, b)
	return nil
}

// psParse fails t when script does not parse as Windows PowerShell 5.1.
// Every generated session script goes through it.
func psParse(t *testing.T, script string) {
	t.Helper()
	if p := psProblems(t, script); len(p) > 0 {
		t.Errorf("the script does not parse as Windows PowerShell 5.1:\n%s\nscript:\n%s", strings.Join(p, "\n"), script)
	}
}

// The check passes a script Windows PowerShell 5.1 reads, and names each
// broken or PowerShell-7-only line of one it does not.
func TestPSParseCheck(t *testing.T) {
	psParse(t, "$a = 'it''s'\nif ($a) { Write-Output $a } else { exit 3 }\nGet-Item -LiteralPath $a | ForEach-Object { $_.Name }\n")
	cases := []struct {
		name, script string
		line         int
		newer        bool // PowerShell 7 reads it: pwsh says "newer", Windows PowerShell 5.1 "error"
	}{
		{name: "unclosed block", script: "if ($a) {\n", line: 1},
		{name: "unclosed string", script: "$a = 1\n$b = 'x\n", line: 2},
		{name: "pipeline chain", script: "$a = 1\ngit status && git diff\n", line: 2, newer: true},
		{name: "ternary", script: "$a = $true ? 1 : 2\n", line: 1, newer: true},
		{name: "null coalescing", script: "$a = $b ?? 1\n", line: 1, newer: true},
		{name: "null coalescing assignment", script: "$a ??= 1\n", line: 1, newer: true},
		{name: "null-conditional member", script: "$n = ${a}?.Length\n", line: 1, newer: true},
		{name: "null-conditional index", script: "$n = ${a}?[0]\n", line: 1, newer: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := strings.Join(psProblems(t, c.script), "\n")
			at := fmt.Sprintf(" line %d:", c.line)
			if !strings.HasPrefix(p, "error"+at) && !(c.newer && strings.HasPrefix(p, "newer"+at)) {
				t.Errorf("problems %q, want the first on line %d", p, c.line)
			}
		})
	}
}

// psParserFor finds the parser on a Windows runner (Windows PowerShell,
// the servers' own) before pwsh, skips without one, and fails without one
// when CI asks for it.
func TestPSParserFor(t *testing.T) {
	cases := []struct {
		name    string
		found   []string
		require string
		want    string
		wantErr bool
	}{
		{name: "windows powershell first", found: []string{"powershell", "pwsh"}, want: "/bin/powershell"},
		{name: "pwsh alone", found: []string{"pwsh"}, want: "/bin/pwsh"},
		{name: "none, not required: skip", want: ""},
		{name: "none, required: fail", require: "1", wantErr: true},
		{name: "found, required", found: []string{"pwsh"}, require: "1", want: "/bin/pwsh"},
		{name: "none, required only by 1", require: "yes", want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			look := func(name string) (string, error) {
				for _, f := range c.found {
					if f == name {
						return "/bin/" + name, nil
					}
				}
				return "", errors.New("not found")
			}
			getenv := func(k string) string {
				if k == requirePSEnv {
					return c.require
				}
				return ""
			}
			got, err := psParserFor(look, getenv)
			if (err != nil) != c.wantErr || got != c.want {
				t.Errorf("psParserFor = %q, %v; want %q, error %v", got, err, c.want, c.wantErr)
			}
		})
	}
}
