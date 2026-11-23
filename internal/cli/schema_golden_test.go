package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The pins below hold today's command tree byte for byte while its code
// moves into packages of its own: what `komando schema` prints, the help of
// every command, and every question a person is asked. A move that changes
// one of them fails here. KOMANDO_GOLDEN_UPDATE=1 records them again (only
// on purpose, after reading the diff).

func TestSchemaGolden(t *testing.T) {
	if testing.Short() || raceOn {
		t.Skip("builds the whole tree")
	}
	unixOnly(t, "the recording is made on Unix: default paths differ on Windows")
	stdout, stderr, code := goldenRun(t, false, []string{"-o", "json", "schema"})
	if code != 0 {
		t.Fatalf("komando schema: exit %d\n%s", code, stderr)
	}
	var b bytes.Buffer
	if err := json.Indent(&b, []byte(stdout), "", "  "); err != nil {
		t.Fatalf("komando schema: not JSON: %v", err)
	}
	b.WriteByte('\n')
	matchGolden(t, "testdata/schema_golden.json", b.String())
}

// matchGolden compares got with the file, or writes it under
// KOMANDO_GOLDEN_UPDATE=1, and names the first line that differs.
func matchGolden(t *testing.T, file, got string) {
	t.Helper()
	if os.Getenv("KOMANDO_GOLDEN_UPDATE") == "1" {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got == string(want) {
		return
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
	for i := range min(len(gl), len(wl)) {
		if gl[i] != wl[i] {
			t.Fatalf("%s changed at line %d (KOMANDO_GOLDEN_UPDATE=1 records it, on purpose only)\n got: %s\nwant: %s%s",
				file, i+1, gl[i], wl[i], goldenSection(gl, i))
		}
	}
	t.Fatalf("%s changed: %d lines, want %d", file, len(gl), len(wl))
}

// goldenSection names the "### " heading above line i, if there is one.
func goldenSection(lines []string, i int) string {
	for j := i; j >= 0; j-- {
		if strings.HasPrefix(lines[j], "### ") {
			return fmt.Sprintf("\nunder: %s", lines[j])
		}
	}
	return ""
}
