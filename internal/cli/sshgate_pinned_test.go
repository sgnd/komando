package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestGateAnswersPinned pins the ssh gate's answer to every command of
// today, typed bare, with --help, and with the flags its read form reads,
// for a read key, a read key with network and a full key. The cut re-keys
// the gate's tables by safety key (cut plan, PR B1): this file must not
// change when it does. KOMANDO_GOLDEN_UPDATE=1 writes it again (only on
// purpose).
func TestGateAnswersPinned(t *testing.T) {
	invHome(t)
	gateInventory(t)
	var lines []string
	seen := map[string]bool{}
	for _, c := range allCommands(newRoot(tcl)) {
		id := cmdID(c)
		if strings.HasPrefix(c.Name(), "__") || seen[id] {
			continue
		}
		seen[id] = true
		path := strings.Fields(strings.TrimPrefix(c.CommandPath(), "komando"))
		for _, extra := range gateProbeFlags(id) {
			words := slices.Concat(path, extra)
			for _, k := range []struct {
				name string
				key  gateKey
			}{{"read", readKey}, {"netread", netReadKey}, {"full", fullKey}} {
				name, _, e := gateCheck(slices.Clone(words), k.key)
				answer := "runs"
				if e != nil {
					answer = e.Code + "|" + e.Message
				}
				lines = append(lines, fmt.Sprintf("%q\t%s\t%s\t%s", strings.Join(words, " "), k.name, name, answer))
			}
		}
	}
	slices.Sort(lines)
	got := strings.Join(lines, "\n") + "\n"
	file := filepath.Join("testdata", "gate_answers_pinned.txt")
	if os.Getenv("KOMANDO_GOLDEN_UPDATE") == "1" {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	for _, l := range lines {
		if !slices.Contains(want, l) {
			t.Errorf("changed or new: %s", l)
		}
	}
	for _, l := range want {
		if !slices.Contains(lines, l) {
			t.Errorf("gone: %s", l)
		}
	}
}

// gateProbeFlags are the flag sets each command is probed with: none,
// --help, and each flag its read form reads.
func gateProbeFlags(id string) [][]string {
	probes := [][]string{nil, {"--help"}}
	for _, f := range []string{"read-only", "write", "analyze", "refresh"} {
		if gateReadForm[id] != nil {
			probes = append(probes, []string{"--" + f})
		}
	}
	return probes
}
