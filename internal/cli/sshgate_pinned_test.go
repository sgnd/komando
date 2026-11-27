package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/spf13/cobra"
)

// TestGateAnswersPinned pins the ssh gate's answer to every command of
// today, typed bare, with --help, with the flags its read form reads, with
// a target word or --to PATH where the gate reads them, for a read key, a
// read key with network, a full key and a --shell-access key. The cut re-keys
// the gate's tables by safety key (cut plan, PR B1): this file must not
// change when it does. KOMANDO_GOLDEN_UPDATE=1 writes it again (only on
// purpose).
func TestGateAnswersPinned(t *testing.T) {
	invHome(t)
	gateInventory(t)
	type probeKey struct {
		name string
		key  gateKey
	}
	keys := []probeKey{{"read", readKey}, {"netread", netReadKey}, {"full", fullKey}, {"shell", shellAccessKey}}
	var ids []string
	paths := map[string][]string{}
	seen := map[string]bool{}
	for _, c := range allCommands(newRoot(tcl)) {
		id := cmdID(c)
		if strings.HasPrefix(c.Name(), "__") || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
		paths[id] = strings.Fields(strings.TrimPrefix(c.CommandPath(), "komando"))
	}
	// no leaf of the vpn type is left out of the probes
	for _, l := range capability.All() {
		if l.Type == "vpn" && l.State == capability.Built && !seen[strings.Join(l.Key.Path(), ".")] {
			t.Errorf("%s: the tree has no command with this ID, so nothing probed it", strings.Join(l.Key.Path(), " "))
		}
	}
	// the answers there must be: one per command, probe and key, counted
	// before any is asked
	probes := 0
	for _, id := range ids {
		probes += len(gateProbeFlags(id)) * len(keys)
	}
	// one tree for every question: gateCheck builds a tree of its own per
	// question, which is most of this test's time; the flags a probe sets
	// are put back after each answer
	sc, root := gateTree()
	answers := 0
	var lines []string
	for _, id := range ids {
		for _, extra := range gateProbeFlags(id) {
			words := slices.Concat(paths[id], extra)
			for _, k := range keys {
				name, _, e := gateCheckIn(sc, root, slices.Clone(words), k.key)
				answers++
				answer := "runs"
				if e != nil {
					answer = e.Code + "|" + e.Message
				}
				lines = append(lines, fmt.Sprintf("%q\t%s\t%s\t%s", strings.Join(words, " "), k.name, name, answer))
			}
			resetProbeFlags(root, words)
		}
	}
	if err := pinCount("gate answer", answers, probes); err != nil {
		t.Error(err)
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
	wantSet := map[string]bool{}
	for _, l := range want {
		wantSet[l] = true
	}
	gotSet := map[string]bool{}
	for _, l := range lines {
		gotSet[l] = true
		if !wantSet[l] {
			t.Errorf("changed or new: %s", l)
		}
	}
	for _, l := range want {
		if !gotSet[l] {
			t.Errorf("gone: %s", l)
		}
	}
}

// probeFlagNames are the flags gateProbeFlags sets after a command's path.
var probeFlagNames = []string{"help", "read-only", "write", "analyze", "refresh", "to"}

// resetProbeFlags puts the flags a probe set on the command words name back
// to their defaults, so the next question on the same tree reads none of
// them.
func resetProbeFlags(root *cobra.Command, words []string) {
	c, _, err := root.Find(words)
	if err != nil {
		return
	}
	for _, n := range probeFlagNames {
		if f := c.Flags().Lookup(n); f != nil && f.Changed {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	}
}

// shellAccessKey is a full key added with --shell-access, called with
// the terminal sshd gives it.
var shellAccessKey = gateKey{network: true, shellAccess: true, tty: true}

// gateProbeFlags are the words each command is probed with after its
// path: none, --help, each flag its read form reads, one target word for
// a command gateTargetArgs reads, and --to PATH for one gateSavesHere
// names.
func gateProbeFlags(id string) [][]string {
	probes := [][]string{nil, {"--help"}}
	for _, f := range []string{"read-only", "write", "analyze", "refresh"} {
		if gateReadForm[cmdKeys[id]] != nil {
			probes = append(probes, []string{"--" + f})
		}
	}
	if gateTargetArgs[cmdKeys[id]] != nil {
		probes = append(probes, []string{"web"})
	}
	if gateSavesHere[cmdKeys[id]] != nil {
		probes = append(probes, []string{"--to", "/tmp/x"})
	}
	return probes
}
