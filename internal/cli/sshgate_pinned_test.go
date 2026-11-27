package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sgnd/komando/internal/capability"
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
	type probe struct {
		words []string
		name  string
		key   gateKey
	}
	var probes []probe
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
			}{{"read", readKey}, {"netread", netReadKey}, {"full", fullKey}, {"shell", shellAccessKey}} {
				probes = append(probes, probe{words, k.name, k.key})
			}
		}
	}
	// no leaf of the vpn type is left out of the probes
	for _, l := range capability.All() {
		if l.Type == "vpn" && l.State == capability.Built && !seen[strings.Join(l.Key.Path(), ".")] {
			t.Errorf("%s: the tree has no command with this ID, so nothing probed it", strings.Join(l.Key.Path(), " "))
		}
	}
	// Every probe builds a command tree of its own (gateCheck) and reads
	// the stored inventory only, so the probes run on all cores; the answers
	// land at the probe's index and the lines are sorted below.
	lines := make([]string, len(probes))
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(runtime.NumCPU(), 8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(probes) {
					return
				}
				p := probes[i]
				name, _, e := gateCheck(slices.Clone(p.words), p.key)
				answer := "runs"
				if e != nil {
					answer = e.Code + "|" + e.Message
				}
				lines[i] = fmt.Sprintf("%q\t%s\t%s\t%s", strings.Join(p.words, " "), p.name, name, answer)
			}
		}()
	}
	wg.Wait()
	if n := len(slices.DeleteFunc(slices.Clone(lines), func(l string) bool { return l == "" })); n != len(probes) {
		t.Fatalf("%d answers for %d probes: a probe was skipped", n, len(probes))
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
	inWant, inGot := make(map[string]bool, len(want)), make(map[string]bool, len(lines))
	for _, l := range want {
		inWant[l] = true
	}
	for _, l := range lines {
		inGot[l] = true
	}
	for _, l := range lines {
		if !inWant[l] {
			t.Errorf("changed or new: %s", l)
		}
	}
	for _, l := range want {
		if !inGot[l] {
			t.Errorf("gone: %s", l)
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
