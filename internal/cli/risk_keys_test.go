package cli

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/policy"
)

// TestSafetyTablesPinned: every command keeps the rule-table rows, the
// kind (read, change, depends) and the TARGET kinds it had, and each row
// with a condition gives the same tier for the words that meet it when the tables were keyed by command ID, so moving
// the key to (type, area, verb) changes nothing a person or an agent sees.
// KOMANDO_GOLDEN_UPDATE=1 writes the file again (only on purpose).
func TestSafetyTablesPinned(t *testing.T) {
	var lines []string
	seen := map[string]bool{}
	for _, c := range allCommands(newRoot(tcl)) {
		id := cmdID(c)
		if strings.HasPrefix(c.Name(), "__") || seen[id] {
			continue
		}
		seen[id] = true
		var rows []string
		for _, r := range rowsFor(c) {
			rows = append(rows, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", r.tier, r.cond, r.what, r.dynamic, r.bulk, r.typed, r.items))
		}
		kind := "none"
		if k, ok := kindOf(c); ok {
			kind = k.Kind + "|" + k.Note
		}
		lines = append(lines, fmt.Sprintf("%s\tkind=%s\ttarget=%q\t%s", id, kind, targetKinds(c), strings.Join(rows, " ; ")))
	}
	lines = append(lines, probeLines(t)...)
	slices.Sort(lines)
	got := strings.Join(lines, "\n") + "\n"
	file := filepath.Join("testdata", "safety_tables_pinned.txt")
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

// TestSafetyKeys: every command has a (type, area, verb) key and no two
// share one, every rule-table row names a command's key, and every shell
// (host, database, cluster) is for a person only (spec section 7.1).
func TestSafetyKeys(t *testing.T) {
	root := newRoot(tcl)
	inTree := map[string]bool{}
	for _, c := range allCommands(root) {
		if strings.HasPrefix(c.Name(), "__") {
			continue // cobra's completion plumbing
		}
		id := cmdID(c)
		inTree[id] = true
		if _, ok := cmdKeys[id]; !ok {
			t.Errorf("command %s has no key in cmdKeys, so no row can give it a tier", id)
		}
	}
	for id := range cmdKeys {
		if !inTree[id] {
			t.Errorf("cmdKeys has %s, which is no command ID", id)
		}
	}
	owner := map[safetyKey]string{}
	for id, k := range cmdKeys {
		if other, ok := owner[k]; ok && !(providerIDs[id] && providerIDs[other]) {
			t.Errorf("%s and %s share the key %v: they would share their rows", id, other, k)
		}
		owner[k] = id
	}
	for i, r := range riskRows {
		if _, ok := owner[r.key]; !ok {
			t.Errorf("riskRows[%d] names the key %v, which no command has", i, r.key)
		}
	}
	for k := range commandKinds {
		if _, ok := owner[k]; !ok {
			t.Errorf("commandKinds names the key %v, which no command has", k)
		}
	}
	gateTables := map[string][]safetyKey{
		"gateReadForm": slices.Collect(maps.Keys(gateReadForm)), "gateNotForReadKey": slices.Collect(maps.Keys(gateNotForReadKey)),
		"gateNeedsPerson": slices.Collect(maps.Keys(gateNeedsPerson)), "gateOnServers": slices.Collect(maps.Keys(gateOnServers)),
		"gateSavesHere": slices.Collect(maps.Keys(gateSavesHere)), "gateTargetArgs": slices.Collect(maps.Keys(gateTargetArgs)),
	}
	for name, keys := range gateTables {
		for _, k := range keys {
			if _, ok := owner[k]; !ok {
				t.Errorf("%s names the key %v, which no command has", name, k)
			}
		}
	}
	// riskID (approval_words_id.go) is keyed by policy rule, not by command:
	// it has no key to move
	rules := map[string]bool{}
	for _, r := range policy.Rules() {
		rules[r.ID] = true
	}
	for name := range riskID {
		if !rules[name] || cmdKeys[name] != (safetyKey{}) {
			t.Errorf("riskID has %q, which is no policy rule or is a command ID", name)
		}
	}
	shells := 0
	for _, c := range allCommands(root) {
		if k := cmdKeys[cmdID(c)]; k.verb == "shell" {
			shells++
			if got := riskOf(c, nil).tier; got != tierPerson {
				t.Errorf("%s (%v) is %s, want person", cmdID(c), k, got)
			}
		}
	}
	if shells < 3 {
		t.Errorf("%d shells, want host, database and cluster", shells)
	}
}

// commandKindIDs are the command IDs commandKinds names, with spaces for
// dots ("" for a key no command has).
func commandKindIDs() []string {
	ids := make([]string, 0, len(commandKinds))
	for k := range commandKinds {
		ids = append(ids, strings.ReplaceAll(keyID(k), ".", " "))
	}
	return ids
}

// fakeKind gives a command ID that is in no table a key and a kind, for
// this test only.
func fakeKind(t *testing.T, id string, kind cmdKind) {
	t.Helper()
	k := safetyKey{"test", "", id}
	cmdKeys[id], commandKinds[k] = k, kind
	t.Cleanup(func() { delete(cmdKeys, id); delete(commandKinds, k) })
}

// whenProbes are command lines that meet the condition of each rule row
// that has one (TestSafetyTablesPinned pins what they give).
var whenProbes = []string{
	"cluster scale c1 web 0",
	"credential key remove k1 --delete-file",
	"pkg rm web1 openssh-server",
	"copy ./site web1:/srv --sync --delete",
	"pkg upgrade web1 --security",
	"host ssh edit web1 --protected=false",
	"conn edit app-db --protected=false",
	"cache redis edit prod-redis --protected=false",
	"registry oci edit ghcr --protected=false",
	"queue kafka edit prod-kafka --protected=false",
	"storage s3 edit prod-s3 --protected=false",
	"database postgres edit prod-db --protected=false",
	"cluster kubernetes edit prod-k8s --protected=false",
	"vpn socks edit kantor --protected=false",
	"vpn socks edit kantor --mfa=false",
	"host ssh add web2 root@10.0.0.6 --proxy-command nc",
	"host ssh edit web1 --proxy-command nc",
	"import kubeconfig",
	"snippet create r1 --overwrite --read-only",
	"config vault keychain",
	"host ssh trust web1 --reset",
	"export --sealed",
	"export --for-phone",
	"credential key install web1 --user anna --public-key-file k.pub",
	"import komando backup.json",
	"group remove big",
	"policy edit rm-root --off",
}

// probeLines are whenProbes with the row riskOf picks for each. A probe
// must parse with the command's own flags, and every row with a condition
// must be met by one probe, so a flag renamed in a condition or in the
// command fails here.
func probeLines(t *testing.T) []string {
	t.Helper()
	met := map[int]bool{}
	var lines []string
	for _, p := range whenProbes {
		line := strings.Fields(p)
		c, rest, err := newRoot(tcl).Find(line)
		if err != nil || c.ParseFlags(rest) != nil {
			t.Errorf("probe %q does not parse as a command: %v", p, err)
			continue
		}
		c, words, _ := lineWords(line)
		for i, r := range riskRows {
			if r.when != nil && r.key == cmdKeys[cmdID(c)] && r.when(words) {
				met[i] = true
			}
		}
		r := riskOf(c, words)
		lines = append(lines, fmt.Sprintf("probe %s\t%s|%s|%s|%s", p, r.tier, r.what, r.dynamic, r.bulk))
	}
	for i, r := range riskRows {
		if r.when != nil && !met[i] {
			t.Errorf("riskRows[%d] (%v, %s) has a condition no probe meets: add one to whenProbes", i, r.key, r.cond)
		}
	}
	return lines
}
