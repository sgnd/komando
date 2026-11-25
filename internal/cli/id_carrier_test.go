package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
)

// TestEveryIDHasCarrier reads the facts of the cut plan's section 1 from
// the code: every command ID of today has a safety key and a carrier, the
// thing that keeps its protection after the cut. TestEveryIDHasFate
// (internal/capability) checks that each ID has exactly one fate.
//
// The carrier, by fate:
//   - a leaf carries it: every carrying leaf has a v2.7 row at least as
//     high as today's highest row (as TestLeafNotWeaker);
//   - internal: the leaf it serves is at least as high;
//   - gone: the decision is written (Why);
//   - cobra's own or a group: it runs nothing of its own, so no row of
//     today names its key.
func TestEveryIDHasCarrier(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "command_ids.txt"))
	if err != nil {
		t.Fatal(err)
	}
	ids := strings.Fields(string(b))
	if len(ids) == 0 {
		t.Fatal("testdata/command_ids.txt lists no command ID")
	}
	carried := idCarriers()
	for _, id := range ids {
		key, ok := cmdKeys[id]
		if !ok || key == (safetyKey{}) {
			t.Errorf("%s: no safety key", id)
			continue
		}
		if why := idCarrierGap(id, carried[id]); why != "" {
			t.Errorf("%s (key %v, highest row today %s): %s", id, key, todayTier(key), why)
		}
	}
}

// idFate is how one ID's fate is written: the leaves that carry it, its
// gone or internal entry, or cobra's own or a group.
type idFate struct {
	leaves   []capability.Key
	gone     *capability.Gone
	internal *capability.Internal
	plain    bool // cobra's own or a group
}

// idCarriers maps each of today's IDs to its fate.
func idCarriers() map[string]idFate {
	m := map[string]idFate{}
	for _, l := range capability.All() {
		for _, id := range slices.Concat(l.Today, l.Carries) {
			f := m[id]
			f.leaves = append(f.leaves, l.Key)
			m[id] = f
		}
	}
	for _, g := range capability.Gones() {
		f := m[g.Today]
		f.gone = &g
		m[g.Today] = f
	}
	for _, in := range capability.Internals() {
		f := m[in.Today]
		f.internal = &in
		m[in.Today] = f
	}
	for _, id := range slices.Concat(capability.CobraOwn(), capability.Groups()) {
		f := m[id]
		f.plain = true
		m[id] = f
	}
	return m
}

// idCarrierGap says why id's protection is not carried, or "".
func idCarrierGap(id string, f idFate) string {
	want := todayTier(cmdKeys[id])
	switch {
	case len(f.leaves) > 0:
		for _, k := range f.leaves {
			pair := k.String() + " | " + id
			if _, ok := notWeakerExceptions[pair]; !ok && int(leafTier(k)) < int(want) {
				return "carried by " + k.String() + ", whose highest v2.7 row is " + tier(leafTier(k)).String()
			}
		}
	case f.internal != nil:
		got, found := servedTier(f.internal.For)
		if !found {
			return "internal for " + f.internal.For.String() + ", which no leaf has"
		}
		if int(got) < int(want) {
			return "internal for " + f.internal.For.String() + ", whose highest v2.7 row is " + tier(got).String()
		}
	case f.gone != nil:
		if strings.TrimSpace(f.gone.Why) == "" {
			return "gone with no decision written (Why)"
		}
	case f.plain:
		if want != tierRead {
			return "cobra's own or a group, but a row of today names its key"
		}
	default:
		return "no fate, so nothing carries it"
	}
	return ""
}

// servedTier is the highest v2.7 row of the leaves an internal command
// serves (an empty Provider means every provider).
func servedTier(k capability.Key) (capability.Tier, bool) {
	best, found := capability.Read, false
	for _, l := range capability.All() {
		lk := l.Key
		if k.Provider == "" {
			lk.Provider = ""
		}
		if lk == k {
			found = true
			best = max(best, leafTier(l.Key))
		}
	}
	return best, found
}
