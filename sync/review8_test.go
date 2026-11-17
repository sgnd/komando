package komandosync

import (
	"fmt"
	"slices"
	"testing"
)

// Tests for finding 73 (round 3 of the review of findings 67 to 69).
// Each one fails on the code before its fix.

// deviceView is what a person sees of a few records on a device: live,
// deleted for good, or neither, and the records whose change waits.
func deviceView(d *Device, ids ...RecordID) string {
	out := ""
	for _, id := range ids {
		_, live := d.Get(id)
		out += fmt.Sprintf("%x live=%v gone=%v; ", id[:4], live, gone(d, id))
	}
	var waits []string
	for _, w := range d.Waiting() {
		waits = append(waits, fmt.Sprintf("%x", w.Record[:4]))
	}
	slices.Sort(waits)
	return out + fmt.Sprintf("waiting %v", waits)
}

// Building on a confirmed snapshot never changes what a device holds,
// and a yes for a removed device's newcomer dropped past its floor takes
// nothing away, also once a snapshot holds that newcomer and raises the
// floor past it. X writes S2 "prod-db" (X:2) while S1 "prod-db" is agreed;
// B reads it. A, which never saw S2, removes X with floor X:1, then reads
// X:2 by B's summary and drops its waiting change. A's snapshot holds
// X:2. B, which has not read the removal, approves S2. Before the fix A
// ignored the yes until it built on the snapshot; then the yes deleted S1
// on A and B for good with nothing in its place.
func TestRebaseKeepsAYesForADroppedNewcomerIdle(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	x := w.pair(a, "X", false)
	w.syncAll(a, b, x)
	s1 := createApproved(t, a, TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	w.syncAll(a, b, x)
	s2, err := x.Create(TypeServer, field("name", "prod-db"), field("address", "203.0.113.9"))
	must(t, err)
	_, err = b.Sync()
	must(t, err)
	yes := waitingFor(t, b, s2)
	if !slices.Equal(yes.ReplacesIDs, []RecordID{s1}) {
		t.Fatalf("setup: B's screen should replace S1: %v", yes.ReplacesIDs)
	}
	must(t, a.Remove(x.ID()))
	_, err = a.Sync()
	must(t, err)
	if a.applied[x.ID()].Seq != 2 || a.list.Removed[x.ID()].LastSeq != 1 {
		t.Fatalf("setup: A should hold X:2 past the floor X:1, holds X:%d", a.applied[x.ID()].Seq)
	}
	snap, err := a.MakeSnapshot()
	must(t, err)
	must(t, b.Approve(yes.Ref))

	rebased := map[*Device]bool{}
	for range 4 {
		for _, d := range []*Device{a, b} {
			_, knew := d.list.Removed[x.ID()]
			before, base := deviceView(d, s1, s2), d.baseHash
			_, err := d.Sync()
			must(t, err)
			if d.baseHash != base && knew {
				rebased[d] = true
				if after := deviceView(d, s1, s2); after != before {
					t.Errorf("%s: building on the snapshot changed what it holds:\nbefore %s\nafter  %s", d.Name, before, after)
				}
			}
		}
	}
	if !rebased[a] || a.baseHash != snap.Hash() || a.floorOf(x.ID()).Seq != 2 {
		t.Fatalf("setup: A should build on its snapshot, which raises X's floor to 2 (floor %d)", a.floorOf(x.ID()).Seq)
	}
	for _, d := range []*Device{a, b} {
		if _, ok := d.Get(s1); !ok || gone(d, s1) {
			t.Errorf("%s: S1 was deleted by a yes whose newcomer was dropped", d.Name)
		}
		if _, ok := d.Get(s2); ok {
			t.Errorf("%s: the dropped newcomer applied", d.Name)
		}
	}
	sameData(t, a, b)
}

// A snapshot's state keeps which writes did not count, so a yes that
// arrives after the snapshot for such a write acts never, though the
// write is among the snapshot's writes.
func TestSnapshotKeepsWhichWritesDidNotCount(t *testing.T) {
	var dev DeviceID
	dev[0] = 1
	s1 := recordID(TypeServer, [12]byte(seq(1, 12)))
	s2 := recordID(TypeServer, [12]byte(seq(2, 12)))
	ref := WriteRef{Writer: dev, Seq: 1, Hash: Hash(seq(3, 32))}
	m := newMergeState()
	m.records[s1] = &record{Type: TypeServer, Exists: true, Fields: map[string]fieldVal{"name": {Value: "prod-db"}}}
	m.arrive(ref, false)
	heads := map[DeviceID]Head{dev: {Device: dev, Seq: 1, Hash: ref.Hash}}
	b, err := decodeState(m.encode(heads))
	must(t, err)
	b.heads[dev] = 1 // as Device.baseData does
	for name, s := range map[string]*mergeState{"merged": m, "from the snapshot": b} {
		s.approve(ref, s2, TypeServer, []RecordID{s1}, nil)
		if _, live := s.get(s1); !live {
			t.Errorf("%s: a yes for a write that did not count deleted S1", name)
		}
		if len(s.approved) > 0 || len(s.pending) > 0 {
			t.Errorf("%s: a yes for a write that did not count is kept", name)
		}
	}
}
