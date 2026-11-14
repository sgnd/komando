package komandosync

import (
	"slices"
	"testing"
)

// Tests for findings 70 and 71 (round 2 of the review of findings 67 to
// 69). Each one fails on the code before its fix.

// merged merges a record change that counts, as Device.applyTo does.
func merged(m *mergeState, ref WriteRef, c *Change, clock HLC) {
	m.arrive(ref, true)
	m.apply(ref, c, clock)
}

// A yes for a removed device's newcomer that is dropped past its floor
// takes nothing away. X, which is removed later, makes S2 "prod-db"
// while S1 "prod-db" is agreed and A's S3 "prod-db" waits. B sees
// "replaces prod-db (deleted)" with S3 set aside, and approves. A, which
// never saw S2, removes X: S2 is dropped on every device (SS 6.2), so
// B's yes neither deletes S1 nor sets S3 aside. Before the fix S1 was
// deleted for good with nothing in its place.
func TestYesForADroppedNewcomerTakesNothing(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	x := w.pair(a, "X", false)
	w.syncAll(a, b, x)
	s1 := createApproved(t, a, TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	w.syncAll(a, b, x)
	s3, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.7"))
	must(t, err)
	_, err = a.Sync()
	must(t, err)
	s2, err := x.Create(TypeServer, field("name", "prod-db"), field("address", "203.0.113.9"))
	must(t, err)
	_, err = b.Sync()
	must(t, err)
	yes := waitingFor(t, b, s2)
	if !slices.Equal(yes.ReplacesIDs, []RecordID{s1}) || len(yes.Withdraws) != 1 {
		t.Fatalf("setup: B's screen should replace S1 and set S3 aside: %v %v", yes.ReplacesIDs, yes.Withdraws)
	}
	must(t, b.Approve(yes.Ref))
	if !gone(b, s1) {
		t.Fatal("setup: B's yes should delete S1 while X is listed")
	}
	must(t, a.Remove(x.ID()))
	for range 3 {
		for _, d := range []*Device{a, b} {
			_, err := d.Sync()
			must(t, err)
		}
	}
	for _, d := range []*Device{a, b} {
		if _, ok := d.Get(s1); !ok || gone(d, s1) {
			t.Errorf("%s: S1 was deleted by a yes whose newcomer was dropped", d.Name)
		}
		if _, ok := d.Get(s2); ok {
			t.Errorf("%s: the dropped newcomer applied", d.Name)
		}
		if !slices.ContainsFunc(d.Waiting(), func(v Waiting) bool { return v.Record == s3 }) {
			t.Errorf("%s: S3 was set aside by a yes whose newcomer was dropped", d.Name)
		}
		if len(d.DroppedWrites()) == 0 {
			t.Errorf("%s: the dropped newcomer is not shown", d.Name)
		}
	}
	sameData(t, a, b)
}

// A yes acts once its change arrives and counts, in either order, and a
// yes still waiting for its change keeps what it lists through a
// snapshot's state. A yes whose change never counts acts never.
func TestYesActsOnlyOnceItsChangeCounts(t *testing.T) {
	var dev, other DeviceID
	dev[0], other[0] = 1, 2
	s1 := recordID(TypeServer, [12]byte(seq(1, 12)))
	s2 := recordID(TypeServer, [12]byte(seq(2, 12)))
	ref := WriteRef{Writer: dev, Seq: 1, Hash: Hash(seq(3, 32))}
	newcomer := &Change{Kind: kindRecord, Record: s2, Type: TypeServer, Create: true,
		Fields: []Field{field("name", "prod-db")}}
	start := func() *mergeState {
		m := newMergeState()
		m.records[s1] = &record{Type: TypeServer, Exists: true, Fields: map[string]fieldVal{"name": {Value: "prod-db"}}}
		m.heads[other] = 1
		return m
	}
	yes := func(m *mergeState) { m.approve(ref, s2, TypeServer, []RecordID{s1}, nil) }
	change := func(m *mergeState, counts bool) {
		if counts {
			merged(m, ref, newcomer, HLC{Wall: 1})
		} else {
			m.arrive(ref, false)
		}
	}
	check := func(name string, m *mergeState, replaced bool) {
		t.Helper()
		_, live1 := m.get(s1)
		_, live2 := m.get(s2)
		if live1 == replaced || live2 != replaced {
			t.Errorf("%s: S1 live %v, S2 live %v; want S2 to replace S1: %v", name, live1, live2, replaced)
		}
	}

	m := start()
	change(m, true)
	yes(m)
	check("change, then yes", m, true)

	m = start()
	yes(m)
	if _, live := m.get(s1); !live {
		t.Fatal("yes first: S1 was deleted before its newcomer arrived")
	}
	b, err := decodeState(m.encode(map[DeviceID]Head{other: {Device: other, Seq: 1}}))
	must(t, err)
	b.heads[other] = 1
	change(b, true)
	check("yes, snapshot, then change", b, true)
	change(m, true)
	check("yes, then change", m, true)

	m = start()
	yes(m)
	change(m, false)
	check("yes, then a change that does not count", m, false)
	m.forgetYesesPast(dev, 0)
	if len(m.pending) > 0 || len(m.approved) > 0 {
		t.Error("a yes whose change never counts is still kept")
	}
}

// A yes deletes only agreed records and deletion markers that hold the
// name. S2's creation still waits, though a yes renamed it to prod-db:
// the yes for S3 "prod-db" sets S2 aside, never deletes it. Before the
// fix S2 was listed as an old holder and deleted.
func TestYesSetsAsideAnUnagreedRecordWithItsName(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	a.AutoApprove, b.AutoApprove = false, false
	w.syncAll(a, b)
	s2, err := a.Create(TypeServer, field("name", "x"), field("address", "10.0.0.6"))
	must(t, err)
	ref, err := a.Update(s2, field("name", "prod-db"))
	must(t, err)
	must(t, a.Approve(ref))
	if _, ok := a.Get(s2); ok {
		t.Fatal("setup: S2's creation should still wait")
	}
	w.syncAll(a, b)
	s3, err := b.Create(TypeServer, field("name", "prod-db"))
	must(t, err)
	yes := waitingFor(t, b, s3)
	if len(yes.ReplacesIDs) != 0 || len(yes.Withdraws) != 1 {
		t.Fatalf("B's screen lists S2 as an old holder (%v), not as set aside (%v)", yes.ReplacesIDs, yes.Withdraws)
	}
	if yes.ReplacesLine() != "replaces prod-db (deleted)" {
		t.Fatalf("screen line %q", yes.ReplacesLine())
	}
	must(t, b.Approve(yes.Ref))
	w.syncAll(a, b)
	for _, d := range []*Device{a, b} {
		if gone(d, s2) {
			t.Errorf("%s: S2, never agreed, was deleted", d.Name)
		}
		if slices.ContainsFunc(d.Waiting(), func(v Waiting) bool { return v.Record == s2 }) {
			t.Errorf("%s: S2 is still asked about", d.Name)
		}
		if _, ok := d.Get(s3); !ok {
			t.Errorf("%s: S3 did not apply", d.Name)
		}
	}
	sameData(t, a, b)
}
