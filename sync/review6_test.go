package komandosync

import (
	"slices"
	"testing"
)

// Tests for the review of the owner's decisions on findings 57 and 61
// (findings 67 to 69 in sync-prototype.md). Each one fails on the code
// before its fix.

// gone reports whether d holds rec as deleted.
func gone(d *Device, rec RecordID) bool {
	r := d.data.records[rec]
	return r != nil && r.Deleted
}

// syncWatching syncs every device rounds times and fails when a record
// that a device held as deleted is not deleted there after a later sync:
// a deletion is final.
func syncWatching(t *testing.T, rounds int, recs []RecordID, devs ...*Device) {
	t.Helper()
	seen := map[string]bool{}
	check := func(d *Device) {
		for i, rec := range recs {
			k := d.Name + string(rune('0'+i))
			if gone(d, rec) {
				seen[k] = true
			} else if seen[k] {
				t.Fatalf("%s: record %d was deleted and is back", d.Name, i)
			}
		}
	}
	for _, d := range devs {
		check(d)
	}
	for range rounds {
		for _, d := range devs {
			_, err := d.Sync()
			must(t, err)
			check(d)
		}
	}
}

// lateYesWorld is the scenario of finding 67. S1 "prod-db" is agreed. A
// makes S2 "prod-db" and B reads it. C, which has not read S2, makes S3
// "prod-db" and approves it, replacing S1. When seeLive, A reads C's yes
// before it says yes to S2 (it sees S3 live); otherwise A reads S3 while
// it still waits. B, which has not read S3, approves S2 naming S1 only,
// and makes a snapshot. A then approves S2, after the snapshot's heads.
func lateYesWorld(t *testing.T, seeLive bool) (w *world, a, b, c *Device, s1, s2, s3 RecordID, snap *Snapshot) {
	w = newWorld(t)
	a, _ = w.account("A")
	b = w.pair(a, "B", true)
	c = w.pair(a, "C", true)
	w.syncAll(a, b, c)
	s1 = createApproved(t, a, TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	w.syncAll(a, b, c)
	var err error
	s2, err = a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.6"))
	must(t, err)
	for _, d := range []*Device{a, b} {
		_, err := d.Sync()
		must(t, err)
	}
	s3, err = c.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.7"))
	must(t, err)
	if !seeLive {
		_, err = c.Sync()
		must(t, err)
		_, err = a.Sync()
		must(t, err)
	}
	must(t, c.Approve(waitingFor(t, c, s3).Ref))
	_, err = c.Sync()
	must(t, err)
	if seeLive {
		_, err = a.Sync()
		must(t, err)
		if _, ok := a.Get(s3); !ok {
			t.Fatal("setup: A should see S3 live")
		}
	}
	yesB := waitingFor(t, b, s2)
	if !slices.Equal(yesB.ReplacesIDs, []RecordID{s1}) {
		t.Fatal("setup: B should name S1 only")
	}
	must(t, b.Approve(yesB.Ref))
	_, err = b.Sync()
	must(t, err)
	snap, err = b.MakeSnapshot()
	must(t, err)
	must(t, a.Approve(waitingFor(t, a, s2).Ref))
	if snap.headMap()[a.ID()].Seq >= a.ownSeq {
		t.Fatal("setup: A's yes should come after the snapshot's heads")
	}
	return w, a, b, c, s1, s2, s3, snap
}

// Finding 67: A saw S3 live and approved S2 with "replaces prod-db
// (deleted)" for S1 and S3. Its yes came after a snapshot every device
// then builds on. Devices that read the yes before building on the
// snapshot, after it, and a new device that starts from it all delete S3,
// and none brings it back.
func TestLateYesAfterASnapshotDeletesTheSame(t *testing.T) {
	w, a, b, c, s1, s2, s3, snap := lateYesWorld(t, true)
	syncWatching(t, 4, []RecordID{s1, s3}, a, b, c)
	for _, d := range []*Device{a, b, c} {
		if p := d.SnapshotToPrune(); p == nil || p.Hash() != snap.Hash() {
			t.Fatalf("setup: %s should build on the snapshot", d.Name)
		}
		if !gone(d, s3) || !gone(d, s1) {
			t.Fatalf("%s: a holder A's yes named is live", d.Name)
		}
		if _, ok := d.Get(s2); !ok {
			t.Fatalf("%s: the approved newcomer is not live", d.Name)
		}
	}
	nd := w.pair(a, "new Mac", true)
	if nd.baseHash != snap.Hash() {
		t.Fatal("setup: the new device should start from the snapshot")
	}
	syncWatching(t, 2, []RecordID{s1, s3}, a, b, c, nd)
	if !gone(nd, s3) {
		t.Fatal("the new device brought back a record a yes deleted")
	}
	sameData(t, a, b, c, nd)
}

// Finding 67, with a newcomer that still waited when A said yes: A read
// S3 waiting, so its yes sets S3 aside, while C's own yes made S3 live.
// Nothing is deleted that C agreed to, and nothing comes back: S2 and S3
// both stay, shown as "waiting: name taken" on every device, before and
// after the snapshot, and on a new device that starts from it.
func TestLateYesForAWaitingNewcomerAfterASnapshot(t *testing.T) {
	w, a, b, c, s1, s2, s3, snap := lateYesWorld(t, false)
	syncWatching(t, 4, []RecordID{s1, s2, s3}, a, b, c)
	nd := w.pair(a, "new Mac", true)
	if nd.baseHash != snap.Hash() {
		t.Fatal("setup: the new device should start from the snapshot")
	}
	syncWatching(t, 2, []RecordID{s1, s2, s3}, a, b, c, nd)
	want := slices.SortedFunc(slices.Values([]RecordID{s2, s3}), cmpRecord)
	for _, d := range []*Device{a, b, c, nd} {
		cl := d.NameClashes()
		if len(cl) != 1 || !slices.Equal(cl[0].Records, want) {
			t.Fatalf("%s: clashes %+v, want S2 and S3 under prod-db", d.Name, cl)
		}
	}
	sameData(t, a, b, c, nd)
}

// Finding 69: S1 "prod-db" is deleted. A and B each make a server named
// prod-db, read each other's while both wait, and approve their own. Each
// screen shows "replaces prod-db (deleted)" and lists the other one, but
// neither yes deletes a record another yes agreed to: both servers stay,
// shown as "waiting: name taken", the same on every device.
func TestTwoWaitingNewcomersApprovedAtOnceBothStay(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	s1 := createApproved(t, a, TypeServer, field("name", "prod-db"))
	w.syncAll(a, b, c)
	_, err := a.Delete(s1)
	must(t, err)
	w.syncAll(a, b, c)
	if !gone(a, s1) {
		t.Fatal("setup: S1 should be deleted")
	}
	na, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.6"))
	must(t, err)
	nb, err := b.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.7"))
	must(t, err)
	w.syncAll(a, b)
	wa, wb := waitingFor(t, a, na), waitingFor(t, b, nb)
	if wa.ReplacesLine() != "replaces prod-db (deleted)" || wb.ReplacesLine() != "replaces prod-db (deleted)" {
		t.Fatal("setup: each newcomer should wait with the replaces line")
	}
	must(t, a.Approve(wa.Ref))
	must(t, b.Approve(wb.Ref))
	syncWatching(t, 3, []RecordID{na, nb}, a, b, c)
	want := slices.SortedFunc(slices.Values([]RecordID{na, nb}), cmpRecord)
	for _, d := range []*Device{a, b, c} {
		for _, id := range want {
			if _, ok := d.Get(id); !ok {
				t.Fatalf("%s: an approved newcomer disappeared", d.Name)
			}
		}
		cl := d.NameClashes()
		if len(cl) != 1 || !slices.Equal(cl[0].Records, want) || cl[0].Line() != "waiting: name taken: prod-db (2 server records)" {
			t.Fatalf("%s: clashes %+v, want both newcomers", d.Name, cl)
		}
	}
	sameData(t, a, b, c)
}

// Finding 67 removed Snapshot.Base, which kept a device from going back
// to the snapshot it builds on. Two snapshots of the same writes hold the
// same state; every device settles on the one with the smaller hash, so
// all of them build on one snapshot and none goes back and forth.
func TestTwoSnapshotsOfTheSameWritesSettleOnOne(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	createApproved(t, a, TypeServer, field("name", "prod-db"))
	w.syncAll(a, b, c)
	snap1, err := a.MakeSnapshot()
	must(t, err)
	for _, d := range []*Device{a, b, c} {
		_, err := d.Sync()
		must(t, err)
	}
	snap2, err := c.MakeSnapshot()
	must(t, err)
	if !covers(snap1, snap2) || !covers(snap2, snap1) {
		t.Fatal("setup: both snapshots should hold the same writes")
	}
	want := snap1
	if after(snap2, snap1) {
		want = snap2
	}
	w.syncAll(a, b, c)
	w.syncAll(a, b, c)
	for _, d := range []*Device{a, b, c} {
		if d.baseHash != want.Hash() || d.snap == nil || d.snap.Hash() != want.Hash() {
			t.Fatalf("%s does not build on the snapshot with the smaller hash", d.Name)
		}
	}
	sameData(t, a, b, c)
}

// Finding 67: a yes now names its change's record, and its type sets
// which holders it deletes and which waiting changes it sets aside. A yes
// that names another record does not approve the change, and a yes for a
// secret neither deletes a server nor sets aside a server's waiting
// change, in any order.
func TestAYesActsOnlyForTheRecordItNames(t *testing.T) {
	srv := func(b byte) RecordID { return recordID(TypeServer, [12]byte{b}) }
	sec := recordID(TypeSecret, [12]byte{9})
	s1, s2, s3 := srv(1), srv(2), srv(3)
	ref := func(b byte) WriteRef { return WriteRef{Writer: DeviceID{b}, Seq: 1} }
	create := func(s RecordID, typ string) *Change {
		return &Change{Kind: kindRecord, Record: s, Type: typ, Create: true, Fields: []Field{field("name", "prod-db")}}
	}
	for _, yesFirst := range []bool{false, true} {
		m := newMergeState()
		merged(m, ref(1), create(s1, TypeServer), HLC{Wall: 1})
		m.approve(ref(1), s1, TypeServer, nil, nil)
		yeses := func() {
			m.approve(ref(2), s3, TypeServer, nil, nil)                            // names another record
			m.approve(ref(4), sec, TypeSecret, []RecordID{s1}, []WriteRef{ref(3)}) // a secret's yes
		}
		if yesFirst {
			yeses()
		}
		merged(m, ref(2), create(s2, TypeServer), HLC{Wall: 2})
		merged(m, ref(3), create(s3, TypeServer), HLC{Wall: 3})
		merged(m, ref(4), create(sec, TypeSecret), HLC{Wall: 4})
		if !yesFirst {
			yeses()
		}
		if _, ok := m.get(s2); ok {
			t.Fatalf("yes first %v: a yes for another record approved the change", yesFirst)
		}
		if _, ok := m.get(s1); !ok {
			t.Fatalf("yes first %v: a secret's yes deleted a server", yesFirst)
		}
		if !slices.ContainsFunc(m.list(), func(w Waiting) bool { return w.Record == s3 }) {
			t.Fatalf("yes first %v: a secret's yes set aside a server's waiting change", yesFirst)
		}
		if _, ok := m.get(sec); !ok {
			t.Fatalf("yes first %v: the secret's own yes did not apply", yesFirst)
		}
	}
}
