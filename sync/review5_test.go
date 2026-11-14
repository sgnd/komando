package komandosync

import (
	"slices"
	"testing"
	"time"
)

// Tests for the review of the freeze decisions (findings 57 to 61 in
// sync-prototype.md). Each one fails on the code before its fix, or
// under the mutation its comment names.

func waitingFor(t *testing.T, d *Device, rec RecordID) Waiting {
	t.Helper()
	for _, w := range d.Waiting() {
		if w.Record == rec {
			return w
		}
	}
	t.Fatalf("%s: no waiting change for the record", d.Name)
	return Waiting{}
}

// Finding 57: A, B and C agree on S1 "prod-db". A makes S2 "prod-db"; C
// makes S3 "prod-db". A has seen S3 when it approves S2, and B has not:
// A's yes replaces S1 and S3, B's yes only S1. The change replaces the
// union, whatever order the yeses arrive in, so all three devices hold
// the same data, and S3 is no longer asked about.
func TestTwoApprovalsOfOneNewcomerAgree(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	s1, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, b, c)
	s2, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.6"))
	must(t, err)
	for _, d := range []*Device{a, b} {
		_, err := d.Sync()
		must(t, err)
	}
	s3, err := c.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.7"))
	must(t, err)
	for _, d := range []*Device{c, a} {
		_, err := d.Sync()
		must(t, err)
	}
	wa, wb := waitingFor(t, a, s2), waitingFor(t, b, s2)
	if len(wa.ReplacesIDs) != 2 || len(wb.ReplacesIDs) != 1 {
		t.Fatalf("setup: A replaces %d, B replaces %d", len(wa.ReplacesIDs), len(wb.ReplacesIDs))
	}
	must(t, a.Approve(wa.Ref))
	must(t, b.Approve(wb.Ref))
	w.syncAll(a, b, c)
	for _, d := range []*Device{a, b, c} {
		if _, ok := d.Get(s2); !ok {
			t.Fatalf("%s: the approved newcomer is not live", d.Name)
		}
		for _, old := range []RecordID{s1, s3} {
			if r := d.data.records[old]; r == nil || !r.Deleted {
				t.Fatalf("%s: an old holder named by one of the yeses is not deleted", d.Name)
			}
		}
		if slices.ContainsFunc(d.Waiting(), func(x Waiting) bool { return x.Record == s3 }) {
			t.Fatalf("%s: a deleted record is still waiting for a yes", d.Name)
		}
	}
	if string(a.data.encode(nil)) != string(b.data.encode(nil)) || string(a.data.encode(nil)) != string(c.data.encode(nil)) {
		t.Fatal("devices hold different data after the same writes")
	}
}

// Finding 57, merge level: a later yes adds an old holder after the
// change applied. Applied live, or after the state went through a
// snapshot, it deletes that holder; any order gives the same state.
func TestLateApprovalAddsAHolderInAnyOrder(t *testing.T) {
	id := func(b byte) RecordID { return recordID(TypeServer, [12]byte{b}) }
	s1, s2, s3 := id(1), id(2), id(3)
	ref := func(b byte) WriteRef { return WriteRef{Writer: DeviceID{b}, Seq: 1} }
	create := func(s RecordID, addr string) *Change {
		return &Change{Kind: kindRecord, Record: s, Type: TypeServer, Create: true,
			Fields: []Field{field("name", "prod-db"), field("address", addr)}}
	}
	type step func(m *mergeState) *mergeState
	base := func(m *mergeState) *mergeState {
		for i, s := range []RecordID{s1, s3} {
			r := ref(byte(10 + i))
			m.apply(r, create(s, "10.0.0.5"), HLC{Wall: 1})
			m.approve(r, nil)
		}
		return m
	}
	write := func(m *mergeState) *mergeState { m.apply(ref(2), create(s2, "10.0.0.6"), HLC{Wall: 2}); return m }
	yesA := func(m *mergeState) *mergeState { m.approve(ref(2), []RecordID{s1, s3}); return m }
	yesB := func(m *mergeState) *mergeState { m.approve(ref(2), []RecordID{s1}); return m }
	heads := map[DeviceID]Head{}
	for _, b := range []byte{2, 10, 11} {
		heads[DeviceID{b}] = Head{Seq: 1}
	}
	snap := func(m *mergeState) *mergeState {
		out, err := decodeState(m.encode(heads))
		must(t, err)
		return out
	}
	orders := [][]step{
		{write, yesA, yesB},
		{write, yesB, yesA},
		{yesA, write, yesB},
		{yesB, write, yesA},
		{write, yesB, snap, yesA},
		{yesB, write, snap, yesA},
	}
	var want []byte
	for i, o := range orders {
		m := base(newMergeState())
		for _, s := range o {
			m = s(m)
		}
		if r := m.records[s3]; r == nil || !r.Deleted {
			t.Fatalf("order %d: the holder the later yes names is not deleted", i)
		}
		got := m.encode(heads)
		if want == nil {
			want = got
		} else if string(got) != string(want) {
			t.Fatalf("order %d gives other data", i)
		}
	}
}

// Finding 58: X turns protected on and B applies it; no summary covers
// it. A, which never saw it, turns protected off with its own yes and
// removes X. B reads the removal and A's newer yes in one sync. It does
// not write X's value again over the newer yes.
func TestStricterValueNotWrittenOverAYesInTheSameSync(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	x := w.pair(a, "X", true)
	srv, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, b, x)
	_, err = x.Update(srv, field("protected", "true"))
	must(t, err)
	_, err = b.pull()
	must(t, err)
	w.clk.add(time.Second)
	_, err = a.Update(srv, field("protected", "false")) // with A's yes, newer than X's write
	must(t, err)
	must(t, a.Remove(x.ID()))
	rep, err := b.Sync()
	must(t, err)
	if rep.Rewritten != 0 {
		t.Fatalf("B wrote %d values again over a newer yes", rep.Rewritten)
	}
	w.syncAll(a, b)
	for _, d := range []*Device{a, b} {
		if got := value(t, d, srv, "protected"); got != "false" {
			t.Fatalf("%s: protected %q, want the newer yes's false", d.Name, got)
		}
	}
}

// Finding 59: X makes deny rule R; B and C apply it, and no summary
// covers it. C deletes R with its own yes; A, which never saw R, removes
// X. B reads the removal and the deletion in one sync. It does not write
// R again: a person deleted it.
func TestDeletedDenyRuleNotWrittenAgainInTheSameSync(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	x := w.pair(a, "X", true)
	w.syncAll(a, b, c, x)
	r, err := x.Create(TypeDeny, field("pattern", "rm -rf"))
	must(t, err)
	for _, d := range []*Device{b, c} {
		_, err = d.pull()
		must(t, err)
	}
	w.clk.add(time.Second)
	_, err = c.Delete(r) // with C's yes
	must(t, err)
	must(t, a.Remove(x.ID()))
	rep, err := b.Sync()
	must(t, err)
	if rep.Rewritten != 0 {
		t.Fatalf("B wrote a deleted deny rule again (%d)", rep.Rewritten)
	}
	w.syncAll(a, b, c)
	for _, d := range []*Device{a, b, c} {
		if n := denyRules(d, "rm -rf"); n != 0 {
			t.Fatalf("%s: a deny rule deleted with a yes is live again (%d)", d.Name, n)
		}
	}
}

// cutByMac: A removes the iPad X after the Mac mini M signed a summary
// covering X's last write, which A never saw: it turns protected on. A
// keeps that write because M's summary sets X's cut.
func cutByMac(t *testing.T) (w *world, a, m, x *Device, srv RecordID, ref WriteRef) {
	w = newWorld(t)
	a, _ = w.account("A")
	m = w.pair(a, "Mac mini", false)
	x = w.pair(a, "iPad", true)
	srv, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, m, x)
	ref, err = x.Update(srv, field("protected", "true"))
	must(t, err)
	_, err = m.Sync()
	must(t, err)
	must(t, a.Remove(x.ID()))
	w.syncAll(a, m)
	if a.cuts[x.ID()].Seq != ref.Seq || len(a.DroppedWrites()) != 0 {
		t.Fatalf("setup: M's summary should set X's cut (cut %d, write %d)", a.cuts[x.ID()].Seq, ref.Seq)
	}
	return w, a, m, x, srv, ref
}

// Finding 60 (finding 40's rule): once M, whose summary set X's cut, is
// removed too, the cut is found again without it and goes down. A merges
// again, shows X's write as dropped and writes the stricter value again
// as its own. Fails if computeCuts keeps an old cut after its signer is
// removed.
func TestCutGoesDownWhenItsSignerIsRemoved(t *testing.T) {
	_, a, m, x, srv, ref := cutByMac(t)
	must(t, a.Remove(m.ID()))
	rep, err := a.Sync()
	must(t, err)
	if a.cuts[x.ID()].Seq >= ref.Seq {
		t.Fatalf("the cut stayed at %d after its signer was removed", a.cuts[x.ID()].Seq)
	}
	if !slices.Contains(a.DroppedWrites(), ref) {
		t.Fatal("X's write past the lowered cut was not shown as dropped")
	}
	if rep.Rewritten != 1 || value(t, a, srv, "protected") != "true" {
		t.Fatalf("the stricter value was not written again (rewritten %d)", rep.Rewritten)
	}
}

// Finding 60 (finding 40's rule): while M stays listed, a server that
// hides M's summary from before the removal cannot lower X's cut. Fails
// if computeCuts drops an old cut while its signer is listed.
func TestCutStaysWhileItsSignerIsListed(t *testing.T) {
	w, a, m, x, srv, ref := cutByMac(t)
	removal := a.list.RemInfo[x.ID()].At
	w.srv.OnRead = func(by DeviceID, log string, items [][]byte) [][]byte {
		if by != a.ID() || log != logSummaries(m.ID()) {
			return items
		}
		return slices.DeleteFunc(slices.Clone(items), func(it []byte) bool {
			s, err := ParseSummary(it)
			return err == nil && s.ListNum < removal
		})
	}
	rep, err := a.Sync()
	must(t, err)
	if a.cuts[x.ID()].Seq != ref.Seq || rep.Revoked != 0 || len(a.DroppedWrites()) != 0 {
		t.Fatalf("hiding a summary lowered the cut to %d (revoked %d)", a.cuts[x.ID()].Seq, rep.Revoked)
	}
	if value(t, a, srv, "protected") != "true" {
		t.Fatal("X's kept write is gone")
	}
}

// Finding 60 (finding 43's rule): A and M confirm a snapshot that holds
// X's kept write, past the write A's removal records. A new Mac starts
// from it while the server hides M's summary from before the removal.
// Its floor is the snapshot's write, not the removal's, so it keeps what
// the snapshot holds. Fails if floorOf ignores the confirmed snapshot.
func TestFloorNeverGoesBelowAConfirmedSnapshot(t *testing.T) {
	w, a, m, x, srv, ref := cutByMac(t)
	snap, err := a.MakeSnapshot()
	must(t, err)
	if snap.headMap()[x.ID()].Seq != ref.Seq {
		t.Fatal("setup: the snapshot should hold X's kept write")
	}
	w.syncAll(a, m)
	if p := a.SnapshotToPrune(); p == nil || p.Hash() != snap.Hash() {
		t.Fatal("setup: A and M should build on the snapshot")
	}
	if a.list.Removed[x.ID()].LastSeq >= ref.Seq {
		t.Fatal("setup: the removal should record an older write")
	}
	removal := a.list.RemInfo[x.ID()].At
	w.srv.OnRead = func(by DeviceID, log string, items [][]byte) [][]byte {
		if by == a.ID() || by == m.ID() || log != logSummaries(m.ID()) {
			return items
		}
		return slices.DeleteFunc(slices.Clone(items), func(it []byte) bool {
			s, err := ParseSummary(it)
			return err == nil && s.ListNum < removal
		})
	}
	c := w.pair(a, "new Mac", true)
	if c.base == nil {
		t.Fatal("setup: the new Mac should start from the snapshot")
	}
	if got := value(t, c, srv, "protected"); got != "true" || len(c.DroppedWrites()) != 0 {
		t.Fatalf("the new Mac took apart a confirmed snapshot: protected %q, dropped %v", got, c.DroppedWrites())
	}
}
