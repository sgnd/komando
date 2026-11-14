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
// makes S3 "prod-db". A has seen S3 waiting when it approves S2, and B
// has not: A's yes replaces S1 and sets S3 aside, B's yes replaces S1.
// Whatever order the yeses arrive in, all three devices hold the same
// data, and S3 is no longer asked about (finding 69: set aside, not
// deleted, since no one agreed to it).
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
	if !slices.Equal(wa.ReplacesIDs, []RecordID{s1}) || len(wa.Withdraws) != 1 || !slices.Equal(wb.ReplacesIDs, []RecordID{s1}) || len(wb.Withdraws) != 0 {
		t.Fatalf("setup: A replaces %d and sets aside %d, B replaces %d", len(wa.ReplacesIDs), len(wa.Withdraws), len(wb.ReplacesIDs))
	}
	must(t, a.Approve(wa.Ref))
	must(t, b.Approve(wb.Ref))
	w.syncAll(a, b, c)
	for _, d := range []*Device{a, b, c} {
		if _, ok := d.Get(s2); !ok {
			t.Fatalf("%s: the approved newcomer is not live", d.Name)
		}
		if !gone(d, s1) {
			t.Fatalf("%s: the old holder the yeses named is not deleted", d.Name)
		}
		if _, ok := d.Get(s3); ok || slices.ContainsFunc(d.Waiting(), func(x Waiting) bool { return x.Record == s3 }) {
			t.Fatalf("%s: the newcomer A's yes set aside is live or still asked about", d.Name)
		}
	}
	if string(a.data.encode(nil)) != string(b.data.encode(nil)) || string(a.data.encode(nil)) != string(c.data.encode(nil)) {
		t.Fatal("devices hold different data after the same writes")
	}
}

// Finding 57, merge level: a later yes adds an old holder after the
// change applied. Applied live, or after the state went through a
// snapshot, it deletes that holder; any order gives the same state. A
// yes acts from what it names alone (finding 67), so a yes that arrives
// before its change, after it or after a snapshot gives the same result.
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
			m.approve(r, s, TypeServer, nil, nil)
		}
		return m
	}
	write := func(m *mergeState) *mergeState { m.apply(ref(2), create(s2, "10.0.0.6"), HLC{Wall: 2}); return m }
	yesA := func(m *mergeState) *mergeState { m.approve(ref(2), s2, TypeServer, []RecordID{s1, s3}, nil); return m }
	yesB := func(m *mergeState) *mergeState { m.approve(ref(2), s2, TypeServer, []RecordID{s1}, nil); return m }
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
		{write, snap, yesA, yesB},
		{yesA, snap, write, yesB},
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

// createApproved makes a record with the person's yes, collected while
// editing (AutoApprove) or on the waiting screen.
func createApproved(t *testing.T, d *Device, typ string, fields ...Field) RecordID {
	t.Helper()
	id, err := d.Create(typ, fields...)
	must(t, err)
	if _, ok := d.Get(id); !ok {
		must(t, d.Approve(waitingFor(t, d, id).Ref))
	}
	return id
}

func sameData(t *testing.T, devs ...*Device) {
	t.Helper()
	for _, d := range devs[1:] {
		if string(d.data.encode(nil)) != string(devs[0].data.encode(nil)) {
			t.Fatalf("%s and %s hold different data after the same writes", devs[0].Name, d.Name)
		}
	}
}

// Finding 61, decided by the owner 2026-11-14: A and B are offline and
// each make a server named prod-db with a yes that replaces nothing. After
// syncing, both servers are marked "name taken" on every device, neither
// is picked by name and neither disappears. The person keeps A's on B;
// that yes deletes B's server everywhere and the name works again.
func TestTwoNewcomersWithOneNameWaitForAPick(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	sa := createApproved(t, a, TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	sb := createApproved(t, b, TypeServer, field("name", "prod-db"), field("address", "10.0.0.6"))
	w.syncAll(c, b, a) // C reads both in one sync, A and B each saw their own first

	want := slices.SortedFunc(slices.Values([]RecordID{sa, sb}), cmpRecord)
	for _, d := range []*Device{a, b, c} {
		cl := d.NameClashes()
		if len(cl) != 1 || cl[0].Type != TypeServer || cl[0].Name != "prod-db" || !slices.Equal(cl[0].Records, want) {
			t.Fatalf("%s: clashes %+v, want both servers under prod-db", d.Name, cl)
		}
		if got := cl[0].Line(); got != "waiting: name taken: prod-db (2 server records)" {
			t.Fatalf("%s: line %q", d.Name, got)
		}
		_, err := d.Find(TypeServer, "prod-db")
		wantErr(t, err, ErrNameTaken)
		for _, id := range want {
			if _, ok := d.Get(id); !ok {
				t.Fatalf("%s: a server in the clash disappeared", d.Name)
			}
		}
	}
	sameData(t, a, b, c)

	ref, err := b.KeepName(sa)
	must(t, err)
	wt := waitingFor(t, b, sa)
	if wt.Ref != ref || !slices.Equal(wt.ReplacesIDs, []RecordID{sb}) || wt.ReplacesLine() != "replaces prod-db (deleted)" {
		t.Fatalf("the pick does not wait with the replaces line: %+v", wt)
	}
	if len(b.NameClashes()) != 1 {
		t.Fatal("the clash ended before the person's yes")
	}
	must(t, b.Approve(ref))
	w.syncAll(a, b, c)
	for _, d := range []*Device{a, b, c} {
		if got, err := d.Find(TypeServer, "prod-db"); err != nil || got != sa {
			t.Fatalf("%s: prod-db finds %x, %v; want A's server", d.Name, got[:4], err)
		}
		if r := d.data.records[sb]; r == nil || !r.Deleted {
			t.Fatalf("%s: the server the person did not keep is not deleted", d.Name)
		}
		if len(d.NameClashes()) != 0 || len(d.Waiting()) != 0 {
			t.Fatalf("%s: still clashes %v or waits %v", d.Name, d.NameClashes(), d.Waiting())
		}
	}
	sameData(t, a, b, c)
}

// Finding 61: the person keeps both by renaming one; that rename waits
// like any rename, and once agreed each name finds its own server. A
// record outside a clash cannot be "kept", and records of another type
// or deleted ones never clash.
func TestNameTakenEndsWithARename(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	w.syncAll(a, b)
	sa := createApproved(t, a, TypeServer, field("name", "prod-db"))
	sb := createApproved(t, b, TypeServer, field("name", "prod-db"))
	_, err := a.Create(TypeNote, field("name", "prod-db"))
	must(t, err)
	_, err = b.Create(TypeNote, field("name", "prod-db"))
	must(t, err)
	w.syncAll(a, b)
	if cl := a.NameClashes(); len(cl) != 1 || cl[0].Type != TypeServer {
		t.Fatalf("clashes %+v, want the servers only (notes hold no name)", cl)
	}
	a.AutoApprove = false
	ref, err := a.Update(sb, field("name", "prod-db-2"))
	must(t, err)
	if len(a.NameClashes()) != 1 {
		t.Fatal("a waiting rename ended the clash")
	}
	must(t, a.Approve(ref))
	w.syncAll(a, b)
	for _, d := range []*Device{a, b} {
		if got, err := d.Find(TypeServer, "prod-db"); err != nil || got != sa {
			t.Fatalf("%s: prod-db: %v", d.Name, err)
		}
		if got, err := d.Find(TypeServer, "prod-db-2"); err != nil || got != sb {
			t.Fatalf("%s: prod-db-2: %v", d.Name, err)
		}
		if len(d.NameClashes()) != 0 {
			t.Fatalf("%s: still clashes", d.Name)
		}
	}
	_, err = a.KeepName(sa)
	wantErr(t, err, ErrBadWrite)
	_, err = a.Find(TypeServer, "web")
	wantErr(t, err, ErrNoRecord)
	sameData(t, a, b)
}

// A device one snapshot behind takes an honest newer one. A does not see
// that C named the first snapshot yet, so it does not build on it, while
// C already made a second one on it. A merges the second snapshot's
// writes from its own base and takes it instead of refusing it.
func TestDeviceOneSnapshotBehindTakesANewerOne(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	s1 := createApproved(t, a, TypeServer, field("name", "prod-db"))
	w.syncAll(a, b, c)
	s2, err := b.Create(TypeServer, field("name", "prod-db"))
	must(t, err)
	must(t, b.Approve(waitingFor(t, b, s2).Ref))
	w.syncAll(a, b, c)
	if _, ok := a.Get(s1); ok {
		t.Fatal("setup: the old holder should be deleted")
	}

	snap1, err := a.MakeSnapshot()
	must(t, err)
	shown := len(mustRead(t, w, logSummaries(c.ID())))
	for _, d := range []*Device{a, b, c} {
		_, err := d.Sync()
		must(t, err)
	}
	if c.baseHash != snap1.Hash() || a.baseHash == snap1.Hash() {
		t.Fatal("setup: C should build on the first snapshot, A not yet")
	}
	_, err = c.Create(TypeNote, field("text", "after the first snapshot"))
	must(t, err)
	snap2, err := c.MakeSnapshot()
	must(t, err)
	w.srv.OnRead = func(by DeviceID, log string, items [][]byte) [][]byte {
		if by == a.ID() && log == logSummaries(c.ID()) {
			return items[:shown]
		}
		return items
	}
	rep, err := a.Sync()
	must(t, err)
	if rep.Refused != 0 || a.snap == nil || a.snap.Hash() != snap2.Hash() || a.baseHash == snap1.Hash() {
		t.Fatal("A did not take an honest snapshot built on a base it does not build on yet")
	}
	w.srv.OnRead = nil
	w.syncAll(a, b, c)
	for _, d := range []*Device{a, b, c} {
		if p := d.SnapshotToPrune(); p == nil || p.Hash() != snap2.Hash() {
			t.Fatalf("%s did not take the second snapshot", d.Name)
		}
	}
	sameData(t, a, b, c)
}
