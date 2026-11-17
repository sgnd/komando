package komandosync

import (
	"maps"
	"slices"
	"testing"
	"time"
)

// Tests for the review of the freeze re-test (findings 45 to 53 in
// sync-prototype.md). Each one fails on the code before its fix.

// signedSummary signs a summary with dev's sync key: number num, after
// prev, naming list entry listNum, covering every write of extra as dev
// never saw it.
func signedSummary(t *testing.T, dev, extra *Device, num uint64, prev Hash, listNum uint32, listHash Hash) *Summary {
	t.Helper()
	s := &Summary{Account: dev.account, Signer: dev.id, Num: num, Prev: prev, KeyGen: 1,
		ListNum: listNum, ListHash: listHash, MinClient: minClient}
	for id, h := range dev.applied {
		if id != extra.id {
			s.Heads = append(s.Heads, h)
		}
	}
	s.Heads = append(s.Heads, extra.applied[extra.id])
	slices.SortFunc(s.Heads, func(p, q Head) int { return cmpDevice(p.Device, q.Device) })
	var err error
	s.Sig, err = sign(dev.keys.Sync, labelSummary, s.signedBytes())
	must(t, err)
	return s
}

// uncappedSnapshot is a snapshot of everything d holds, signed by a
// client that ignores the removal caps.
func uncappedSnapshot(t *testing.T, d *Device) *Snapshot {
	t.Helper()
	gen := d.list.GenAt[d.head-1]
	s := &Snapshot{Account: d.account, Signer: d.id, Num: d.snapNum + 1,
		ListNum: d.head, ListHash: d.headHash, KeyGen: gen}
	for _, id := range slices.SortedFunc(maps.Keys(d.applied), cmpDevice) {
		s.Heads = append(s.Heads, d.applied[id])
	}
	plain := d.data.encode(s.headMap())
	s.State = sum(labelSnapState, plain)
	body, err := sealRecord(d.vaultKeys[gen], s.header(), plain)
	must(t, err)
	s.Body = body
	s.Sig, err = sign(d.keys.Sync, labelSnapshot, s.signedBytes())
	must(t, err)
	must(t, d.srv.Append(d.id, logSnapshots(d.id), s.Marshal()))
	d.snapNum = s.Num
	return s
}

// pendingRemoval: A, the iPhone B and the stolen iPad X share prod-db. B
// asks for X's removal, which waits 7 days. During the wait X moves
// prod-db and approves it itself.
func pendingRemoval(t *testing.T) (w *world, a, b, x *Device, srv RecordID, num uint32) {
	w = newWorld(t)
	a, _ = w.account("A")
	b = w.pair(a, "iPhone", true)
	x = w.pair(a, "stolen iPad", true)
	srv, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, b, x)
	num, err = b.RemoveLater(x.ID())
	must(t, err)
	w.syncAll(a, b, x)
	_, err = x.Update(srv, field("address", "203.0.113.9")) // with X's own yes
	must(t, err)
	return w, a, b, x, srv, num
}

// Finding 45: a snapshot made while X's removal waits stops at the write
// the removal records. Every device confirms it and builds on it, and
// once the removal applies X's change and yes are still dropped and
// shown, as with no snapshot (finding 35).
func TestSnapshotStopsAtAWaitingRemoval(t *testing.T) {
	w, a, b, x, srv, num := pendingRemoval(t)
	w.syncAll(a, b, x)
	snap, err := a.MakeSnapshot()
	must(t, err)
	if h := snap.headMap()[x.ID()]; h.Seq > a.list.Pending[num].Inner.Removes[0].LastSeq {
		t.Fatalf("the snapshot holds X's write %d, past the waiting removal", h.Seq)
	}
	w.syncAll(a, b, x)
	if p := a.SnapshotToPrune(); p == nil || p.Hash() != snap.Hash() {
		t.Fatal("setup: every device should build on the snapshot")
	}
	w.clk.add(WaitYoung)
	must(t, b.ApplyPending(num))
	w.syncAll(a, b)
	for _, d := range []*Device{a, b} {
		if got := value(t, d, srv, "address"); got != "10.0.0.5" {
			t.Fatalf("%s: an approval made during a waiting removal was kept: address %q", d.Name, got)
		}
		if got := d.DroppedWrites(); len(got) != 2 {
			t.Fatalf("%s: the dropped change and yes were not shown: %v", d.Name, got)
		}
	}

	// A snapshot past the cap, from a client that ignores it, is never
	// taken.
	w2, a2, b2, x2, _, _ := pendingRemoval(t)
	w2.syncAll(a2, b2, x2)
	bad := uncappedSnapshot(t, a2)
	w2.syncAll(a2, b2, x2)
	for _, d := range []*Device{a2, b2, x2} {
		if d.snap != nil && d.snap.Hash() == bad.Hash() {
			t.Fatalf("%s took a snapshot past a waiting removal", d.Name)
		}
	}
}

// Finding 46: clients that ignore the caps named a snapshot holding X's
// yes from during the wait; after the removal A and B take it back. The
// server shows a new Mac only their summaries from before the removal.
// The Mac does not start from that snapshot: it reads every write and
// ends with what A and B hold.
func TestNewDeviceSkipsASnapshotFromBeforeARemoval(t *testing.T) {
	w, a, b, _, srv, num := pendingRemoval(t)
	w.syncAll(a, b)
	s := uncappedSnapshot(t, a)
	shown := map[string]int{}
	for _, d := range []*Device{a, b} {
		d.snap = s
		must(t, d.publishSummary())
		shown[logSummaries(d.ID())] = len(mustRead(t, w, logSummaries(d.ID())))
	}
	w.clk.add(WaitYoung)
	must(t, b.ApplyPending(num))
	w.syncAll(a, b)
	if value(t, a, srv, "address") != "10.0.0.5" {
		t.Fatal("setup: A should drop X's change once the removal applies")
	}

	w.srv.OnRead = func(by DeviceID, log string, items [][]byte) [][]byte {
		if n, ok := shown[log]; ok && by != a.ID() && by != b.ID() {
			return items[:n]
		}
		return items
	}
	c := w.pair(a, "new Mac", true)
	if got := value(t, c, srv, "address"); got != "10.0.0.5" {
		t.Fatalf("the new device started from a snapshot from before a removal: address %q", got)
	}
	w.srv.OnRead = nil
	w.syncAll(a, b, c)
	if string(c.data.encode(nil)) != string(a.data.encode(nil)) {
		t.Fatalf("the new device holds other data: address %q", value(t, c, srv, "address"))
	}

	// Clients that ignore the caps name it again after the removal. Their
	// summaries are new enough, but the snapshot holds X's writes past
	// its floor: the new device still reads every write.
	w, a, b, _, srv, num = pendingRemoval(t)
	w.syncAll(a, b)
	s = uncappedSnapshot(t, a)
	w.clk.add(WaitYoung)
	must(t, b.ApplyPending(num))
	w.syncAll(a, b)
	for _, d := range []*Device{a, b} {
		d.snap = s
		must(t, d.publishSummary())
	}
	c = w.pair(a, "new Mac", true)
	if got := value(t, c, srv, "address"); got != "10.0.0.5" || c.base != nil {
		t.Fatalf("the new device started from a snapshot past a removed device's floor: address %q", got)
	}
}

// removedWithLateNote: A removes X while the Mac mini M stays. X then
// writes a note. old is M's honest summary from before the removal.
func removedWithLateNote(t *testing.T, syncsAfter int) (w *world, a, m, x *Device, note RecordID, old *Summary) {
	w = newWorld(t)
	a, _ = w.account("A")
	m = w.pair(a, "Mac mini", false)
	x = w.pair(a, "iPad", true)
	w.syncAll(a, m, x)
	old = m.summaries[m.id]
	must(t, a.Remove(x.ID()))
	for range syncsAfter {
		_, err := m.Sync()
		must(t, err)
	}
	_, err := a.Sync()
	must(t, err)
	note, err = x.Create(TypeNote, field("text", "late"))
	must(t, err)
	return w, a, m, x, note, old
}

func hideSummaries(w *world, to, signer *Device, hide ...Hash) {
	w.srv.OnRead = func(by DeviceID, log string, items [][]byte) [][]byte {
		if by != to.ID() || log != logSummaries(signer.ID()) {
			return items
		}
		return slices.DeleteFunc(slices.Clone(items), func(it []byte) bool {
			s, err := ParseSummary(it)
			return err == nil && slices.Contains(hide, s.Hash())
		})
	}
}

// Finding 47: A holds M's summary that names the removal. The thief signs
// the next one with M's sync key, naming the entry before the removal,
// and the server hides the one A holds. A still refuses it.
func TestBackdatedSummaryRefusedWhenTheNewerIsHidden(t *testing.T) {
	w, a, m, x, note, _ := removedWithLateNote(t, 1)
	held := a.summaries[m.id]
	if held == nil || held.ListNum < a.list.RemInfo[x.id].At {
		t.Fatal("setup: A should hold M's summary naming the removal")
	}
	forged := signedSummary(t, m, x, held.Num+1, held.Hash(), held.ListNum-1, a.list.Hashes[held.ListNum-2])
	must(t, w.srv.Append(m.id, logSummaries(m.id), forged.Marshal()))
	hideSummaries(w, a, m, held.Hash())
	_, err := a.Sync()
	wantErr(t, err, ErrRollback)
	if _, ok := a.Get(note); ok {
		t.Fatal("a backdated summary kept a removed device's late note")
	}
}

// Finding 48: the thief signs a summary with the number of one of M's
// honest summaries from before the removal, naming the same entry and
// covering X's late note. Served beside it, or in its place, it is a
// fork. With everything after it hidden too, it does not count toward
// the cut.
func TestSummaryBesideAnOldOneIsRefused(t *testing.T) {
	for _, c := range []struct {
		name      string
		after     int
		hideOld   bool
		hideAfter int
		want      error
	}{
		{"served beside it", 1, false, 0, ErrFork},
		{"in its place", 1, true, 0, ErrFork},
		{"in its place, the chain after it hidden", 2, true, 1, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, a, m, x, note, old := removedWithLateNote(t, c.after)
			forged := signedSummary(t, m, x, old.Num, old.Prev, old.ListNum, old.ListHash)
			must(t, w.srv.Append(m.id, logSummaries(m.id), forged.Marshal()))
			var hide []Hash
			if c.hideOld {
				hide = append(hide, old.Hash())
			}
			for _, it := range mustRead(t, w, logSummaries(m.id)) {
				s, err := ParseSummary(it)
				must(t, err)
				if s.Num > old.Num && s.Num <= old.Num+uint64(c.hideAfter) {
					hide = append(hide, s.Hash())
				}
			}
			hideSummaries(w, a, m, hide...)
			_, err := a.Sync()
			if c.want != nil {
				wantErr(t, err, c.want)
			} else {
				must(t, err)
			}
			if _, ok := a.Get(note); ok {
				t.Fatal("a summary slipped in beside an old one kept a removed device's late note")
			}
		})
	}
}

// Finding 49: after building on s1, A accepts a newer s2 that B has not
// named yet. Writes may still go only up to s1.
func TestSnapshotToPruneIsTheConfirmedOne(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	srv, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, b)
	s1, err := a.MakeSnapshot()
	must(t, err)
	w.syncAll(a, b)
	if p := a.SnapshotToPrune(); p == nil || p.Hash() != s1.Hash() {
		t.Fatal("setup: A should build on s1")
	}
	_, err = a.Update(srv, field("description", "after s1"))
	must(t, err)
	_, err = a.Sync()
	must(t, err)
	s2, err := a.MakeSnapshot()
	must(t, err)
	_, err = a.Sync()
	must(t, err)
	if p := a.SnapshotToPrune(); p == nil || p.Hash() != s1.Hash() {
		t.Fatal("a snapshot B has not named was offered for pruning")
	}
	w.syncAll(a, b)
	if p := a.SnapshotToPrune(); p == nil || p.Hash() != s2.Hash() {
		t.Fatal("s2, which every device named, is not the one to prune to")
	}
}

// Findings 50 and 53: names are held per type. A server named after a
// device, or after a note, replaces neither, and an approval whose list
// of old holders names a device record or a note deletes neither.
func TestApprovalNeverDeletesADeviceRecord(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("MacBook")
	b := w.pair(a, "iPhone", true)
	m := w.pair(a, "Mac mini", false)
	note, err := m.Create(TypeNote, field("name", "prod-db"), field("text", "a note"))
	must(t, err)
	w.syncAll(a, b, m)
	nw, err := m.Create(TypeServer, field("name", "iPhone"), field("address", "10.0.0.7"))
	must(t, err)
	_, err = m.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.8"))
	must(t, err)
	w.syncAll(a, b, m)
	ws := a.Waiting()
	if len(ws) != 2 || ws[0].Replaces != "" || ws[1].Replaces != "" {
		t.Fatalf("a device or a note holds a server's name: %+v", ws)
	}
	for _, wt := range ws {
		must(t, a.Approve(wt.Ref))
	}

	// A modified client lists B's device record and the note as old
	// holders, signed with a real authority key.
	other, err := m.Create(TypeServer, field("name", "web"), field("address", "10.0.0.9"))
	must(t, err)
	w.syncAll(a, b, m)
	wt := a.Waiting()[0]
	replaces := slices.SortedFunc(slices.Values([]RecordID{idRecord(b.ID()), note}), func(p, q RecordID) int { return slices.Compare(p[:], q[:]) })
	yes := &Change{Kind: kindApproval, Record: wt.Record, Type: wt.Type, Target: wt.Ref, Replaces: replaces}
	sig, err := sign(a.keys.Authority, labelApproval, approvalBytes(a.account, yes))
	must(t, err)
	yes.Approval = sig
	_, err = a.write(yes)
	must(t, err)
	w.syncAll(a, b, m)
	for _, d := range []*Device{a, b, m} {
		if name, ok := d.DeviceName(b.ID()); !ok || name != "iPhone" {
			t.Fatalf("%s: B's device record was deleted", d.Name)
		}
		if _, ok := d.Get(note); !ok {
			t.Fatalf("%s: the note was deleted", d.Name)
		}
		if _, ok := d.Get(nw); !ok {
			t.Fatalf("%s: the server named iPhone is missing", d.Name)
		}
		if _, ok := d.Get(other); !ok {
			t.Fatalf("%s: the approved server is missing", d.Name)
		}
	}
}

// Finding 51: on a device with Face ID, creating a second server named
// prod-db does not delete the first in the same edit. It waits, shown as
// "replaces prod-db (deleted)", until the person says yes.
func TestAutoApproveNeverImpliesADeletingYes(t *testing.T) {
	w := newWorld(t)
	phone, _ := w.account("iPhone")
	old, err := phone.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	if _, ok := phone.Get(old); !ok {
		t.Fatal("setup: the first server should be approved while editing")
	}
	nw, err := phone.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.7"))
	must(t, err)
	if _, ok := phone.Get(old); !ok {
		t.Fatal("the old prod-db was deleted without the person seeing it")
	}
	ws := phone.Waiting()
	if len(ws) != 1 || ws[0].ReplacesLine() != "replaces prod-db (deleted)" {
		t.Fatalf("the newcomer does not wait with its replaces line: %+v", ws)
	}
	must(t, phone.Approve(ws[0].Ref))
	if _, ok := phone.Get(old); ok {
		t.Fatal("the yes did not delete the old holder")
	}
	if _, ok := phone.Get(nw); !ok {
		t.Fatal("the yes did not apply the newcomer")
	}
}

func denyRules(d *Device, pattern string) int {
	n := 0
	for _, r := range d.data.records {
		if r.Type == TypeDeny && r.Exists && !r.Deleted && r.Fields["pattern"].Value == pattern {
			n++
		}
	}
	return n
}

// Finding 52: X's deny rule is past its cut, and B and C both applied
// it. Both write it again, as one rule: every device ends with one copy.
func TestRewrittenDenyRuleIsOneRule(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	x := w.pair(a, "X", true)
	w.syncAll(a, b, c, x)
	_, err := x.Create(TypeDeny, field("pattern", "rm -rf *"))
	must(t, err)
	for _, d := range []*Device{b, c} {
		_, err = d.pull()
		must(t, err)
	}
	must(t, a.Remove(x.ID()))
	w.syncAll(a, b, c)
	for _, d := range []*Device{a, b, c} {
		if n := denyRules(d, "rm -rf *"); n != 1 {
			t.Fatalf("%s holds %d copies of the deny rule, want 1", d.Name, n)
		}
	}
	if string(b.data.encode(nil)) != string(c.data.encode(nil)) {
		t.Fatal("B and C hold other data")
	}
}

// Finding 54: X turns protected on; B pulls it, then turns it off with a
// person's yes. No summary covered X's write when A removed X. B does not
// write X's value again over the newer yes.
func TestStricterValueReplacedByAYesIsNotWrittenAgain(t *testing.T) {
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
	_, err = b.Update(srv, field("protected", "false")) // with B's yes
	must(t, err)
	must(t, a.Remove(x.ID()))
	w.syncAll(a, b)
	for _, d := range []*Device{a, b} {
		if got := value(t, d, srv, "protected"); got != "false" {
			t.Fatalf("%s: a value replaced by a newer yes was written again: protected %q", d.Name, got)
		}
	}
}
