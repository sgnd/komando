package komandosync

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// Tests for the owner's decisions of 2026-11-14 that close SS 21
// (findings 9, 16, 17, 19, 32, 33 and 35 in sync-prototype.md). Each one
// fails on the code before its rule was built.

// forgeSummary signs a summary with dev's sync key, naming list entry
// num, that covers every write of extra as dev never saw it.
func forgeSummary(t *testing.T, w *world, dev, extra *Device, num uint32, hash Hash) {
	t.Helper()
	s := &Summary{Account: dev.account, Signer: dev.id, Num: dev.sumNum[dev.id] + 1, KeyGen: 1,
		ListNum: num, ListHash: hash, MinClient: minClient}
	if prev := dev.summaries[dev.id]; prev != nil {
		s.Prev = prev.Hash()
	}
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
	must(t, w.srv.Append(dev.id, logSummaries(dev.id), s.Marshal()))
}

// Finding 35, hostile server: the server holds the Mac mini M on the list
// from before X's removal. X changes prod-db's address and approves it
// itself; M applies both and signs a summary naming the old entry. That
// summary raises X's cut, but past the floor only what applies by itself
// counts: the address change and X's yes are dropped on every device and
// shown, M included once it catches up (SS 6.2).
func TestHeldSummaryCannotBringInAnApproval(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	m := w.pair(a, "Mac mini", false)
	x := w.pair(a, "iPad", true)
	srv, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, m, x)
	held := len(mustRead(t, w, logList))
	w.srv.OnRead = func(by DeviceID, log string, items [][]byte) [][]byte {
		if by == m.ID() && log == logList {
			return items[:held]
		}
		return items
	}
	must(t, a.Remove(x.ID()))
	note, err := x.Create(TypeNote, field("text", "late"))
	must(t, err)
	_, err = x.Update(srv, field("address", "203.0.113.9"))
	must(t, err)
	_, err = m.Sync()
	must(t, err)
	if value(t, m, srv, "address") != "203.0.113.9" {
		t.Fatal("setup: the held Mac should apply X's approved change")
	}

	rep, err := a.Sync()
	must(t, err)
	if got := value(t, a, srv, "address"); got != "10.0.0.5" {
		t.Fatalf("a held device's summary brought in a removed device's approval: address %q", got)
	}
	if _, ok := a.Get(note); !ok {
		t.Fatal("a note the summary covers was not kept")
	}
	if len(a.DroppedWrites()) != 2 || !strings.Contains(strings.Join(rep.Alerts, "\n"), "were not kept") {
		t.Fatalf("the dropped change and yes were not shown: %v %v", a.DroppedWrites(), rep.Alerts)
	}

	w.srv.OnRead = nil
	w.syncAll(a, m)
	if got := value(t, m, srv, "address"); got != "10.0.0.5" {
		t.Fatalf("M kept the approval once it caught up: address %q", got)
	}
	if len(m.DroppedWrites()) != 2 {
		t.Fatalf("M did not show what it dropped: %v", m.DroppedWrites())
	}
}

// Finding 35, stolen sync key: the thief holds the Mac mini's sync key.
// A removes the iPad, then the Mac. A summary signed with the Mac's key,
// naming the entry from before both removals, covers the iPad's late
// note. The Mac is no longer listed, so its summary counts for nothing.
func TestRemovedSignerSummaryDoesNotCount(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	m := w.pair(a, "stolen Mac mini", false)
	x := w.pair(a, "stolen iPad", true)
	w.syncAll(a, m, x)
	oldNum, oldHash := m.head, m.headHash
	must(t, a.Remove(x.ID()))
	must(t, a.Remove(m.ID()))
	note, err := x.Create(TypeNote, field("text", "late"))
	must(t, err)
	forgeSummary(t, w, m, x, oldNum, oldHash)
	_, err = a.Sync()
	must(t, err)
	if _, ok := a.Get(note); ok {
		t.Fatal("a summary of a removed device moved the cut")
	}
	if !slices.ContainsFunc(a.DroppedWrites(), func(r WriteRef) bool { return r.Writer == x.ID() }) {
		t.Fatal("the dropped note was not shown")
	}
}

// Finding 35, backdated summary: the Mac mini is still listed and already
// signed a summary naming the removal. A summary signed later with its
// sync key that names an entry from before the removal is refused.
func TestBackdatedSummaryIsRefused(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	m := w.pair(a, "Mac mini", false)
	x := w.pair(a, "iPad", true)
	w.syncAll(a, m, x)
	oldNum, oldHash := m.head, m.headHash
	must(t, a.Remove(x.ID()))
	_, err := m.Sync() // M names the removal
	must(t, err)
	_, err = x.Create(TypeNote, field("text", "late"))
	must(t, err)
	forgeSummary(t, w, m, x, oldNum, oldHash)
	_, err = a.Sync()
	wantErr(t, err, ErrRollback)
}

// Finding 32: the Mac mini M, which has no authority key, moves prod-db.
// C gives the yes, and B applies it, but no summary covered C's yes
// before A removed C. The yes is past the cut: B merges again without it,
// so B shows the same address as A, which never saw the yes. The person
// sees the dropped yes and approves again (SS 6.2).
func TestApprovalPastTheCutIsDropped(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	m := w.pair(a, "Mac mini", false)
	srv, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, b, c, m)
	ref, err := m.Update(srv, field("address", "203.0.113.9"))
	must(t, err)
	w.syncAll(a, b, c, m)
	must(t, c.Approve(ref))
	_, err = b.pull()
	must(t, err)
	if value(t, b, srv, "address") != "203.0.113.9" {
		t.Fatal("setup: B should apply the change C approved")
	}
	must(t, a.Remove(c.ID()))
	w.syncAll(a, b)
	for _, d := range []*Device{a, b} {
		if got := value(t, d, srv, "address"); got != "10.0.0.5" {
			t.Fatalf("%s: a yes past the cut was kept: address %q", d.Name, got)
		}
	}
	if got := b.DroppedWrites(); len(got) != 1 || got[0].Writer != c.ID() {
		t.Fatalf("B did not show the dropped yes: %v", got)
	}
	must(t, a.Approve(ref))
	w.syncAll(a, b)
	if value(t, b, srv, "address") != "203.0.113.9" {
		t.Fatal("a fresh yes did not apply")
	}
}

// Finding 16: the stricter-values table. Each rule field has one value
// that applies by itself; anything not in the table waits. A new deny
// rule applies by itself; an edit or a delete of one waits; a second
// "create" of a deny rule's ID is refused (SS 8.1).
func TestStricterValuesTable(t *testing.T) {
	w := newWorld(t)
	phone, _ := w.account("iPhone")
	mini := w.pair(phone, "Mac mini", false)
	id, err := phone.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(phone, mini)
	for _, c := range []struct {
		f     Field
		waits bool
	}{
		{field("never_ai", "true"), false},
		{field("approval", "required"), false},
		{field("protected", "true"), false},
		{field("never_ai", "false"), true},
		{field("approval", "optional"), true},
		{field("protected", "yes"), true}, // not the table's value
		{field("audit", "strict"), true},  // not in the table
	} {
		before := value(t, phone, id, c.f.Name)
		_, err := mini.Update(id, c.f)
		must(t, err)
		w.syncAll(phone, mini)
		got := value(t, phone, id, c.f.Name)
		if waited := got == before && got != c.f.Value; waited != c.waits {
			t.Fatalf("%s=%s: waits %v, want %v", c.f.Name, c.f.Value, waited, c.waits)
		}
		for _, wt := range phone.Waiting() {
			must(t, phone.Approve(wt.Ref))
		}
		w.syncAll(phone, mini)
	}

	deny, err := mini.Create(TypeDeny, field("pattern", "rm -rf *"))
	must(t, err)
	w.syncAll(phone, mini)
	if got := value(t, phone, deny, "pattern"); got != "rm -rf *" {
		t.Fatalf("a new deny rule did not apply by itself: %q", got)
	}
	_, err = mini.Update(deny, field("pattern", "nothing"))
	must(t, err)
	_, err = mini.Delete(deny)
	must(t, err)
	w.syncAll(phone, mini)
	if got := value(t, phone, deny, "pattern"); got != "rm -rf *" || len(phone.Waiting()) != 2 {
		t.Fatalf("an edit or delete of a deny rule applied without a yes: %q, waiting %d", got, len(phone.Waiting()))
	}
	again := &Change{Kind: kindRecord, Record: deny, Type: TypeDeny, Create: true, Fields: []Field{field("pattern", "nothing")}}
	_, err = mini.change(again)
	wantErr(t, err, ErrBadWrite)
	_, err = mini.write(again) // a client that skips its own check
	must(t, err)
	rep, err := phone.Sync()
	must(t, err)
	if rep.Rejected != 1 || value(t, phone, deny, "pattern") != "rm -rf *" {
		t.Fatalf("a second create of a deny rule: rejected %d, pattern %q", rep.Rejected, value(t, phone, deny, "pattern"))
	}
}

// Finding 17: a newcomer that takes a held name is shown as "replaces
// prod-db (deleted)", and approving it deletes the old holder in the same
// signed yes, so two records never hold one name. An approval whose list
// of old holders was changed does not verify (SS 8.1).
func TestApprovingANewcomerDeletesTheOldHolder(t *testing.T) {
	w := newWorld(t)
	phone, _ := w.account("iPhone")
	mini := w.pair(phone, "Mac mini", false)
	old, err := phone.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	other, err := phone.Create(TypeServer, field("name", "web"), field("address", "10.0.0.6"))
	must(t, err)
	w.syncAll(phone, mini)
	nw, err := mini.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.7"))
	must(t, err)
	w.syncAll(phone, mini)
	ws := phone.Waiting()
	if len(ws) != 1 || ws[0].ReplacesLine() != "replaces prod-db (deleted)" || !slices.Equal(ws[0].ReplacesIDs, []RecordID{old}) {
		t.Fatalf("the screen does not show the old holder: %+v", ws)
	}

	// A yes whose list of old holders was swapped for another record.
	yes := &Change{Kind: kindApproval, Record: ws[0].Record, Type: ws[0].Type, Target: ws[0].Ref, Replaces: ws[0].ReplacesIDs}
	sig, err := sign(phone.keys.Authority, labelApproval, approvalBytes(phone.account, yes))
	must(t, err)
	yes.Replaces, yes.Approval = []RecordID{other}, sig
	_, err = phone.write(yes)
	must(t, err)
	rep, err := mini.Sync()
	must(t, err)
	if rep.Rejected != 1 {
		t.Fatalf("a changed list of old holders verified: rejected %d", rep.Rejected)
	}

	must(t, phone.Approve(ws[0].Ref))
	w.syncAll(phone, mini)
	for _, d := range []*Device{phone, mini} {
		if _, ok := d.Get(old); ok {
			t.Fatalf("%s: the old holder of prod-db is still there", d.Name)
		}
		if value(t, d, nw, "address") != "10.0.0.7" || value(t, d, other, "address") != "10.0.0.6" {
			t.Fatalf("%s: newcomer %q, other %q", d.Name, value(t, d, nw, "address"), value(t, d, other, "address"))
		}
	}
}

// Finding 9: snapshots. A snapshot that does not match a device's own
// merged state is refused and the writes stay. One every current device
// signed a summary naming lets the older writes go; a new device starts
// from it and reads only the writes after it (SS 9).
func TestSnapshots(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	srv, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	gone, err := b.Create(TypeNote, field("name", "old-note"), field("text", "soon deleted"))
	must(t, err)
	_, err = b.Delete(gone)
	must(t, err)
	for i := range 20 {
		_, err = a.Update(srv, field("description", strings.Repeat("x", i)))
		must(t, err)
	}
	w.syncAll(a, b)

	// B's sync key signs a state in which prod-db moved. A refuses it.
	rec := b.data.records[srv]
	real := rec.Fields["address"]
	rec.Fields["address"] = fieldVal{Value: "203.0.113.9", Clock: real.Clock}
	_, err = b.MakeSnapshot()
	must(t, err)
	rec.Fields["address"] = real
	rep, err := a.Sync()
	must(t, err)
	if rep.Refused != 1 || !strings.Contains(strings.Join(rep.Alerts, "\n"), "refused") || a.snap != nil {
		t.Fatalf("A did not refuse a snapshot that differs: refused %d, alerts %v", rep.Refused, rep.Alerts)
	}
	_, err = b.Sync() // B judges its own again and drops it
	must(t, err)
	if b.snap != nil {
		t.Fatal("B still names a snapshot that differs from its data")
	}

	snap, err := a.MakeSnapshot()
	must(t, err)
	_, err = a.Sync()
	must(t, err)
	if a.SnapshotToPrune() != nil {
		t.Fatal("writes may go before every current device named the snapshot")
	}
	w.syncAll(a, b)
	for _, d := range []*Device{a, b} {
		if p := d.SnapshotToPrune(); p == nil || p.Hash() != snap.Hash() {
			t.Fatalf("%s: the snapshot every device named is not the one to prune to", d.Name)
		}
		if len(d.log) != 0 {
			t.Fatalf("%s: still keeps %d writes the snapshot holds", d.Name, len(d.log))
		}
	}
	before := len(w.srv.AllBytes())
	w.srv.PruneWrites(snap.Heads)
	if after := len(w.srv.AllBytes()); after >= before {
		t.Fatalf("pruning kept %d of %d items", after, before)
	}

	// Writes after the snapshot still sync, on top of it.
	_, err = b.Update(srv, field("description", "after the snapshot"))
	must(t, err)
	w.syncAll(a, b)

	// A new device starts from the snapshot: the writes it holds are no
	// longer on the server.
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	if c.base == nil {
		t.Fatal("the new device did not start from the snapshot")
	}
	for _, d := range []*Device{a, b} {
		if string(c.data.encode(nil)) != string(d.data.encode(nil)) {
			t.Fatalf("C holds other data than %s", d.Name)
		}
	}
	if value(t, c, srv, "description") != "after the snapshot" || value(t, c, srv, "address") != "10.0.0.5" {
		t.Fatalf("C: %v", c.data.records[srv].Fields)
	}
	if _, ok := c.Get(gone); ok {
		t.Fatal("a deleted record came back from the snapshot")
	}
	if f := c.data.records[gone].Fields; len(f) != 1 || f["name"].Value != "old-note" {
		t.Fatalf("a deleted record did not keep its name and only that: %v", f)
	}
}

// Finding 19: the lowest Go version is Go 1.26, the first with
// crypto/hpke. go vet's stdversion check then refuses any standard
// library call newer than that.
func TestLowestGoVersion(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	must(t, err)
	if !slices.Contains(strings.Split(string(b), "\n"), "go 1.26.0") {
		t.Fatalf("go.mod does not name Go 1.26 as the lowest version:\n%s", b)
	}
}
