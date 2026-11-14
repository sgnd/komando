package komandosync

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// Tests for the review findings of 2026-11-14 (sync-prototype.md, "Review
// findings"). Each one fails on the code before its fix.

// pairBefore pairs a device without Touch ID whose ID sorts before by's, so
// a newly joined device opens its writes first.
func (w *world) pairBefore(by *Device, name string) *Device {
	w.t.Helper()
	for {
		k, err := NewSoftDeviceKeys(false)
		must(w.t, err)
		m := NewDevice(name, k, w.srv, w.clk.now)
		mid, bid := m.ID(), by.ID()
		if bytes.Compare(mid[:], bid[:]) >= 0 {
			continue
		}
		j, code, err := StartJoin(m)
		must(w.t, err)
		must(w.t, by.AcceptJoin(code, func(string) bool { return true }))
		_, err = j.Finish()
		must(w.t, err)
		_, err = m.Sync()
		must(w.t, err)
		return m
	}
}

// A device without an authority key relabels a server as a note to skip
// the person's yes. The type is fixed in the record ID, so every device
// refuses the change, old and new alike.
func TestRecordTypeIsFixedByItsID(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("iPhone")
	id, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	_, err = a.Sync()
	must(t, err)
	m := w.pairBefore(a, "Mac mini")
	w.clk.add(time.Minute)
	forged := &Change{Kind: kindRecord, Record: id, Type: TypeNote, Fields: []Field{field("address", "203.0.113.9")}}
	_, err = m.change(forged)
	wantErr(t, err, ErrBadWrite)
	_, err = m.write(forged) // a client that skips its own check
	must(t, err)

	rep, err := a.Sync()
	must(t, err)
	if rep.Rejected != 1 {
		t.Fatalf("A rejected %d changes, want 1", rep.Rejected)
	}
	n := w.pair(a, "new iPad", true)
	for _, d := range []*Device{a, n} {
		if got := value(t, d, id, "address"); got != "10.0.0.5" || len(d.Waiting()) != 0 {
			t.Fatalf("%s: address %s, %d waiting", d.Name, got, len(d.Waiting()))
		}
	}
}

// Merging the same writes in any order gives the same state (SS 9).
func TestMergeIsOrderFree(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("iPhone")
	m := w.pair(a, "Mac mini", false)
	id, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	_, err = a.Create(TypeNote, field("text", "a note"))
	must(t, err)
	w.syncAll(a, m)
	_, err = m.Update(id, field("address", "10.0.0.6"), field("protected", "true"))
	must(t, err)
	_, err = m.write(&Change{Kind: kindRecord, Record: id, Type: TypeNote, Fields: []Field{field("address", "203.0.113.9")}})
	must(t, err)
	_, err = m.write(&Change{Kind: kindRecord, Record: idRecord(a.ID()), Type: TypeDevice, Delete: true})
	must(t, err)
	w.syncAll(a, m)

	state := func(log []staged) string {
		d := &Device{data: newMergeState(), list: a.list, account: a.account}
		for _, s := range log {
			d.applyChange(s.w, s.c, &Report{})
		}
		var b strings.Builder
		for _, rid := range slices.SortedFunc(maps.Keys(d.data.records), func(x, y RecordID) int { return bytes.Compare(x[:], y[:]) }) {
			f, ok := d.Get(rid)
			fmt.Fprintf(&b, "%x %v", rid, ok)
			for _, k := range slices.Sorted(maps.Keys(f)) {
				fmt.Fprintf(&b, " %s=%s", k, f[k])
			}
			b.WriteString("\n")
		}
		return fmt.Sprintf("%swaiting %d", b.String(), len(d.Waiting()))
	}
	fwd := state(a.log)
	back := slices.Clone(a.log)
	slices.Reverse(back)
	if rev := state(back); rev != fwd {
		t.Fatalf("order changes the result:\n%s\nreversed:\n%s", fwd, rev)
	}
	if _, ok := a.DeviceName(a.ID()); !ok {
		t.Fatal("another device deleted A's name record")
	}
}

// A device record is written only by its own device and never deleted:
// another device can neither remove a name nor rename it to a part of it.
func TestDeviceRecordOnlyByItsDevice(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("Budi's old MacBook")
	m := w.pair(a, "Mac mini", false)
	w.syncAll(a, m)
	f, ok := a.Get(idRecord(a.ID()))
	if !ok {
		t.Fatal("setup: no name record")
	}
	salt, _ := hex.DecodeString(f["salt"])
	longer := hex.EncodeToString(append(salt, "Budi's old "...))
	_, err := m.write(&Change{Kind: kindRecord, Record: idRecord(a.ID()), Type: TypeDevice,
		Fields: []Field{field("salt", longer), field("name", "MacBook")}})
	must(t, err)
	_, err = m.write(&Change{Kind: kindRecord, Record: idRecord(a.ID()), Type: TypeDevice, Delete: true})
	must(t, err)
	w.syncAll(a, m)
	if name, ok := a.DeviceName(a.ID()); !ok || name != "Budi's old MacBook" {
		t.Fatalf("A's name: %q %v", name, ok)
	}
}

// Salt and name are hashed with their lengths, so bytes cannot move from
// one to the other.
func TestDeviceInfoHashSeparatesSaltAndName(t *testing.T) {
	salt := seq(1, infoSaltSize)
	if deviceInfoHash(salt, "Budi's old MacBook") == deviceInfoHash(append(slices.Clone(salt), "Budi's old "...), "MacBook") {
		t.Fatal("salt and name can trade bytes")
	}
}

// forgeAuth builds a replace-authority entry with the given request
// signatures, signed in by by's authority key or by a kit.
func forgeAuth(t *testing.T, by *Device, target DeviceID, newKey *SoftSigner, asker Signer, kit *Kit) *Entry {
	t.Helper()
	pub := pubBytes(newKey.Public())
	en := by.nextEntry(Body{Action: ActReplaceAuthority, AuthOf: target, NewAuth: pub})
	msg := authAskBytes(by.account, target, by.list.Members[target].Rec.AuthPub, pub)
	ask, err := sign(asker, labelAuthAsk, msg)
	must(t, err)
	proof, err := sign(newKey, labelAuthAsk, msg)
	must(t, err)
	en.Sigs = []EntrySig{{Role: RoleAuthAsk, Device: target, Sig: ask}, {Role: RoleAuthProof, Device: target, Sig: proof}}
	if kit != nil {
		must(t, en.signEntry(kit.signer(), RoleKit, DeviceID{}, uint8(by.list.kitIndex(kit.Record()))))
	} else {
		must(t, en.signEntry(by.keys.Authority, RoleAuthority, by.ID(), 0))
	}
	return en
}

// Swapping another device's authority key needs that device's own
// request. A device added today, or a thief with only the kit, cannot do
// it, and a new key never makes its device younger to others.
func TestReplaceAuthorityNeedsTheDevice(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	w.clk.add(30 * 24 * time.Hour)
	c := w.pair(a, "iPad", true)
	w.clk.add(30 * 24 * time.Hour)
	d := w.pair(a, "tricked-in device", true)
	w.syncAll(a, c, d)
	wantErr(t, d.Remove(a.ID()), ErrYoungDevice)

	// D asks in A's name with a key of its own: refused.
	junk := mustSigner(t)
	wantErr(t, d.appendEntry(forgeAuth(t, d, a.ID(), junk, d.keys.Sync, nil)), ErrNotAuthorized)
	// A thief with the kit signs in its own key for A: refused.
	thief := w.device("thief", true)
	_, err := OpenWithKit(thief, kit)
	must(t, err)
	wantErr(t, thief.appendEntry(forgeAuth(t, thief, a.ID(), junk, thief.keys.Sync, kit)), ErrNotAuthorized)

	// A's real request: D, 0 days old, may not sign it in for older A.
	req, err := a.AskAuthority(mustSigner(t))
	must(t, err)
	wantErr(t, d.SignInAuthority(req), ErrYoungDevice)
	must(t, c.SignInAuthority(req))
	// A's new key does not make A younger than D: not on D, and not on C
	// when D skips its own check.
	must(t, d.refreshList())
	wantErr(t, d.Remove(a.ID()), ErrYoungDevice)
	g, err := newGen(d.list.Gen.Gen + 1)
	must(t, err)
	rm := d.nextEntry(Body{Action: ActRemove, Removes: d.removals([]DeviceID{a.ID()}), Key: &g.KeyGen})
	must(t, rm.signEntry(d.keys.Authority, RoleAuthority, d.ID(), 0))
	keep := mustRead(t, w, logList)
	must(t, w.srv.MemServer.AppendAt(d.ID(), logList, int(rm.Num-1), rm.Marshal()))
	_, err = c.Sync()
	wantErr(t, err, ErrYoungDevice)
	w.srv.SetLog(logList, keep)
	// The request cannot be replayed once used: it names the key it replaced.
	wantErr(t, c.SignInAuthority(req), ErrNotAuthorized)
	rep, err := a.Sync()
	must(t, err)
	if !strings.Contains(strings.Join(rep.Alerts, "\n"), "for this device") {
		t.Fatalf("A not told: %v", rep.Alerts)
	}
}

// A kit cannot cancel a waiting change: a lost-kit replacement goes
// through even when the lost kit is in a thief's hands.
func TestKitCannotCancel(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	lost, num, err := a.ReplaceLostKits(1)
	must(t, err)
	thief := w.device("thief", true)
	_, err = OpenWithKit(thief, kit)
	must(t, err)
	en := thief.nextEntry(Body{Action: ActCancel, Ref: num})
	must(t, en.signEntry(kit.signer(), RoleKit, DeviceID{}, uint8(thief.list.kitIndex(kit.Record()))))
	wantErr(t, thief.appendEntry(en), ErrNotAuthorized)
	w.clk.add(WaitKitLost + time.Hour)
	must(t, a.ApplyPending(num))
	_, err = OpenWithKit(w.device("x", true), kit)
	wantErr(t, err, ErrKitUnknown)
	_, err = OpenWithKit(w.device("y", true), lost[0])
	must(t, err)
}

// The kit alone, on a device that is not listed, cannot use the recovery
// step that applies at once; it only gets the 24-hour takeover.
func TestRecoveryStepNeedsAListedDevice(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	b := w.pair(a, "iPhone", true)
	w.syncAll(a, b)
	thief := w.device("thief", true)
	_, err := OpenWithKit(thief, kit)
	must(t, err)
	g, err := newGen(thief.list.Gen.Gen + 1)
	must(t, err)
	kits, recs, err := makeKits(1)
	must(t, err)
	en := thief.nextEntry(Body{Action: ActRecoveryStep, Removes: thief.removals([]DeviceID{a.ID()}), Key: &g.KeyGen, Kits: recs})
	must(t, addNewKitSigs(en, kits))
	must(t, en.signEntry(kit.signer(), RoleKit, DeviceID{}, uint8(thief.list.kitIndex(kit.Record()))))
	wantErr(t, thief.appendEntry(en), ErrNotAuthorized)
	// Its own sync key, not listed, does not help either.
	must(t, en.signEntry(thief.keys.Sync, RoleDevice, thief.ID(), 0))
	wantErr(t, thief.appendEntry(en), ErrNotAuthorized)
	_, err = b.Sync()
	must(t, err)
}

// A key change during a wait does not strand the waiting change: its new
// key is made when it applies.
func TestPendingSurvivesAKeyChange(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	lost, num, err := a.ReplaceLostKits(1)
	must(t, err)
	must(t, b.Remove(c.ID()))
	_, err = a.Sync()
	must(t, err)
	w.clk.add(WaitKitLost + time.Hour)
	must(t, a.ApplyPending(num))
	_, err = OpenWithKit(w.device("y", true), lost[0])
	must(t, err)

	// A removal that waits, whose target another entry removed meanwhile,
	// applies as done, with no new key.
	w.clk.add(30 * 24 * time.Hour)
	d := w.pair(a, "D", true)
	w.syncAll(a, b, d)
	later, err := d.RemoveLater(b.ID())
	must(t, err)
	must(t, a.Remove(b.ID()))
	_, err = d.Sync()
	must(t, err)
	gen := d.List().Gen.Gen
	w.clk.add(WaitYoung + time.Hour)
	must(t, d.ApplyPending(later))
	if p := d.List().Pending[later]; !p.Done || d.List().Gen.Gen != gen {
		t.Fatalf("done %v, generation %d -> %d", p.Done, gen, d.List().Gen.Gen)
	}
}

// A device that sees a waiting change and its apply at once holds the
// list for its own wait. It keeps syncing what it can, reports the hold
// and the alert, and catches up after the wait.
func TestHeldDeviceKeepsSyncing(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	_, num, err := a.ReplaceLostKits(1)
	must(t, err)
	_, err = b.Sync()
	must(t, err)
	w.clk.add(WaitKitLost + time.Hour) // C is offline the whole time
	must(t, a.ApplyPending(num))
	note, err := a.Create(TypeNote, field("text", "after the new key"))
	must(t, err)
	w.syncAll(a, b)

	rep, err := c.Sync()
	must(t, err)
	if rep.Hold == nil || rep.Held == 0 || len(rep.Alerts) == 0 {
		t.Fatalf("C: %+v", rep)
	}
	if _, ok := c.Get(note); ok {
		t.Fatal("C applied a write past its hold")
	}
	w.clk.add(WaitKitLost)
	rep, err = c.Sync()
	must(t, err)
	if rep.Hold != nil {
		t.Fatalf("still held: %+v", rep.Hold)
	}
	if _, ok := c.Get(note); !ok {
		t.Fatal("C did not catch up after the hold")
	}
}

// A write must be sealed under the generation in force at the list entry
// it names.
func TestWriteUnderAnOldGenerationIsRefused(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	must(t, a.Remove(b.ID()))
	_, err := c.Sync()
	must(t, err)
	c.list.Gen = c.list.Gens[1] // a client that keeps using the old key
	_, err = c.write(&Change{Kind: kindRecord, Record: recordID(TypeNote, [12]byte{1}), Type: TypeNote, Create: true})
	must(t, err)
	_, err = a.Sync()
	wantErr(t, err, ErrBadWrite)
}

// A code answered twice, by two devices the server shows different lists,
// never gives two replies under one key and nonce; one device answers a
// code once whatever the server does.
func TestPairingReplyFreshKeyEachAnswer(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("MacBook")
	b := w.pair(a, "iPhone", true)
	w.syncAll(a, b)
	var replies [][]byte
	w.srv.OnPut = func(_ DeviceID, name string, data []byte) bool {
		if strings.HasSuffix(name, "/reply") {
			replies = append(replies, data)
		}
		return !(strings.HasSuffix(name, "/req") && data == nil) // never deletes a request
	}
	listBefore := mustRead(t, w, logList)
	sumsBefore := len(mustRead(t, w, logSummaries(a.ID())))
	_, code, err := StartJoin(w.device("iPad", true))
	must(t, err)
	yes := func(string) bool { return true }
	must(t, a.AcceptJoin(code, yes))
	wantErr(t, a.AcceptJoin(code, yes), ErrPairingUsed)

	// Fork: B is shown the list and A's summaries from before the answer.
	w.srv.SetLog(logList, listBefore)
	w.srv.OnRead = func(by DeviceID, l string, items [][]byte) [][]byte {
		if by == b.ID() && l == logSummaries(a.ID()) {
			return items[:sumsBefore]
		}
		return items
	}
	must(t, b.AcceptJoin(code, yes))
	if len(replies) != 2 {
		t.Fatalf("%d replies", len(replies))
	}
	for off := 0; off+32 <= min(len(replies[0]), len(replies[1])); off += 32 {
		if bytes.Equal(replies[0][off:off+32], replies[1][off:off+32]) {
			t.Fatalf("the two replies share bytes %d to %d: one key and nonce twice", off, off+32)
		}
	}
}

// Paper parts carry their kit's ID: a part of an older kit is left out, and
// parts of two kits are never combined into a wrong key.
func TestPaperPartsOfTwoKits(t *testing.T) {
	k1, err := NewKit()
	must(t, err)
	k2, err := NewKit()
	must(t, err)
	p1, err := k1.Paper()
	must(t, err)
	p2, err := k2.Paper()
	must(t, err)
	got, err := KitFromPaper(p2[0], p1[1], p2[2])
	must(t, err)
	if got.key != k2.key {
		t.Fatal("three parts with one from an older kit gave the wrong key")
	}
	_, err = KitFromPaper(p1[0], p2[1])
	wantErr(t, err, ErrKitParts)
	if g := strings.Fields(p1[0]); len(g) != 15 || len(g[14]) != 4 {
		t.Fatalf("a part is not 15 groups of four: %q", p1[0])
	}
}
