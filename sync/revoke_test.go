package komandosync

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRevokedDeviceCannotReadOrWrite(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("MacBook")
	b := w.pair(a, "iPhone", true)
	c := w.pair(a, "stolen iPad", true)
	old, err := c.Create(TypeNote, field("text", "written before removal"))
	must(t, err)
	w.syncAll(a, b, c)

	must(t, a.Remove(c.ID()))
	removal := a.Head()
	if got := a.Unconfirmed(removal); !slices.Contains(got, b.ID()) {
		t.Fatalf("B should show as not yet confirmed: %v", got)
	}
	// C has not heard yet and keeps writing with what it has.
	late, err := c.Create(TypeNote, field("text", "written after removal"))
	must(t, err)
	secret, err := a.Create(TypeSecret, field("name", "db-pass"), field("value", "new-password"))
	must(t, err)

	rep, err := b.Sync()
	must(t, err)
	if rep.Revoked != 1 {
		t.Fatalf("revoked writes = %d, want 1", rep.Revoked)
	}
	if _, ok := b.Get(late); ok {
		t.Fatal("a write signed after removal was accepted")
	}
	if _, ok := b.Get(old); !ok {
		t.Fatal("a write from before the removal was lost")
	}
	if got := value(t, b, secret, "value"); got != "new-password" {
		t.Fatalf("B cannot read the new write: %q", got)
	}
	if got := a.Unconfirmed(removal); slices.Contains(got, b.ID()) {
		_, err = a.Sync()
		must(t, err)
		if got := a.Unconfirmed(removal); len(got) != 0 {
			t.Fatalf("still unconfirmed after both synced: %v", got)
		}
	}

	// C cannot read anything written after its removal.
	_, err = c.Sync()
	wantErr(t, err, ErrRemoved)
	g := a.List().Gen
	if blob, _ := w.srv.Get(c.ID(), blobDeviceKey(g.KeyID, c.ID())); blob != nil {
		t.Fatal("the new account key was sealed to the removed device")
	}
	for _, other := range []DeviceID{a.ID(), b.ID()} {
		blob, _ := w.srv.Get(c.ID(), blobDeviceKey(g.KeyID, other))
		if _, err := c.keys.Unwrap.Open(infoDevice(c.Account(), g.Gen, c.ID()), blob); err == nil {
			t.Fatal("the removed device opened a key sealed to another device")
		}
	}
	items, _ := w.srv.Read(c.ID(), logWrites(a.ID()))
	nw, err := ParseWrite(items[len(items)-1])
	must(t, err)
	for _, vk := range c.vaultKeys {
		if _, err := openRecord(vk, nw.header(), nw.Body); err == nil {
			t.Fatal("the removed device opened a write made after its removal")
		}
	}
}

func TestNewDeviceAfterRekeyReadsOldRecords(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	c := w.pair(a, "C", true)
	id, err := a.Create(TypeServer, field("name", "web"), field("address", "10.0.0.9"))
	must(t, err)
	w.syncAll(a, c)
	must(t, a.Remove(c.ID()))
	must(t, a.Remove(w.pair(a, "E", true).ID()))
	d := w.pair(a, "D", true) // joins at key generation 3
	if d.List().Gen.Gen != 3 || len(d.acctKeys) != 3 {
		t.Fatalf("gen %d, keys %d", d.List().Gen.Gen, len(d.acctKeys))
	}
	if got := value(t, d, id, "address"); got != "10.0.0.9" {
		t.Fatalf("D cannot read a generation-1 record: %q", got)
	}
}

func TestYoungDeviceCannotRemoveOlder(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("MacBook")
	w.clk.add(30 * 24 * time.Hour)
	b := w.pair(a, "new iPhone", true)

	wantErr(t, b.Remove(a.ID()), ErrYoungDevice)

	// A forged direct removal (a client that skips its own check) is
	// refused by the older device.
	g, err := newGen(b.List().Gen.Gen + 1)
	must(t, err)
	en := b.nextEntry(Body{Action: ActRemove, Removes: b.removals([]DeviceID{a.ID()}), Key: &g.KeyGen})
	must(t, en.signEntry(b.keys.Authority, RoleAuthority, b.ID(), 0))
	must(t, w.srv.AppendAt(b.ID(), logList, int(en.Num-1), en.Marshal()))
	rep, err := a.Sync() // time only delays: A holds the list at it
	must(t, err)
	if rep.Hold == nil || rep.Hold.Entry != en.Num {
		t.Fatalf("A did not hold a young device's direct removal: %+v", rep.Hold)
	}
	w.srv.SetLog(logList, mustRead(t, w, logList)[:en.Num-1])

	// The young device's way: a removal that waits 7 days, which A sees
	// and cancels.
	num, err := b.RemoveLater(a.ID())
	must(t, err)
	rep, err = a.Sync()
	must(t, err)
	if len(rep.Alerts) == 0 {
		t.Fatal("A was not told about the waiting removal")
	}
	must(t, a.CancelPending(num))
	w.clk.add(WaitYoung)
	_, err = b.Sync()
	must(t, err)
	wantErr(t, b.ApplyPending(num), ErrCancelled)

	// Not cancelled: it applies after 7 days.
	num, err = b.RemoveLater(a.ID())
	must(t, err)
	wantErr(t, b.ApplyPending(num), ErrWaiting)
	_, err = a.Sync() // A sees it wait
	must(t, err)
	w.clk.add(WaitYoung)
	must(t, b.ApplyPending(num))
	_, err = a.Sync()
	wantErr(t, err, ErrRemoved)
}

func mustRead(t *testing.T, w *world, log string) [][]byte {
	items, err := w.srv.MemServer.Read(DeviceID{}, log)
	must(t, err)
	return items
}

// The 7-day rule is counted on each device's own clock (SS 6.2). A device
// that was offline sees "added" and "removed" at the same moment. Time
// only delays, never refuses: it holds the list for its own 7 days and
// then ends where every other device is.
func TestOfflineDeviceHoldsAValidRemoval(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	d := w.pair(a, "D", true) // C is offline from here on
	w.clk.add(WaitYoung + time.Hour)
	w.syncAll(a, b, d)
	must(t, d.Remove(b.ID())) // D is 7 days old on its own clock and on A's
	_, err := a.Sync()
	must(t, err)
	rep, err := c.Sync()
	must(t, err)
	if rep.Hold == nil || c.List().Members[b.ID()] == nil {
		t.Fatalf("C did not hold: %+v", rep.Hold)
	}
	w.clk.add(WaitYoung)
	_, err = c.Sync()
	must(t, err)
	if c.List().Members[b.ID()] != nil || c.Head() != a.Head() {
		t.Fatal("C did not apply the removal after its own wait")
	}
}

func TestAuthorityKeyAfterFaceIDChange(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("MacBook")
	w.clk.add(30 * 24 * time.Hour)
	b := w.pair(a, "iPhone", true)
	w.clk.add(30 * 24 * time.Hour)
	w.syncAll(a, b)

	// Face ID changed on B: its old authority key is gone; it makes a new
	// one and asks for it, but cannot sign it in itself.
	newKey := mustSigner(t)
	req, err := b.AskAuthority(newKey)
	must(t, err)
	wantErr(t, b.SignInAuthority(req), ErrNotAuthorized)

	id, err := a.Create(TypeServer, field("name", "db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, b)
	b.AutoApprove = false
	ref, err := b.Update(id, field("address", "10.0.0.6"))
	must(t, err)
	must(t, b.Approve(ref)) // signed with a key the list does not hold yet
	rep, err := a.Sync()
	must(t, err)
	if rep.Rejected != 1 || value(t, a, id, "address") != "10.0.0.5" {
		t.Fatalf("approval by an unlisted authority key: rejected=%d", rep.Rejected)
	}

	must(t, a.SignInAuthority(req))
	rep, err = b.Sync()
	must(t, err)
	if !strings.Contains(strings.Join(rep.Alerts, "\n"), "new authority key was signed in for this device") {
		t.Fatalf("B was not told its authority key changed: %v", rep.Alerts)
	}
	must(t, b.Approve(ref))
	w.syncAll(a, b)
	if got := value(t, a, id, "address"); got != "10.0.0.6" {
		t.Fatalf("approval by the signed-in key: %q", got)
	}
	// The new key counts as a device added today.
	wantErr(t, b.Remove(a.ID()), ErrYoungDevice)
}

func TestDeviceWithoutAuthorityCannotChangeTheList(t *testing.T) {
	w := newWorld(t)
	phone, _ := w.account("iPhone")
	mini := w.pair(phone, "Mac mini", false)
	wantErr(t, mini.Remove(phone.ID()), ErrNoAuthority)
	_, code, err := StartJoin(w.device("x", true))
	must(t, err)
	wantErr(t, mini.AcceptJoin(code, func(string) bool { return true }), ErrNoAuthority)

	// Its sync key passed off as an authority signature is refused.
	en := mini.nextEntry(Body{Action: ActCancel, Ref: 1})
	must(t, en.signEntry(mini.keys.Sync, RoleAuthority, mini.ID(), 0))
	must(t, w.srv.AppendAt(mini.ID(), logList, int(en.Num-1), en.Marshal()))
	_, err = phone.Sync()
	wantErr(t, err, ErrChainBroken)
}

// B applied a write of C that A had not seen when A removed C. B's signed
// summary from before the removal covers it, so it counts (SS 6.2,
// decided 2026-11-14): B keeps it and A reads it too, past the last write
// A recorded. A server that hides B's summary from before the removal is
// caught by B's summary from after it.
func TestRemovalKeepsWritesASummaryCovered(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	x, err := c.Create(TypeNote, field("text", "C's last word"))
	must(t, err)
	_, err = b.Sync() // B applies it and signs a summary covering it
	must(t, err)
	must(t, a.Remove(c.ID())) // A never saw it
	removal := a.Head()
	rep, err := b.Sync()
	must(t, err)
	if _, ok := b.Get(x); !ok || rep.Revoked != 0 {
		t.Fatalf("B dropped a write it confirmed before the removal (revoked=%d)", rep.Revoked)
	}

	w.srv.OnRead = func(by DeviceID, log string, items [][]byte) [][]byte {
		if by != a.ID() || log != logSummaries(b.ID()) {
			return items
		}
		var out [][]byte
		for _, it := range items {
			if s, err := ParseSummary(it); err == nil && s.ListNum >= removal {
				out = append(out, it)
			}
		}
		return out
	}
	_, err = a.Sync()
	wantErr(t, err, ErrMissingWrites)
	w.srv.OnRead = nil

	w.syncAll(a, b)
	if _, ok := a.Get(x); !ok || a.Records() != b.Records() {
		t.Fatalf("A has %d records, B %d", a.Records(), b.Records())
	}
}

// B applied two writes of C that no remaining device confirmed in a
// summary before the removal: one makes a server protected, which applies
// by itself, the other is a note. A removal at an older write drops both
// on every device and shows them to the person. B had applied the
// stricter value, so it writes it again as its own write, and every
// device ends with it (SS 6.2, decided 2026-11-14; finding 32).
func TestRemovalNeverTakesBackAStricterValue(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	srv, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, b, c)
	_, err = c.Update(srv, field("protected", "true"))
	must(t, err)
	note, err := c.Create(TypeNote, field("text", "after the last confirmed write"))
	must(t, err)
	_, err = b.pull() // B applies both, but its summary never reaches the server
	must(t, err)
	if value(t, b, srv, "protected") != "true" {
		t.Fatal("setup: the stricter value did not apply by itself")
	}
	must(t, a.Remove(c.ID()))
	rep, err := b.Sync()
	must(t, err)
	if rep.Revoked != 2 || rep.Rewritten != 1 {
		t.Fatalf("revoked %d, written again %d; want 2 and 1", rep.Revoked, rep.Rewritten)
	}
	if _, ok := b.Get(note); ok {
		t.Fatal("B kept a write no summary covered")
	}
	if got := b.DroppedWrites(); len(got) != 2 || got[1].Seq != c.ownSeq {
		t.Fatalf("dropped writes shown: %v", got)
	}
	if !strings.Contains(strings.Join(rep.Alerts, "\n"), "were not kept") {
		t.Fatalf("the person was not told: %v", rep.Alerts)
	}
	b.ConfirmDropped()
	if len(b.DroppedWrites()) != 0 {
		t.Fatal("confirmed writes still shown")
	}
	w.syncAll(a, b)
	for _, d := range []*Device{a, b} {
		if value(t, d, srv, "protected") != "true" {
			t.Fatalf("%s: the removal took a stricter value back", d.Name)
		}
	}
}
