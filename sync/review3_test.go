package komandosync

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// Tests for the third review of 2026-11-14 (findings 34 to 38 in
// sync-prototype.md). Each one fails on the code before its fix.

// A thief starts two takeovers with one kit. The person cancels one and
// replaces the kits. The second takeover was signed by the replaced kit,
// so it ends with it: its own client says so, and a hand-built apply is
// refused by every device (SS 6.4).
func TestReplacedKitEndsItsTakeover(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("iPhone")
	n1 := w.device("thief 1", true)
	r1, err := OpenWithKit(n1, kit)
	must(t, err)
	must(t, r1.Begin(1))
	n2 := w.device("thief 2", true)
	r2, err := OpenWithKit(n2, kit)
	must(t, err)
	must(t, r2.Begin(1))
	_, err = a.Sync()
	must(t, err)
	must(t, a.CancelPending(r1.Pending()))
	_, num, err := a.ReplaceKits(1, kit)
	must(t, err)
	if num != 0 {
		t.Fatalf("alone on the list, the kits are replaced at once; got pending entry %d", num)
	}
	rep, err := a.Sync()
	must(t, err)
	for _, al := range rep.Alerts {
		if strings.Contains(al, "take the account over") {
			t.Fatalf("the ended takeover is still shown: %q", al)
		}
	}
	w.clk.add(WaitRecovery + time.Minute)
	_, err = r2.Finish()
	wantErr(t, err, ErrKitReplaced)

	// A modified client builds the apply by hand.
	d := n2
	g, err := newGen(d.list.Gen.Gen + 1)
	must(t, err)
	en := d.nextEntry(Body{Action: ActApply, Ref: r2.Pending(), Removes: d.removals(d.memberIDs()), Key: &g.KeyGen})
	must(t, en.signEntry(d.keys.Authority, RoleRequester, d.id, 0))
	must(t, w.srv.AppendAt(d.id, logList, int(en.Num-1), en.Marshal()))
	_, err = a.Sync()
	wantErr(t, err, ErrChainBroken)
}

// A stolen Mac without Touch ID starts two recovery steps that remove the
// iPhone. The iPhone cancels one and replaces the kits. The other step
// was signed by the replaced kit and never applies.
func TestReplacedKitEndsItsRecoveryStep(t *testing.T) {
	w := newWorld(t)
	phone, kit := w.account("iPhone")
	mini := w.pair(phone, "stolen Mac mini", false)
	w.syncAll(phone, mini)
	_, n1, err := mini.RecoveryStep(kit, []DeviceID{phone.ID()}, 1)
	must(t, err)
	_, n2, err := mini.RecoveryStep(kit, []DeviceID{phone.ID()}, 1)
	must(t, err)
	_, err = phone.Sync()
	must(t, err)
	must(t, phone.CancelPending(n1))
	_, pend, err := phone.ReplaceKits(1, kit)
	must(t, err)
	w.clk.add(WaitRecovery + time.Minute)
	must(t, phone.ApplyPending(pend))
	if p := phone.List().Pending[n2]; p == nil || !p.KitGone {
		t.Fatalf("the step signed by the replaced kit is still waiting: %+v", p)
	}
	_, err = mini.Sync() // the Mac first waits out the kit change on its own clock
	must(t, err)
	w.clk.add(WaitRecovery + time.Minute)
	_, err = mini.Sync()
	must(t, err)
	wantErr(t, mini.ApplyPending(n2), ErrKitReplaced)
	_, err = phone.Sync()
	must(t, err)
	if phone.List().Members[phone.ID()] == nil {
		t.Fatal("the iPhone was removed by a step the replaced kit signed")
	}
}

// A write that was dropped and confirmed as dropped comes back when a
// signed summary from before the removal raises the cut. The person is
// told, and confirms again (SS 6.2: never silently).
func TestKeptAgainIsShown(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	m := w.pair(a, "Mac mini", false)
	x := w.pair(a, "iPad", true)
	srv, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, m, x)
	oldNum, oldHash := m.head, m.headHash
	must(t, a.Remove(x.ID()))
	_, err = x.Update(srv, field("address", "203.0.113.9"))
	must(t, err)
	_, err = a.Sync()
	must(t, err)
	if len(a.DroppedWrites()) == 0 {
		t.Fatal("the late write was not shown as dropped")
	}
	a.ConfirmDropped()

	// A summary signed with M's sync key, naming the entry from before the
	// removal, covers X's late writes.
	s := &Summary{Account: m.account, Signer: m.id, Num: m.sumNum[m.id] + 1, KeyGen: 1,
		ListNum: oldNum, ListHash: oldHash, MinClient: minClient}
	for id, h := range m.applied {
		if id != x.id {
			s.Heads = append(s.Heads, h)
		}
	}
	s.Heads = append(s.Heads, x.applied[x.id])
	slices.SortFunc(s.Heads, func(p, q Head) int { return strings.Compare(string(p.Device[:]), string(q.Device[:])) })
	s.Sig, err = sign(m.keys.Sync, labelSummary, s.signedBytes())
	must(t, err)
	must(t, w.srv.Append(m.id, logSummaries(m.id), s.Marshal()))
	rep, err := a.Sync()
	must(t, err)
	if len(a.KeptAgain()) == 0 || !slices.ContainsFunc(rep.Alerts, func(al string) bool { return strings.Contains(al, "now kept") }) {
		t.Fatalf("writes shown as not kept came back without a word: kept again %v, alerts %v", a.KeptAgain(), rep.Alerts)
	}
	a.ConfirmDropped()
	if len(a.KeptAgain()) != 0 {
		t.Fatal("confirming does not clear the kept-again writes")
	}
}

// The list moves forward outside Sync, here when B saves a secret. B's
// next Sync still seals its note from before the removal again under the
// newest key, and still shows a new device (SS 6.3, 7.1).
func TestListRefreshOutsideSyncStillAlertsAndReseals(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", false)
	w.syncAll(a, b, c)
	held := len(mustRead(t, w, logList))
	w.srv.OnRead = func(by DeviceID, log string, items [][]byte) [][]byte {
		if by == b.ID() && log == logList {
			return items[:held]
		}
		return items
	}
	must(t, a.Remove(c.ID()))
	_, err := b.Create(TypeNote, field("text", "written while behind"))
	must(t, err)
	w.srv.OnRead = nil
	_, err = b.Create(TypeSecret, field("name", "db-pass"), field("value", "s3cret"))
	must(t, err)
	rep, err := b.Sync()
	must(t, err)
	if rep.Resealed != 1 {
		t.Fatalf("resealed %d writes, want the 1 note written while behind", rep.Resealed)
	}

	w.pair(a, "D", false)
	_, err = b.Create(TypeSecret, field("name", "api-key"), field("value", "x"))
	must(t, err)
	rep, err = b.Sync()
	must(t, err)
	if !slices.ContainsFunc(rep.Alerts, func(al string) bool { return strings.Contains(al, "A new device was added") }) {
		t.Fatalf("the new device was not shown: %v", rep.Alerts)
	}
}
