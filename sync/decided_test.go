package komandosync

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Tests for the owner's decisions of 2026-11-14 (SS 6.1 to 7.1; findings
// 18, 22, 25 and 26 in sync-prototype.md).

// listDown is a server whose device list cannot be read.
type listDown struct{ Server }

var errDown = errors.New("the service does not answer")

func (s listDown) Read(by DeviceID, log string) ([][]byte, error) {
	if log == logList {
		return nil, errDown
	}
	return s.Server.Read(by, log)
}

// A typo in the pairing code is caught by the check character on the
// existing device, before it reads anything from the server, so the one
// try is still there for the right code (SS 6.3).
func TestPairingTypoCaughtBeforeTheTry(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	nd := w.device("iPad", true)
	j, code, err := StartJoin(nd)
	must(t, err)
	gets := 0
	w.srv.OnGet = func(_ DeviceID, name string, data []byte) []byte {
		if strings.HasPrefix(name, "pair/") {
			gets++
		}
		return data
	}
	for i := range len(code) {
		c := alphabet32[(strings.IndexByte(alphabet32, code[i])+7)%32]
		bad := code[:i] + string(c) + code[i+1:]
		wantErr(t, a.AcceptJoin(bad, func(string) bool { return true }), ErrPairingTypo)
	}
	if gets != 0 {
		t.Fatalf("a typo reached the server %d times", gets)
	}
	must(t, a.AcceptJoin(code, func(string) bool { return true }))
	_, err = j.Finish()
	must(t, err)
}

// A kit step on a listed device waits 24 hours while another device is
// listed: here the kit signs in a device's own new authority key. The new
// key signs nothing until the device applies it; alone on the list it
// applies at once (SS 6.1, 6.4).
func TestAuthoritySignInWithKitWaits(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	b := w.pair(a, "iPhone", true)
	id, err := a.Create(TypeServer, field("name", "db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(a, b)

	req, err := b.AskAuthority(mustSigner(t)) // Face ID changed on B
	must(t, err)
	_, err = a.SignInAuthorityWithKit(kit, req)
	wantErr(t, err, ErrNotAuthorized) // only the device that asked
	num, err := b.SignInAuthorityWithKit(kit, req)
	must(t, err)
	if num == 0 {
		t.Fatal("the kit signed a key in at once while another device is listed")
	}
	b.AutoApprove = false
	ref, err := b.Update(id, field("address", "10.0.0.6"))
	must(t, err)
	must(t, b.Approve(ref)) // with the key that is not in yet
	rep, err := a.Sync()
	must(t, err)
	if rep.Rejected != 1 || !strings.Contains(strings.Join(rep.Alerts, "\n"), "recovery key was used") {
		t.Fatalf("A: rejected %d, alerts %v", rep.Rejected, rep.Alerts)
	}
	wantErr(t, b.ApplyPending(num), ErrWaiting)
	w.clk.add(WaitRecovery + time.Minute)
	must(t, b.ApplyPending(num))
	must(t, b.Approve(ref))
	rep, err = a.Sync()
	must(t, err)
	if !strings.Contains(strings.Join(rep.Alerts, "\n"), "new authority key was signed in") {
		t.Fatalf("A not told of the new key: %v", rep.Alerts)
	}
	w.syncAll(a, b)
	if got := value(t, a, id, "address"); got != "10.0.0.6" {
		t.Fatalf("approval by the key signed in with the kit: %q", got)
	}

	// Alone on the list, the kit signs the key in at once.
	solo, kit2 := newWorld(t).account("solo")
	req, err = solo.AskAuthority(mustSigner(t))
	must(t, err)
	num, err = solo.SignInAuthorityWithKit(kit2, req)
	must(t, err)
	if num != 0 {
		t.Fatalf("alone, the sign-in waits (entry %d)", num)
	}
}

// A device listed less than 7 days ago signs in an older device's new
// key only as a change that waits 7 days (SS 6.1).
func TestYoungDeviceSignsInLater(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("MacBook")
	w.clk.add(30 * 24 * time.Hour)
	d := w.pair(a, "new iPad", true)
	w.syncAll(a, d)
	req, err := a.AskAuthority(mustSigner(t))
	must(t, err)
	wantErr(t, d.SignInAuthority(req), ErrYoungDevice)
	num, err := d.SignInAuthorityLater(req)
	must(t, err)
	wantErr(t, d.ApplyPending(num), ErrWaiting)
	_, err = a.Sync()
	must(t, err)
	w.clk.add(WaitYoung + time.Minute)
	must(t, d.ApplyPending(num))
	if got := d.List().Members[a.ID()].Rec.AuthPub; string(got) != string(req.NewAuth) {
		t.Fatal("the waited sign-in did not apply")
	}
}

// Before sealing a secret a device refreshes the list, so it seals under
// the newest key; when the list cannot be read it asks the person (SS 7.1).
func TestSecretWriteRefreshesTheList(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	must(t, a.Remove(c.ID()))
	// B has not synced since; a note goes out under the key B holds, a
	// secret under the newest.
	_, err := b.Create(TypeNote, field("text", "a note"))
	must(t, err)
	if b.log[len(b.log)-1].w.KeyGen != 1 {
		t.Fatal("setup: a note should not refresh the list")
	}
	_, err = b.Create(TypeSecret, field("name", "db-pass"), field("value", "s3cret"))
	must(t, err)
	if g := b.log[len(b.log)-1].w.KeyGen; g != 2 {
		t.Fatalf("the secret was sealed under generation %d", g)
	}

	b.srv = listDown{w.srv}
	_, err = b.Create(TypeSecret, field("name", "api-key"), field("value", "x"))
	wantErr(t, err, ErrListUnchecked)
	asked := false
	b.ConfirmUnchecked = func(err error) bool { asked = errors.Is(err, errDown); return true }
	_, err = b.Create(TypeSecret, field("name", "api-key"), field("value", "x"))
	must(t, err)
	if !asked {
		t.Fatal("the person was not asked")
	}
}

// A server holds B on the list from before a removal. B's secret goes out
// under the old key, which the removed device can open: every device
// accepts it with an alert. Once B catches up it seals the write again
// under the newest key (SS 7.1).
func TestWriteUnderASupersededKey(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	held := len(mustRead(t, w, logList))
	w.srv.OnRead = func(by DeviceID, log string, items [][]byte) [][]byte {
		if by == b.ID() && log == logList {
			return items[:held]
		}
		return items
	}
	must(t, a.Remove(c.ID()))
	id, err := b.Create(TypeSecret, field("name", "db-pass"), field("value", "s3cret"))
	must(t, err)
	if b.log[len(b.log)-1].w.KeyGen != 1 {
		t.Fatal("setup: B should still seal under generation 1")
	}
	rep, err := a.Sync()
	must(t, err)
	if rep.OldKey != 2 || value(t, a, id, "value") != "s3cret" { // the secret and B's yes to it
		t.Fatalf("A: old-key writes %d, value %q", rep.OldKey, value(t, a, id, "value"))
	}
	if !strings.Contains(strings.Join(rep.Alerts, "\n"), "a removed device can read them") {
		t.Fatalf("A was not alerted: %v", rep.Alerts)
	}

	w.srv.OnRead = nil
	rep, err = b.Sync()
	must(t, err)
	last := b.log[len(b.log)-1]
	if rep.Resealed != 1 || last.c.Kind != kindReseal || last.w.KeyGen != 2 {
		t.Fatalf("B did not seal it again: resealed %d", rep.Resealed)
	}
	rep, err = a.Sync()
	must(t, err)
	if rep.Rejected != 0 || rep.OldKey != 0 || value(t, a, id, "value") != "s3cret" {
		t.Fatalf("A: rejected %d, old-key %d", rep.Rejected, rep.OldKey)
	}

	// A reseal that does not copy its writer's earlier write is refused.
	bad := *last.c
	bad.Fields = []Field{field("value", "changed")}
	_, err = b.write(&bad)
	must(t, err)
	rep, err = a.Sync()
	must(t, err)
	if rep.Rejected != 1 || value(t, a, id, "value") != "s3cret" {
		t.Fatalf("a changed reseal: rejected %d, value %q", rep.Rejected, value(t, a, id, "value"))
	}
}
