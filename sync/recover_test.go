package komandosync

import (
	"strings"
	"testing"
	"time"
)

func TestKitLettersAndPaper(t *testing.T) {
	k, err := NewKit()
	must(t, err)
	letters := k.Letters()
	if g := strings.Fields(letters); len(g) != 14 || len(g[0]) != 4 {
		t.Fatalf("letters: %q", letters)
	}
	back, err := ParseKit(strings.ToLower(strings.ReplaceAll(letters, " ", "-")))
	must(t, err)
	if back.key != k.key {
		t.Fatal("letters do not give the key back")
	}
	// Every single-character typo is caught.
	flat := strings.ReplaceAll(letters, " ", "")
	for i := range flat {
		c := byte('0')
		if flat[i] == '0' {
			c = '1'
		}
		typo := flat[:i] + string(c) + flat[i+1:]
		if _, err := ParseKit(typo); err == nil {
			t.Fatalf("typo at %d not caught", i)
		}
	}
	parts, err := k.Paper()
	must(t, err)
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}, {2, 0}} {
		got, err := KitFromPaper(parts[pair[0]], parts[pair[1]])
		must(t, err)
		if got.key != k.key {
			t.Fatalf("parts %v do not give the key back", pair)
		}
	}
	if got, err := KitFromPaper(parts[0]); err == nil && got.key == k.key {
		t.Fatal("one part alone gave the key")
	}
	if _, err := KitFromPaper(parts[0], parts[0]); err == nil {
		t.Fatal("the same part twice was accepted")
	}
	bad := []byte(parts[1])
	bad[5] ^= 1
	if _, err := KitFromPaper(parts[0], string(bad)); err == nil {
		t.Fatal("a damaged part was accepted")
	}
}

func TestRecoveryOnNewDeviceWaits24Hours(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	b := w.pair(a, "iPhone", true)
	id, err := a.Create(TypeSecret, field("name", "db-pass"), field("value", "hunter2"))
	must(t, err)
	w.syncAll(a, b)

	n := w.device("new iPhone", true)
	r, err := OpenWithKit(n, kit)
	must(t, err)
	if r.Info.Devices != 2 || r.Info.Records != a.Records() || r.Info.LastWriter == (DeviceID{}) {
		t.Fatalf("recovery info: %+v", r.Info)
	}
	// It reads at once: the 24 hours guard the account, not the data.
	if got := value(t, n, id, "value"); got != "hunter2" {
		t.Fatalf("kit device cannot read: %q", got)
	}
	must(t, r.Begin(2))
	_, err = b.Sync()
	must(t, err)
	rep, err := a.Sync()
	must(t, err)
	if len(rep.Alerts) == 0 || !strings.Contains(strings.Join(rep.Alerts, "\n"), "recovery key was used") {
		t.Fatalf("live device not told: %v", rep.Alerts)
	}
	_, err = r.Finish()
	wantErr(t, err, ErrWaiting)

	// A writes during the wait; the takeover keeps it.
	late, err := a.Create(TypeNote, field("text", "during the wait"))
	must(t, err)
	_, err = a.Sync()
	must(t, err)
	w.clk.add(WaitRecovery)
	kits, err := r.Finish()
	must(t, err)
	if len(kits) != 2 {
		t.Fatalf("%d new kits", len(kits))
	}
	if _, ok := n.Get(late); !ok {
		t.Fatal("a write made during the wait was dropped")
	}
	for _, d := range []*Device{a, b} {
		_, err := d.Sync()
		wantErr(t, err, ErrRemoved)
	}
	// The old kit ended; a new one works.
	_, err = OpenWithKit(w.device("x", true), kit)
	wantErr(t, err, ErrKitUnknown)
	_, err = OpenWithKit(w.device("y", true), kits[1])
	must(t, err)
}

func TestRecoveryCancelledByLiveDevice(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	n := w.device("thief's phone", true)
	r, err := OpenWithKit(n, kit)
	must(t, err)
	must(t, r.Begin(1))
	_, err = a.Sync()
	must(t, err)
	must(t, a.CancelPending(r.Pending()))
	w.clk.add(WaitRecovery)
	_, err = r.Finish()
	wantErr(t, err, ErrCancelled)
	_, err = a.Sync()
	must(t, err)
	if len(a.List().Members) != 1 {
		t.Fatal("the cancelled takeover changed the list")
	}
}

// A server that also holds the kit hides the waiting takeover from the
// live device until it is applied. The live device sees both at once and
// holds the list for its own 24 hours: detected, shown, but it has no
// entry left to cancel with. sync-prototype.md lists this.
func TestHiddenRecoveryWaitIsHeld(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	_, err := a.Sync()
	must(t, err)
	shown := len(mustRead(t, w, logList))
	w.srv.OnRead = func(by DeviceID, l string, items [][]byte) [][]byte {
		if by == a.ID() && l == logList {
			return items[:shown]
		}
		return items
	}
	n := w.device("thief's phone", true)
	r, err := OpenWithKit(n, kit)
	must(t, err)
	must(t, r.Begin(1))
	w.clk.add(WaitRecovery)
	_, err = r.Finish()
	must(t, err)

	w.srv.OnRead = nil
	rep, err := a.Sync()
	must(t, err)
	if rep.Hold == nil || len(rep.Alerts) == 0 {
		t.Fatalf("the late takeover was not held: %+v", rep)
	}
	w.clk.add(WaitRecovery)
	_, err = a.Sync()
	wantErr(t, err, ErrRemoved)
}

func TestRecoveryStepOnListedDevice(t *testing.T) {
	w := newWorld(t)
	phone, kit := w.account("iPhone")
	mini := w.pair(phone, "Mac mini", false)
	w.syncAll(phone, mini)
	// The iPhone is lost; the Mac has no Touch ID, so the kit signs.
	kits, err := mini.RecoveryStep(kit, []DeviceID{phone.ID()}, 3)
	must(t, err)
	if len(mini.List().Members) != 1 || len(mini.List().Kits) != 3 {
		t.Fatalf("members %d kits %d", len(mini.List().Members), len(mini.List().Kits))
	}
	_, err = phone.Sync()
	wantErr(t, err, ErrRemoved)
	_, err = mini.RecoveryStep(kit, nil, 1)
	wantErr(t, err, ErrKitUnknown)
	for _, k := range kits {
		_, err = OpenWithKit(w.device("spare", true), k)
		must(t, err)
	}
}

func TestReplaceKits(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	_, err := a.ReplaceKits(MaxKits+1, kit)
	if err == nil {
		t.Fatal("more than 3 kits")
	}
	_, err = a.ReplaceKits(1, nil)
	wantErr(t, err, ErrNotAuthorized) // the current key must be typed
	kits, err := a.ReplaceKits(3, kit)
	must(t, err)
	_, err = OpenWithKit(w.device("x", true), kit)
	wantErr(t, err, ErrKitUnknown)
	// The old kit cannot read past the replacement either: the current key
	// generation was never sealed to it.
	g := a.List().Gen
	if blob, _ := w.srv.Get(a.ID(), blobKitKey(g.KeyID, kit.Record())); blob != nil {
		t.Fatal("the current account key is sealed to a replaced kit")
	}
	if g.Gen != 2 {
		t.Fatalf("kit replacement left key generation %d", g.Gen)
	}

	// Lost kits: 7 days, cancellable.
	lost, num, err := a.ReplaceLostKits(1)
	must(t, err)
	wantErr(t, a.ApplyPending(num), ErrWaiting)
	w.clk.add(WaitKitLost)
	must(t, a.ApplyPending(num))
	_, err = OpenWithKit(w.device("y", true), kits[0])
	wantErr(t, err, ErrKitUnknown)
	_, err = OpenWithKit(w.device("z", true), lost[0])
	must(t, err)
}

func TestKitOfAnotherAccountIsRefused(t *testing.T) {
	w := newWorld(t)
	w.account("A")
	other := newWorld(t)
	_, kit := other.account("B")
	_, err := OpenWithKit(w.device("x", true), kit)
	wantErr(t, err, ErrKitUnknown)
}

func TestRecoveryAfterAllDevicesLost(t *testing.T) {
	w := newWorld(t)
	a, kit := w.account("MacBook")
	parts, err := kit.Paper()
	must(t, err)
	id, err := a.Create(TypeServer, field("name", "web"), field("address", "10.0.0.7"))
	must(t, err)
	_, err = a.Sync()
	must(t, err)
	// Every device is gone; two of three paper parts are left.
	k2, err := KitFromPaper(parts[2], parts[0])
	must(t, err)
	n := w.device("new Mac", true)
	r, err := OpenWithKit(n, k2)
	must(t, err)
	must(t, r.Begin(1))
	w.clk.add(WaitRecovery + time.Minute)
	_, err = r.Finish()
	must(t, err)
	_, err = n.Sync()
	must(t, err)
	if got := value(t, n, id, "address"); got != "10.0.0.7" {
		t.Fatalf("after recovery: %q", got)
	}
}
