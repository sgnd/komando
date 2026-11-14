package syncproto

import (
	"fmt"
	"testing"
)

func BenchmarkSealRecord1KiB(b *testing.B) {
	key, place, p := randomBytes(32), randomBytes(200), randomBytes(1024)
	b.SetBytes(1024)
	for b.Loop() {
		if _, err := sealRecord(key, place, p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenRecord1KiB(b *testing.B) {
	key, place := randomBytes(32), randomBytes(200)
	s, err := sealRecord(key, place, randomBytes(1024))
	must(b, err)
	b.SetBytes(1024)
	for b.Loop() {
		if _, err := openRecord(key, place, s); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignP256(b *testing.B) {
	s, err := NewSoftSigner()
	must(b, err)
	msg := randomBytes(300)
	for b.Loop() {
		if _, err := sign(s, labelWrite, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyP256(b *testing.B) {
	s, err := NewSoftSigner()
	must(b, err)
	msg := randomBytes(300)
	sig, err := sign(s, labelWrite, msg)
	must(b, err)
	for b.Loop() {
		if !verifySig(s.Public(), labelWrite, msg, sig) {
			b.Fatal("verify")
		}
	}
}

func BenchmarkHPKESealXWing(b *testing.B) {
	u, err := NewSoftUnwrapper()
	must(b, err)
	pub, info, key := u.PublicKey(), randomBytes(60), randomBytes(32)
	for b.Loop() {
		if _, err := sealTo(pub, info, key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHPKEOpenXWing(b *testing.B) {
	u, err := NewSoftUnwrapper()
	must(b, err)
	info := randomBytes(60)
	ct, err := sealTo(u.PublicKey(), info, randomBytes(32))
	must(b, err)
	for b.Loop() {
		if _, err := u.Open(info, ct); err != nil {
			b.Fatal(err)
		}
	}
}

// syncWorld is an account whose first device wrote n server records, each
// with its inline yes (two writes per record).
func syncWorld(b *testing.B, n int) (*world, *Device) {
	w := newWorld(b)
	a, _ := w.account("MacBook")
	for i := range n {
		_, err := a.Create(TypeServer, field("name", fmt.Sprintf("server-%04d", i)),
			field("address", fmt.Sprintf("10.0.%d.%d", i/256, i%256)), field("port", "22"), field("user", "deploy"))
		must(b, err)
	}
	_, err := a.Sync()
	must(b, err)
	return w, a
}

// BenchmarkSync1000Records is a new device joining and pulling 1,000
// records (2,000 signed, sealed writes) checked from write 1.
func BenchmarkSync1000Records(b *testing.B) {
	w, a := syncWorld(b, 1000)
	var stored int
	for _, it := range w.srv.AllBytes() {
		stored += len(it)
	}
	for b.Loop() {
		d := w.pair(a, "iPhone", true)
		if d.Records() < 1001 { // 1,000 servers and the name records of the devices
			b.Fatalf("%d records", d.Records())
		}
	}
	b.ReportMetric(float64(stored), "server-bytes")
}

// TestSizes logs the sizes the design doc quotes (go test -v -run TestSizes).
func TestSizes(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("MacBook")
	bdev := w.pair(a, "iPhone", true)
	_, err := a.Create(TypeServer, field("name", "prod-db"), field("address", "10.0.0.5"), field("port", "5432"))
	must(t, err)
	w.syncAll(a, bdev)
	list := mustRead(t, w, logList)
	for i, it := range list {
		t.Logf("list entry %d (%s): %d bytes", i+1, mustEntry(t, it).Body.Action, len(it))
	}
	writes := mustRead(t, w, logWrites(a.ID()))
	for _, it := range writes {
		wr, _ := ParseWrite(it)
		t.Logf("write %d: %d bytes (sealed body %d)", wr.Seq, len(it), len(wr.Body.CT))
	}
	sums := mustRead(t, w, logSummaries(a.ID()))
	t.Logf("summary naming %d devices: %d bytes", 2, len(sums[len(sums)-1]))
	g := a.List().Gen
	key, _ := w.srv.Get(a.ID(), blobDeviceKey(g.KeyID, a.ID()))
	t.Logf("account key sealed to a device (X-Wing HPKE): %d bytes", len(key))
}

// BenchmarkSyncOneChangeOf1000 is a device that already holds 1,000
// records pulling one new change. The prototype server has no "since"
// query, so the device still reads and hashes every stored write.
func BenchmarkSyncOneChangeOf1000(b *testing.B) {
	w, a := syncWorld(b, 1000)
	d := w.pair(a, "iPhone", true)
	id, err := a.Create(TypeNote, field("text", "x"))
	must(b, err)
	i := 0
	for b.Loop() {
		i++
		if _, err := a.Update(id, field("text", fmt.Sprint(i))); err != nil {
			b.Fatal(err)
		}
		if _, err := d.Sync(); err != nil {
			b.Fatal(err)
		}
	}
}
