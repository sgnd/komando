package syncproto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"
)

func TestXWingSuite(t *testing.T) {
	if xwing.ID() != xwingKEMID {
		t.Fatalf("crypto/hpke MLKEM768X25519 has KEM ID %#x, the format names %#x", xwing.ID(), xwingKEMID)
	}
	u, err := NewSoftUnwrapper()
	must(t, err)
	if n := len(u.PublicKey()); n != 1216 {
		t.Fatalf("X-Wing public key is %d bytes", n)
	}
	info := infoDevice(Hash{1}, 1, DeviceID{2})
	ct, err := sealTo(u.PublicKey(), info, []byte("account key"))
	must(t, err)
	if len(ct) != 1120+len("account key")+16 {
		t.Fatalf("sealed size %d", len(ct))
	}
	got, err := u.Open(info, ct)
	must(t, err)
	if string(got) != "account key" {
		t.Fatal("open")
	}
	for _, other := range [][]byte{infoDevice(Hash{1}, 2, DeviceID{2}), infoDevice(Hash{1}, 1, DeviceID{3}), infoDevice(Hash{9}, 1, DeviceID{2})} {
		if _, err := u.Open(other, ct); err == nil {
			t.Fatal("a sealed key opened for another account, generation or device")
		}
	}
}

func TestRecordSealing(t *testing.T) {
	key, place := randomBytes(32), []byte("place")
	for _, n := range []int{0, 1, 100, 1000, 70000} {
		p := randomBytes(n)
		s, err := sealRecord(key, place, p)
		must(t, err)
		got, err := openRecord(key, place, s)
		must(t, err)
		if !bytes.Equal(got, p) {
			t.Fatalf("size %d: round trip", n)
		}
		if len(s.CT) != padme(4+n)+16 {
			t.Fatalf("size %d: sealed %d, want Padmé %d + tag", n, len(s.CT), padme(4+n))
		}
	}
	s, err := sealRecord(key, place, []byte("prod-db 10.0.0.5"))
	must(t, err)
	cases := []struct {
		name string
		key  []byte
		plc  []byte
		mod  func(*sealed)
	}{
		{"other vault key", randomBytes(32), place, nil},
		{"other place", key, []byte("elsewhere"), nil},
		{"flipped ciphertext", key, place, func(s *sealed) { s.CT[0] ^= 1 }},
		{"flipped commitment", key, place, func(s *sealed) { s.Commit[0] ^= 1 }},
		{"other seed", key, place, func(s *sealed) { s.Seed[0] ^= 1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cp := sealed{Seed: s.Seed, Commit: s.Commit, CT: clone(s.CT)}
			if c.mod != nil {
				c.mod(&cp)
			}
			if _, err := openRecord(c.key, c.plc, cp); err != ErrOpen {
				t.Fatalf("got %v, want the one failure answer", err)
			}
		})
	}
	// The commitment check is what refuses another key: the tag differs
	// before AES-GCM runs.
	_, c2 := recordKeys(randomBytes(32), s.Seed[:], place)
	if bytes.Equal(c2, s.Commit[:]) {
		t.Fatal("two keys gave one commitment")
	}
}

func TestPadme(t *testing.T) {
	for l, want := range map[int]int{0: 0, 1: 1, 4: 4, 9: 10, 100: 104, 1000: 1024, 1025: 1088, 70004: 71680} {
		if got := padme(l); got != want {
			t.Errorf("padme(%d) = %d, want %d", l, got, want)
		}
	}
}

func TestSignatureFixedForm(t *testing.T) {
	s := mustSigner(t)
	body := []byte("body")
	for range 20 { // both halves of s come up
		sig, err := sign(s, labelWrite, body)
		must(t, err)
		if !verifySig(s.Public(), labelWrite, body, sig) {
			t.Fatal("does not verify")
		}
		if verifySig(s.Public(), labelSummary, body, sig) {
			t.Fatal("a write signature passed as a summary signature")
		}
		// The other spelling, n - s, verifies as ECDSA but is refused.
		r := new(big.Int).SetBytes(sig[:32])
		hs := new(big.Int).Sub(p256N, new(big.Int).SetBytes(sig[32:]))
		h := sha256.Sum256(signedMessage(labelWrite, body))
		if !ecdsa.Verify(s.Public(), h[:], r, hs) {
			t.Fatal("test setup: high-s form should verify as plain ECDSA")
		}
		var high Sig
		r.FillBytes(high[:32])
		hs.FillBytes(high[32:])
		if verifySig(s.Public(), labelWrite, body, high) {
			t.Fatal("the high-s spelling was accepted")
		}
	}
	if verifySig(s.Public(), labelWrite, body, Sig{}) {
		t.Fatal("zero signature accepted")
	}
}

func TestCanonicalEncoding(t *testing.T) {
	w := newWorld(t)
	a, _ := w.account("A")
	for _, it := range mustRead(t, w, logList) {
		en := mustEntry(t, it)
		if !bytes.Equal(en.Marshal(), it) {
			t.Fatal("entry does not round trip")
		}
		if _, err := ParseEntry(append(clone(it), 0)); err == nil {
			t.Fatal("trailing byte accepted")
		}
		if _, err := ParseEntry(it[:len(it)-1]); err == nil {
			t.Fatal("short entry accepted")
		}
	}
	items, _ := w.srv.Read(a.ID(), logWrites(a.ID()))
	if _, err := ParseWrite(append(clone(items[0]), 0)); err == nil {
		t.Fatal("trailing byte accepted on a write")
	}
}

func TestGF256AndShamir(t *testing.T) {
	if got := gfMul(0x57, 0x83); got != 0xc1 { // FIPS-197 section 4.2
		t.Fatalf("0x57*0x83 = %#x", got)
	}
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("inverse of %#x", a)
		}
	}
	secret := randomBytes(32)
	for _, nk := range [][2]int{{3, 2}, {5, 3}, {2, 2}} {
		shares, err := shamirSplit(secret, nk[0], nk[1])
		must(t, err)
		xs := []byte{}
		var sub [][]byte
		for i := nk[0] - nk[1]; i < nk[0]; i++ {
			xs = append(xs, byte(i+1))
			sub = append(sub, shares[i])
		}
		got, err := shamirCombine(xs, sub)
		must(t, err)
		if !bytes.Equal(got, secret) {
			t.Fatalf("%v: wrong secret", nk)
		}
	}
}

func TestPairingCode(t *testing.T) {
	secret := randomBytes(16)
	code := encode32(secret)
	if len(code) != 26 {
		t.Fatalf("%d characters", len(code))
	}
	got, err := decode32(strings.ToLower(code), 16)
	must(t, err)
	if !bytes.Equal(got, secret) {
		t.Fatal("round trip")
	}
	// The last character carries two spare bits that must be zero: one
	// typo in four there is caught; elsewhere a typo shows only as a
	// failed check code (the one try is used).
	last := strings.IndexByte(alphabet32, code[25])
	bad := code[:25] + string(alphabet32[last^1])
	if _, err := decode32(bad, 16); err == nil {
		t.Fatal("non-zero spare bits accepted")
	}
}

func TestSoftSignerPresence(t *testing.T) {
	s := mustSigner(t)
	s.Presence = func() error { return ErrDeclined }
	if _, err := sign(s, labelEntry, nil); err != ErrDeclined {
		t.Fatalf("Face ID refused but signed: %v", err)
	}
	s.Presence = nil
	if _, err := sign(s, labelEntry, nil); err != nil || s.Signatures() != 1 {
		t.Fatalf("signatures %d err %v", s.Signatures(), err)
	}
	_ = rand.Reader
}
