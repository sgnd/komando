package komandosync

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
)

// Known answers from outside this prototype, for the building blocks the
// format names. vectors.json only pins regressions; these check that the
// blocks are the standard ones.

// RFC 5869, appendix A, test cases 1 and 3 (HKDF-SHA256). derive() is case
// 3: no salt and no info besides the label.
func TestExternalHKDF(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	okm, err := hkdf.Key(sha256.New, ikm, seq(0x00, 13), string(seq(0xf0, 10)), 42)
	must(t, err)
	if hx(okm) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
		t.Errorf("RFC 5869 case 1: %x", okm)
	}
	if got := hx(derive(ikm, "", 42)); got != "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8" {
		t.Errorf("RFC 5869 case 3: %s", got)
	}
}

// draft-ietf-hpke-pq: X-Wing DeriveKeyPair (used for kit sealing keys and
// the account sealing key), decapsulation and the HKDF-SHA256 key schedule.
// No published vector has X-Wing with AES-256-GCM; the AEAD here is
// ChaCha20-Poly1305, and crosscheck.swift opens the exact suite.
func TestExternalXWing(t *testing.T) {
	b, err := os.ReadFile("testdata/xwing_draft_vector.json")
	must(t, err)
	var v struct {
		KEM                int `json:"kem_id"`
		IKMR, SKRm, PKRm   string
		Enc, Info, AAD, PT string
		CT                 string
	}
	must(t, json.Unmarshal(b, &v))
	if v.KEM != xwingKEMID {
		t.Fatalf("vector KEM %#x", v.KEM)
	}
	sk, err := xwing.DeriveKeyPair(unhx(t, v.IKMR))
	must(t, err)
	seed, err := sk.Bytes()
	must(t, err)
	if hx(seed) != v.SKRm || hx(sk.PublicKey().Bytes()) != v.PKRm {
		t.Fatal("X-Wing DeriveKeyPair differs from the draft")
	}
	r, err := hpke.NewRecipient(unhx(t, v.Enc), sk, hpkeKDF, hpke.ChaCha20Poly1305(), unhx(t, v.Info))
	must(t, err)
	pt, err := r.Open(unhx(t, v.AAD), unhx(t, v.CT))
	if err != nil || hx(pt) != v.PT {
		t.Fatalf("draft encryption does not open: %v", err)
	}
}
