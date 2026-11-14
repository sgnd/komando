package komandosync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorsFile = "testdata/vectors.json"

// Vectors are known answers for the parts a second implementation (the
// Swift side, or a reviewer's) must match byte for byte. Values made with
// randomness (HPKE encapsulation, ECDSA nonces) are checked by opening and
// verifying them; everything else must come out exactly the same.
//
// This file only pins the prototype against regressions: its values come
// from the prototype's own code. Two outside checks stand behind them:
// testdata/crosscheck.swift recomputes every value with Apple CryptoKit, a
// separate implementation, and external_test.go checks the building blocks
// against published vectors (RFC 5869, draft-ietf-hpke-pq X-Wing, FIPS-197
// for GF(256) in crypto_test.go).
type vectors struct {
	Note        string            `json:"note"`
	Record      recordVector      `json:"record_seal"`
	Padme       map[string]int    `json:"padme"`
	KeyID       map[string]string `json:"key_id"`
	Kit         kitVector         `json:"recovery_kit"`
	Shamir      shamirVector      `json:"kit_paper_2_of_3"`
	HPKE        hpkeVector        `json:"hpke_xwing"`
	Signature   sigVector         `json:"ecdsa_p256_fixed_form"`
	Entry       entryVector       `json:"list_entry"`
	PairingCode map[string]string `json:"pairing_code"`
}

type recordVector struct {
	VaultKey, Seed, Place, Plaintext string
	Commit, Ciphertext               string
}

type kitVector struct {
	Key, Letters, SignPub, SealPub string
	SealSeed                       string // the X-Wing seed DeriveKeyPair gives
	Challenge                      [2]int
}

type shamirVector struct {
	Secret string
	Parts  [3]string
}

type hpkeVector struct {
	KEMID                      int
	IKM, Seed, PublicKey, Info string
	Plaintext, Ciphertext      string
}

type sigVector struct {
	Scalar, PublicKey, Label, Body, Sig string
}

type entryVector struct {
	SignedBytes, Hash string
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func unhx(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	must(t, err)
	return b
}

func seq(start, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i)
	}
	return b
}

// deterministic computes every vector that has one right answer.
func deterministic(t *testing.T) vectors {
	var v vectors
	v.Note = "komando sync prototype, suite 1. Regression values from the prototype, recomputed by crosscheck.swift (Apple CryptoKit). See docs/design/sync-prototype.md. Hex unless said."
	vk, place, plain := seq(0, 32), []byte("komando test place"), []byte("prod-db 10.0.0.5")
	s := sealRecordSeed(vk, place, plain, [32]byte(seq(32, 32)))
	v.Record = recordVector{hx(vk), hx(s.Seed[:]), hx(place), hx(plain), hx(s.Commit[:]), hx(s.CT)}
	v.Padme = map[string]int{}
	for _, l := range []int{1, 9, 100, 1000, 70004} {
		v.Padme[hx([]byte{byte(l >> 16), byte(l >> 8), byte(l)})] = padme(l)
	}
	id := keyID(seq(64, 32))
	v.KeyID = map[string]string{"account_key": hx(seq(64, 32)), "key_id": hx(id[:])}
	k, err := KitFromKey([32]byte(seq(96, 32)))
	must(t, err)
	r := k.Record()
	seed, err := k.seal.Bytes()
	must(t, err)
	v.Kit = kitVector{hx(k.key[:]), k.Letters(), hx(r.SignPub), hx(r.SealPub), hx(seed), k.Challenge()}
	v.Shamir.Secret = hx(k.key[:])
	v.HPKE = hpkeVector{KEMID: xwingKEMID, IKM: hx(seq(128, 32)), Info: hx(infoDevice(Hash{1}, 1, DeviceID{2})),
		Plaintext: hx(seq(160, 32))}
	sk, err := xwing.DeriveKeyPair(seq(128, 32))
	must(t, err)
	v.HPKE.PublicKey = hx(sk.PublicKey().Bytes())
	hs, err := sk.Bytes()
	must(t, err)
	v.HPKE.Seed = hx(hs)
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seq(1, 32))
	must(t, err)
	v.Signature = sigVector{Scalar: hx(seq(1, 32)), PublicKey: hx(pubBytes(&priv.PublicKey)), Label: labelWrite,
		Body: hx([]byte("body"))}
	en := Entry{Num: 2, Prev: Hash(seq(200, 32)), Body: Body{Action: ActSetKits, Kits: []KitRecord{r}}}
	v.Entry = entryVector{hx(en.signedBytes()), hx(func() []byte { h := en.Hash(); return h[:] }())}
	v.PairingCode = map[string]string{"secret": hx(seq(5, 16)), "code": pairCode(seq(5, 16))}
	return v
}

func TestVectors(t *testing.T) {
	want := deterministic(t)
	if *update {
		k, _ := KitFromKey([32]byte(seq(96, 32)))
		parts, err := k.Paper()
		must(t, err)
		want.Shamir.Parts = parts
		pk, _ := xwing.NewPublicKey(unhx(t, want.HPKE.PublicKey))
		ct, err := hpke.Seal(pk, hpkeKDF, hpkeAEAD, unhx(t, want.HPKE.Info), unhx(t, want.HPKE.Plaintext))
		must(t, err)
		want.HPKE.Ciphertext = hx(ct)
		priv, _ := ecdsa.ParseRawPrivateKey(elliptic.P256(), seq(1, 32))
		sig, err := sign(kitSigner{priv}, labelWrite, []byte("body"))
		must(t, err)
		want.Signature.Sig = hx(sig[:])
		b, err := json.MarshalIndent(want, "", "  ")
		must(t, err)
		must(t, os.WriteFile(vectorsFile, append(b, '\n'), 0o644))
		return
	}
	b, err := os.ReadFile(vectorsFile)
	must(t, err)
	var got vectors
	must(t, json.Unmarshal(b, &got))
	// Random parts: check them by use, then compare the rest exactly.
	k, err := KitFromPaper(got.Shamir.Parts[1], got.Shamir.Parts[2])
	must(t, err)
	if hx(k.key[:]) != want.Shamir.Secret {
		t.Error("kit paper parts do not give the kit back")
	}
	sk, _ := xwing.DeriveKeyPair(unhx(t, got.HPKE.IKM))
	pt, err := hpke.Open(sk, hpkeKDF, hpkeAEAD, unhx(t, got.HPKE.Info), unhx(t, got.HPKE.Ciphertext))
	if err != nil || hx(pt) != want.HPKE.Plaintext {
		t.Errorf("HPKE vector does not open: %v", err)
	}
	pub := parsePub(unhx(t, got.Signature.PublicKey))
	if !verifySig(pub, got.Signature.Label, unhx(t, got.Signature.Body), Sig(unhx(t, got.Signature.Sig))) {
		t.Error("signature vector does not verify")
	}
	want.Shamir.Parts, want.HPKE.Ciphertext, want.Signature.Sig = got.Shamir.Parts, got.HPKE.Ciphertext, got.Signature.Sig
	a, _ := json.Marshal(want)
	g, _ := json.Marshal(got)
	if string(a) != string(g) {
		t.Errorf("vectors differ from %s; if the change is meant, run go test -run TestVectors -update", vectorsFile)
	}
}
