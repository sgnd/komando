package komandosync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	Snapshot    snapshotVector    `json:"snapshot"`
	DenyID      map[string]string `json:"deny_rule_id"`
	Approval    map[string]string `json:"approval_bytes"`
	Summary     summaryVector     `json:"summary"`
	Write       writeVector       `json:"write"`
	Change      changeVector      `json:"change_deny_written_again"`
	DenyAgainID denyAgainVector   `json:"deny_rule_written_again_id"`
	State       stateVector       `json:"snapshot_state"`
}

// The layout vectors give every field, so a second implementation builds
// the bytes from the fields instead of re-hashing given bytes. Seq, Num,
// Wall and Count are numbers; everything else is hex.

type headVector struct {
	Device string
	Seq    uint64
	Hash   string
}

// summaryVector: a signer's summary with Prev, Snap and Base set (SS 9).
type summaryVector struct {
	Account, Signer   string
	Num               uint64
	Prev              string
	KeyGen, ListNum   uint32
	ListHash          string
	MinClient         uint32
	Heads             []headVector
	Snap, Base        string
	SignedBytes, Hash string
}

// writeVector: a write's header (the seal's place), the signed bytes
// with the sealed body, and the write's hash.
type writeVector struct {
	Account, Vault, Writer   string
	Seq                      uint64
	Prev                     string
	ListNum                  uint32
	ListHash                 string
	KeyGen                   uint32
	Wall                     int64
	Count                    uint32
	Seed, Commit, Ciphertext string
	Header, SignedBytes      string
	Hash                     string
}

// changeVector: a sealed body's plaintext, here a deny rule written again
// with Target set (SS 6.2).
type changeVector struct {
	Kind           uint8
	Record, Type   string
	Create, Delete bool
	Fields         [][2]string
	TargetWriter   string
	TargetSeq      uint64
	TargetHash     string
	Replaces       []string
	Approval       string
	Bytes          string
}

type denyAgainVector struct {
	Writer string
	Seq    uint64
	Hash   string
	Fields [][2]string
	ID     string
}

// stateVector: the one byte form of the merged data a snapshot seals.
// Records are sorted by ID; a deleted record keeps only its name. Waiting
// changes and the applied changes that set a name are sorted by write;
// approvals are kept only for writes past the heads.
type stateVector struct {
	Heads    []headVector
	Records  []stateRecord
	Waiting  []stateWaiting
	Approved []stateApproved
	Done     []stateDone
	Bytes    string
}

type stateField struct {
	Name, Value string
	Wall        int64
	Count       uint32
	Dev         string
}

type stateRecord struct {
	ID, Type        string
	Exists, Deleted bool
	Fields          []stateField
}

type stateWaiting struct {
	Writer         string
	Seq            uint64
	Hash           string
	Record, Type   string
	Create, Delete bool
	Fields         [][2]string
	Wall           int64
	Count          uint32
	Dev            string
}

type stateApproved struct {
	Writer   string
	Seq      uint64
	Hash     string
	Replaces []string
}

type stateDone struct {
	Writer       string
	Seq          uint64
	Hash         string
	Record, Type string
	Replaces     []string
}

func hxs[T ~[16]byte](ids []T) []string {
	out := []string{}
	for _, id := range ids {
		out = append(out, hx(id[:]))
	}
	return out
}

func pairs(fs []Field) [][2]string {
	out := [][2]string{}
	for _, f := range fs {
		out = append(out, [2]string{f.Name, f.Value})
	}
	return out
}

// layouts computes the layout vectors.
func layouts(v *vectors) {
	dev, dev2 := DeviceID(seq(30, 16)), DeviceID(seq(60, 16))
	heads := []Head{{Device: dev, Seq: 7, Hash: Hash(seq(130, 32))}, {Device: dev2, Seq: 3, Hash: Hash(seq(140, 32))}}
	hv := func(hs []Head) []headVector {
		var out []headVector
		for _, h := range hs {
			out = append(out, headVector{hx(h.Device[:]), h.Seq, hx(h.Hash[:])})
		}
		return out
	}

	sm := &Summary{Account: Hash(seq(50, 32)), Signer: dev, Num: 5, Prev: Hash(seq(70, 32)), KeyGen: 2, ListNum: 4,
		ListHash: Hash(seq(90, 32)), MinClient: minClient, Heads: heads, Snap: Hash(seq(110, 32)), Base: Hash(seq(150, 32))}
	sh := sm.Hash()
	v.Summary = summaryVector{hx(sm.Account[:]), hx(sm.Signer[:]), sm.Num, hx(sm.Prev[:]), sm.KeyGen, sm.ListNum,
		hx(sm.ListHash[:]), sm.MinClient, hv(heads), hx(sm.Snap[:]), hx(sm.Base[:]), hx(sm.signedBytes()), hx(sh[:])}

	fields := []Field{{"pattern", "rm -rf *"}, {"note", "kept from a removed device"}}
	target := WriteRef{Writer: dev2, Seq: 3, Hash: Hash(seq(140, 32))}
	again := denyAgainID(target, fields)
	v.DenyAgainID = denyAgainVector{hx(dev2[:]), 3, hx(target.Hash[:]), pairs(fields), hx(again[:])}
	c := &Change{Kind: kindRecord, Record: again, Type: TypeDeny, Create: true, Fields: fields, Target: target}
	v.Change = changeVector{c.Kind, hx(c.Record[:]), c.Type, c.Create, c.Delete, pairs(fields), hx(dev2[:]), 3,
		hx(target.Hash[:]), hxs(c.Replaces), hx(c.Approval[:]), hx(c.marshal())}

	w := &Write{Account: Hash(seq(50, 32)), Vault: [16]byte(seq(180, 16)), Writer: dev, Seq: 8, Prev: Hash(seq(130, 32)),
		ListNum: 4, ListHash: Hash(seq(90, 32)), KeyGen: 2, Clock: HLC{Wall: 1_700_000_000_000, Count: 3, Dev: dev}}
	w.Body = sealRecordSeed(seq(0, 32), w.header(), c.marshal(), [32]byte(seq(200, 32)))
	wh := w.Hash()
	v.Write = writeVector{hx(w.Account[:]), hx(w.Vault[:]), hx(w.Writer[:]), w.Seq, hx(w.Prev[:]), w.ListNum,
		hx(w.ListHash[:]), w.KeyGen, w.Clock.Wall, w.Clock.Count, hx(w.Body.Seed[:]), hx(w.Body.Commit[:]),
		hx(w.Body.CT), hx(w.header()), hx(w.signedBytes()), hx(wh[:])}

	// A live server, its deleted old holder, a waiting edit, an approval
	// for a write past the heads, one at the heads (left out), and an
	// applied newcomer that replaced the old holder.
	srv, old := recordID(TypeServer, [12]byte(seq(1, 12))), recordID(TypeServer, [12]byte(seq(20, 12)))
	clk := HLC{Wall: 1_700_000_000_000, Count: 1, Dev: dev}
	ref := func(d DeviceID, n uint64, b int) WriteRef { return WriteRef{Writer: d, Seq: n, Hash: Hash(seq(b, 32))} }
	m := newMergeState()
	m.records[old] = &record{Type: TypeServer, Exists: true, Deleted: true, Fields: map[string]fieldVal{
		"name": {"prod-db", clk}, "address": {"10.0.0.5", clk}}}
	m.records[srv] = &record{Type: TypeServer, Exists: true, Fields: map[string]fieldVal{
		"name": {"prod-db", clk}, "address": {"10.0.0.6", HLC{Wall: 1_700_000_000_500, Count: 0, Dev: dev2}}}}
	m.waiting[ref(dev2, 3, 140)] = &waiting{Ref: ref(dev2, 3, 140), Record: srv, Type: TypeServer,
		Fields: []Field{{"address", "203.0.113.9"}}, Clock: HLC{Wall: 1_700_000_001_000, Count: 2, Dev: dev2}}
	m.approved[ref(dev2, 4, 160)] = true
	m.replaces[ref(dev2, 4, 160)] = []RecordID{old}
	m.approved[ref(dev, 6, 120)] = true
	m.approved[ref(dev, 7, 130)] = true
	m.replaces[ref(dev, 7, 130)] = []RecordID{old}
	m.done[ref(dev, 7, 130)] = &waiting{Ref: ref(dev, 7, 130), Record: srv, Type: TypeServer}
	hm := map[DeviceID]Head{}
	for _, h := range heads {
		hm[h.Device] = h
	}
	st := stateVector{Heads: hv(heads), Bytes: hx(m.encode(hm))}
	sf := func(fs map[string]fieldVal) []stateField {
		var out []stateField
		for _, n := range []string{"address", "name"} {
			f := fs[n]
			out = append(out, stateField{n, f.Value, f.Clock.Wall, f.Clock.Count, hx(f.Clock.Dev[:])})
		}
		return out
	}
	// Given in another order than the bytes: the reader sorts.
	st.Records = []stateRecord{
		{hx(srv[:]), TypeServer, true, false, sf(m.records[srv].Fields)},
		{hx(old[:]), TypeServer, true, true, sf(m.records[old].Fields)},
	}
	wt := m.waiting[ref(dev2, 3, 140)]
	st.Waiting = []stateWaiting{{hx(dev2[:]), 3, hx(seq(140, 32)), hx(srv[:]), TypeServer, false, false,
		pairs(wt.Fields), wt.Clock.Wall, wt.Clock.Count, hx(wt.Clock.Dev[:])}}
	st.Approved = []stateApproved{
		{hx(dev2[:]), 4, hx(seq(160, 32)), hxs([]RecordID{old})},
		{hx(dev[:]), 6, hx(seq(120, 32)), []string{}},
		{hx(dev[:]), 7, hx(seq(130, 32)), hxs([]RecordID{old})},
	}
	st.Done = []stateDone{{hx(dev[:]), 7, hx(seq(130, 32)), hx(srv[:]), TypeServer, hxs([]RecordID{old})}}
	v.State = st
}

// snapshotVector: the state's one byte form, its hash, the header that
// binds the seal and is signed, the seal (the record seal with the header
// as its place) and the snapshot's hash.
type snapshotVector struct {
	VaultKey, Seed, Header, State, StateHash string
	Commit, Ciphertext, Hash                 string
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

	m := newMergeState()
	rid := RecordID(seq(10, 16))
	m.records[rid] = &record{Type: TypeServer, Exists: true, Fields: map[string]fieldVal{
		"address": {Value: "10.0.0.5", Clock: HLC{Wall: 1_700_000_000_000, Count: 1, Dev: DeviceID(seq(30, 16))}}}}
	snap := &Snapshot{Account: Hash(seq(50, 32)), Signer: DeviceID(seq(30, 16)), Num: 1, ListNum: 4,
		ListHash: Hash(seq(90, 32)), KeyGen: 2, Heads: []Head{{Device: DeviceID(seq(30, 16)), Seq: 7, Hash: Hash(seq(130, 32))}}}
	state := m.encode(snap.headMap())
	snap.State = sum(labelSnapState, state)
	snap.Body = sealRecordSeed(seq(0, 32), snap.header(), state, [32]byte(seq(170, 32)))
	sh := snap.Hash()
	v.Snapshot = snapshotVector{hx(seq(0, 32)), hx(snap.Body.Seed[:]), hx(snap.header()), hx(state), hx(snap.State[:]),
		hx(snap.Body.Commit[:]), hx(snap.Body.CT), hx(sh[:])}
	did := denyID(DeviceID(seq(30, 16)), 7)
	v.DenyID = map[string]string{"writer": hx(seq(30, 16)), "seq": "0000000000000007", "id": hx(did[:])}
	target := WriteRef{Writer: DeviceID(seq(30, 16)), Seq: 7, Hash: Hash(seq(130, 32))}
	v.Approval = map[string]string{"account": hx(seq(50, 32)), "writer": hx(seq(30, 16)), "seq": "0000000000000007",
		"hash": hx(seq(130, 32)), "replaces": hx(seq(10, 16)),
		"bytes": hx(approvalBytes(Hash(seq(50, 32)), target, []RecordID{rid}))}
	layouts(&v)
	return v
}

func TestVectors(t *testing.T) {
	want := deterministic(t)
	b, err := os.ReadFile(vectorsFile)
	if *update && (err != nil || randomParts(t, b, &want) != nil) {
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
		write(t, want)
		return
	}
	must(t, err)
	if err := randomParts(t, b, &want); err != nil {
		t.Fatal(err)
	}
	if *update {
		write(t, want)
		return
	}
	var got vectors
	must(t, json.Unmarshal(b, &got))
	a, _ := json.Marshal(want)
	g, _ := json.Marshal(got)
	if string(a) != string(g) {
		t.Errorf("vectors differ from %s; if the change is meant, run go test -run TestVectors -update", vectorsFile)
	}
}

func write(t *testing.T, v vectors) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(t, err)
	must(t, os.WriteFile(vectorsFile, append(b, '\n'), 0o644))
}

// randomParts checks the parts of the stored vectors made with randomness
// by use, and copies them into want, so the rest compares exactly and an
// update keeps them.
func randomParts(t *testing.T, b []byte, want *vectors) error {
	var got vectors
	if err := json.Unmarshal(b, &got); err != nil {
		return err
	}
	k, err := KitFromPaper(got.Shamir.Parts[1], got.Shamir.Parts[2])
	if err != nil || hx(k.key[:]) != want.Shamir.Secret {
		return errors.New("kit paper parts do not give the kit back")
	}
	sk, _ := xwing.DeriveKeyPair(unhx(t, got.HPKE.IKM))
	pt, err := hpke.Open(sk, hpkeKDF, hpkeAEAD, unhx(t, got.HPKE.Info), unhx(t, got.HPKE.Ciphertext))
	if err != nil || hx(pt) != want.HPKE.Plaintext {
		return fmt.Errorf("HPKE vector does not open: %v", err)
	}
	pub := parsePub(unhx(t, got.Signature.PublicKey))
	if !verifySig(pub, got.Signature.Label, unhx(t, got.Signature.Body), Sig(unhx(t, got.Signature.Sig))) {
		return errors.New("signature vector does not verify")
	}
	want.Shamir.Parts, want.HPKE.Ciphertext, want.Signature.Sig = got.Shamir.Parts, got.HPKE.Ciphertext, got.Signature.Sig
	return nil
}
