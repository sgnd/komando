package sealfile

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testPass = "correct horse battery staple"

var made = Made{By: "komando test", At: time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)}

func content() []byte {
	return []byte(`{"format":"komando-export/1","hosts":[{"name":"web1","address":"10.0.0.5"}],"secrets":{"web1-pass":"s3cret value"}}`)
}

// The word list is BIP-39 English, verbatim: the iPhone app pins the same
// hash, so both sides make the same check phrase.
func TestWordListPinned(t *testing.T) {
	const want = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	if got := sha256.Sum256([]byte(bip39English)); hex.EncodeToString(got[:]) != want {
		t.Fatalf("bip39_english.txt has SHA-256 %x, want %s", got, want)
	}
	if len(Words) != 2048 || Words[0] != "abandon" || Words[2047] != "zoo" {
		t.Fatalf("%d words, first %q, last %q", len(Words), Words[0], Words[len(Words)-1])
	}
	prefixes := map[string]bool{}
	for _, w := range Words {
		prefixes[w[:min(4, len(w))]] = true
	}
	if len(prefixes) != 2048 {
		t.Errorf("4-letter prefixes are not unique: %d", len(prefixes))
	}
}

func TestCheckPhraseBits(t *testing.T) {
	// SHA-256("") starts e3b0c442 98fc...: 11100011101 10000110001 ...
	got := CheckPhrase(nil)
	if len(got) != PhraseWords || got[0] != Words[0b11100011101] || got[1] != Words[0b10000110001] {
		t.Fatalf("%v", got)
	}
}

func TestPassphraseRoundTrip(t *testing.T) {
	f, err := SealPassphrase(content(), testPass, made)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(f, []byte("s3cret")) || bytes.Contains(f, []byte("web1")) {
		t.Fatal("the content shows in the file")
	}
	h, err := ReadHeader(f)
	if err != nil || h.Mode != ModePassphrase || h.KDF.N != 1<<17 || h.KDF.R != 8 || h.KDF.P != 1 || h.KEM != nil ||
		h.Compression != "deflate" || h.MadeBy != "komando test" || h.CreatedAt != "2026-11-14T09:30:00Z" {
		t.Fatalf("%+v %v", h, err)
	}
	if salt, _ := base64.StdEncoding.DecodeString(h.KDF.Salt); len(salt) != 32 {
		t.Errorf("salt %d bytes", len(salt))
	}
	got, _, err := OpenPassphrase(f, testPass)
	if err != nil || !bytes.Equal(got, content()) {
		t.Fatalf("%s %v", got, err)
	}
	if _, _, err := OpenPassphrase(f, "another passphrase here"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if _, _, err := OpenRecipient(f, make([]byte, 32)); !errors.Is(err, ErrWrongMode) {
		t.Errorf("recipient open of a passphrase file: %v", err)
	}
}

// testKey is a recipient's X-Wing key pair: the 32-byte seed the phone
// keeps and the 1216-byte public key it shares.
type testKey struct{ seed, pub []byte }

func recipientKey(t *testing.T) testKey {
	k, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return testKey{seed, k.PublicKey().Bytes()}
}

func TestRecipientRoundTrip(t *testing.T) {
	k := recipientKey(t)
	if len(k.pub) != PublicKeySize || len(k.seed) != PrivateKeySize {
		t.Fatalf("key sizes %d and %d", len(k.pub), len(k.seed))
	}
	f, err := SealRecipient(content(), k.pub, made)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ReadHeader(f)
	if err != nil || h.V != 2 || h.Mode != ModeRecipient || h.KDF != nil || h.KEM.Suite != "MLKEM768X25519-SHA256-AES256GCM" || h.KEM.KeyID != KeyID(k.pub) {
		t.Fatalf("%+v %v", h, err)
	}
	if enc, _ := base64.StdEncoding.DecodeString(h.KEM.Enc); len(enc) != EncSize {
		t.Errorf("enc %d bytes", len(enc))
	}
	got, _, err := OpenRecipient(f, k.seed)
	if err != nil || !bytes.Equal(got, content()) {
		t.Fatalf("%s %v", got, err)
	}
	if _, _, err := OpenRecipient(f, recipientKey(t).seed); !errors.Is(err, ErrWrongKey) {
		t.Errorf("another key: %v", err)
	}
	if _, _, err := OpenPassphrase(f, testPass); !errors.Is(err, ErrWrongMode) {
		t.Errorf("passphrase open of a recipient file: %v", err)
	}
	// an X25519 key (32 bytes, the old kind) and a cut X-Wing key are refused
	for _, pub := range [][]byte{[]byte("short"), make([]byte, 32), k.pub[:PublicKeySize-1], append(slices.Clone(k.pub), 0)} {
		if _, err := SealRecipient(content(), pub, made); err == nil {
			t.Errorf("a %d-byte key was taken", len(pub))
		}
	}
	if _, _, err := OpenRecipient(f, make([]byte, 31)); err == nil || errors.Is(err, ErrWrongKey) {
		t.Errorf("a 31-byte private key: %v", err)
	}
}

// headerAt is where the header's JSON starts and ends in f.
func headerAt(f []byte) (int, int) {
	return headerPrefix, headerPrefix + int(binary.LittleEndian.Uint32(f[len(Magic):]))
}

// replaceInHeader swaps old for new (same length) in the header's JSON.
func replaceInHeader(t *testing.T, f []byte, old, new string) []byte {
	t.Helper()
	s, e := headerAt(f)
	i := bytes.Index(f[s:e], []byte(old))
	if i < 0 || len(old) != len(new) {
		t.Fatalf("%q not in the header %s", old, f[s:e])
	}
	g := slices.Clone(f)
	copy(g[s+i:], new)
	return g
}

// withHeader rewrites f's header (any length) and keeps its body.
func withHeader(t *testing.T, f []byte, change func(*Header)) []byte {
	t.Helper()
	_, e := headerAt(f)
	var h Header
	if err := json.Unmarshal(f[headerPrefix:e], &h); err != nil {
		t.Fatal(err)
	}
	if h.KEM != nil {
		k := *h.KEM
		h.KEM = &k
	}
	change(&h)
	head, err := encodeHead(h)
	if err != nil {
		t.Fatal(err)
	}
	return append(head, f[e:]...)
}

// rawHeader rewrites f's header JSON as bytes (any length) and keeps its
// body.
func rawHeader(t *testing.T, f []byte, change func([]byte) []byte) []byte {
	t.Helper()
	_, e := headerAt(f)
	j := change(slices.Clone(f[headerPrefix:e]))
	b := make([]byte, headerPrefix, headerPrefix+len(j)+len(f)-e)
	copy(b, Magic)
	binary.LittleEndian.PutUint32(b[len(Magic):], uint32(len(j)))
	return append(append(b, j...), f[e:]...)
}

// A change to the header or the body is refused; nothing opens.
func TestTamperRefused(t *testing.T) {
	pf, err := SealPassphrase(content(), testPass, made)
	if err != nil {
		t.Fatal(err)
	}
	k := recipientKey(t)
	rf, err := SealRecipient(content(), k.pub, made)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(f []byte, i int) []byte { g := slices.Clone(f); g[i] ^= 1; return g }
	pOpen := func(f []byte) error { _, _, err := OpenPassphrase(f, testPass); return err }
	rOpen := func(f []byte) error { _, _, err := OpenRecipient(f, k.seed); return err }
	for _, c := range []struct {
		name string
		err  error
		want error
	}{
		{"passphrase body", pOpen(flip(pf, len(pf)-20)), ErrWrongPassphrase},
		{"passphrase nonce", pOpen(flip(pf, headerPrefix+int(binary.LittleEndian.Uint32(pf[8:]))+1)), ErrWrongPassphrase},
		{"passphrase tag", pOpen(flip(pf, len(pf)-1)), ErrWrongPassphrase},
		{"passphrase created_at", pOpen(replaceInHeader(t, pf, "2026-11-14", "2026-11-15")), ErrWrongPassphrase},
		{"passphrase made_by", pOpen(replaceInHeader(t, pf, "komando test", "komando tesT")), ErrWrongPassphrase},
		{"passphrase mode", pOpen(replaceInHeader(t, pf, `"passphrase"`, `"recipient!"`)), ErrUnsupported},
		{"passphrase cost", pOpen(replaceInHeader(t, pf, `"n":131072`, `"n":999999`)), ErrUnsupported},
		{"passphrase json", pOpen(replaceInHeader(t, pf, `{"v":1`, `["v":1`)), ErrInvalid},
		{"passphrase cut", pOpen(pf[:len(pf)-30]), ErrWrongPassphrase},
		{"passphrase cut header", pOpen(pf[:20]), ErrInvalid},
		{"recipient body", rOpen(flip(rf, len(rf)-20)), ErrTampered},
		{"recipient tag", rOpen(flip(rf, len(rf)-1)), ErrTampered},
		{"recipient cut", rOpen(rf[:len(rf)-5]), ErrTampered},
		{"recipient created_at", rOpen(replaceInHeader(t, rf, "2026-11-14", "2026-11-15")), ErrTampered},
		{"recipient made_by", rOpen(replaceInHeader(t, rf, "komando test", "komando tesT")), ErrTampered},
		{"recipient key_id", rOpen(replaceInHeader(t, rf, `"key_id":"`+KeyID(k.pub)[:4], `"key_id":"0000`)), ErrWrongKey},
		{"recipient suite", rOpen(replaceInHeader(t, rf, "MLKEM768X25519", "MLKEM768X448__")), ErrUnsupported},
		{"recipient old suite", rOpen(withHeader(t, rf, func(h *Header) { h.KEM.Suite = "X25519-SHA256-AES256GCM" })), ErrUnsupported},
		{"recipient old version and suite", rOpen(withHeader(t, rf, func(h *Header) { h.V, h.KEM.Suite = 1, "X25519-SHA256-AES256GCM" })), ErrOutdated},
		{"recipient newer version", rOpen(replaceInHeader(t, rf, `"v":2`, `"v":3`)), ErrUnsupported},
		{"recipient old version", rOpen(replaceInHeader(t, rf, `"v":2`, `"v":1`)), ErrOutdated},
		{"passphrase version 2", pOpen(replaceInHeader(t, pf, `"v":1`, `"v":2`)), ErrUnsupported},
		{"recipient key case", rOpen(replaceInHeader(t, rf, `"mode"`, `"MODE"`)), ErrInvalid},
		{"recipient trailing brace", rOpen(rawHeader(t, rf, func(j []byte) []byte { return append(j, '}') })), ErrInvalid},
		{"recipient unknown key", rOpen(rawHeader(t, rf, func(j []byte) []byte { return append([]byte(`{"x":1,`), j[1:]...) })), ErrInvalid},
		{"recipient duplicate key", rOpen(rawHeader(t, rf, func(j []byte) []byte { return append([]byte(`{"v":3,`), j[1:]...) })), ErrInvalid},
		{"passphrase space", pOpen(rawHeader(t, pf, func(j []byte) []byte { return append([]byte(`{ `), j[1:]...) })), ErrInvalid},
		{"not sealed", rOpen([]byte(`{"format":"komando-export/1"}`)), ErrNotSealed},
	} {
		if !errors.Is(c.err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, c.err, c.want)
		}
	}
	// enc changed: another shared secret, so the seal breaks
	h, _ := ReadHeader(rf)
	enc, _ := base64.StdEncoding.DecodeString(h.KEM.Enc)
	enc[3] ^= 1
	if err := rOpen(replaceInHeader(t, rf, h.KEM.Enc, base64.StdEncoding.EncodeToString(enc))); !errors.Is(err, ErrTampered) {
		t.Errorf("enc: %v", err)
	}
}

// A file that unpacks to more than maxContent is refused, not read into
// memory whole.
func TestInflateLimit(t *testing.T) {
	z, err := deflate(make([]byte, maxContent+10))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inflate(z); !errors.Is(err, ErrInvalid) {
		t.Fatalf("%v", err)
	}
}

// vectors is testdata/vectors.json: known answers that pin every byte of
// the format, for the iPhone app's opener (KomandoKit) and for this one.
// hex is lower case; Header is the header's JSON exactly as in the file.
type vectors struct {
	About      string           `json:"about"`
	WordList   string           `json:"bip39_english_sha256"`
	Recipient  recipientVector  `json:"recipient"`
	Passphrase passphraseVector `json:"passphrase"`
	Refused    []refusedVector  `json:"refused"`
}

type recipientVector struct {
	Suite          string   `json:"suite"`
	KEMID          int      `json:"kem_id"`
	KDFID          int      `json:"kdf_id"`
	AEADID         int      `json:"aead_id"`
	Info           string   `json:"info"`
	PrivateKeySeed string   `json:"private_key_seed_hex"`
	PublicKey      string   `json:"public_key_hex"`
	KeyID          string   `json:"key_id"`
	EncapRandom    string   `json:"encap_randomness_hex"`
	Enc            string   `json:"enc_hex"`
	SharedSecret   string   `json:"shared_secret_hex"`
	Key            string   `json:"key_hex"`
	BaseNonce      string   `json:"base_nonce_hex"`
	CreatedAt      string   `json:"created_at"`
	MadeBy         string   `json:"made_by"`
	Header         string   `json:"header"`
	AADLength      int      `json:"aad_length"`
	Content        string   `json:"content"`
	Deflated       string   `json:"deflated_hex"`
	File           string   `json:"file_hex"`
	CheckPhrase    []string `json:"check_phrase"`
}

type passphraseVector struct {
	Passphrase  string   `json:"passphrase"`
	Salt        string   `json:"salt_hex"`
	Nonce       string   `json:"nonce_hex"`
	CreatedAt   string   `json:"created_at"`
	MadeBy      string   `json:"made_by"`
	Header      string   `json:"header"`
	AADLength   int      `json:"aad_length"`
	Content     string   `json:"content"`
	Deflated    string   `json:"deflated_hex"`
	File        string   `json:"file_hex"`
	CheckPhrase []string `json:"check_phrase"`
}

// refusedVector is a file that must not open: with the recipient vector's
// private key (open "recipient") or the passphrase vector's passphrase
// (open "passphrase"), it fails with error.
type refusedVector struct {
	Name  string `json:"name"`
	Open  string `json:"open"`
	Error string `json:"error"`
	File  string `json:"file_hex"`
}

// The errors a refused vector names.
var refusedErrors = map[string]error{
	"outdated":         ErrOutdated,
	"tampered":         ErrTampered,
	"unsupported":      ErrUnsupported,
	"wrong_key":        ErrWrongKey,
	"wrong_passphrase": ErrWrongPassphrase,
	"invalid":          ErrInvalid,
}

var vectorPath = filepath.Join("testdata", "vectors.json")

// The fixed inputs of the vectors.
func vectorInputs() (seed, eseed, salt, nonce []byte) {
	s := sha256.Sum256([]byte("komando sealed file test key v2"))
	e := sha512.Sum512([]byte("komando sealed file test encapsulation v2"))
	a := sha256.Sum256([]byte("komando sealed file test salt v2"))
	n := sha256.Sum256([]byte("komando sealed file test nonce v2"))
	return s[:], e[:], a[:], n[:nonceLen]
}

// oldRecipientV1 is a recipient file komando 0.14.0 made (header v1,
// DHKEM(X25519) only). Nothing reads it now: it is refused as outdated.
const oldRecipientV1 = "4b4d445345414c31250100007b2276223a312c226d6f6465223a22726563697069656e74222c226b6466223a6e756c6c" +
	"2c226b656d223a7b227375697465223a225832353531392d5348413235362d41455332353647434d222c22656e63223a" +
	"22434c7565526a384b31463459515369475662756e3552426a4f767943334d657762537834565869464456673d222c22" +
	"6b65795f6964223a22656265376334303530316432306338656633626137666462636532356433653434633662303165" +
	"36376162366565623232653037326666316364623238646462227d2c22636f6d7072657373696f6e223a226465666c61" +
	"7465222c22637265617465645f6174223a22323032362d31312d31345430393a33303a30305a222c226d6164655f6279" +
	"223a226b6f6d616e646f2074657374227d9342f6f5332fb4d102f8da2b99911854c175b8aa4180fb5ffbc738c72272b0" +
	"7ab1afeda6af17d3e28d190bcb4822d123db140be4cbed76e4db345b38d58c77e564980d30b91c93acf0c19f6e5d4798" +
	"c9423a87a9be352fb9429fcc426d68035816ff19861fb2e70c38fa61932083fb94ffed8c"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q...: %v", s[:min(16, len(s))], err)
	}
	return b
}

// TestKnownAnswers checks testdata/vectors.json byte for byte: the
// reference sealer (reference_test.go) writes each file exactly, the
// package opens it, and every refused file fails as named. With
// KOMANDO_UPDATE_SEALVECTORS=1 it writes new ones first (only for a format
// change: the iPhone app's copy must change with them).
func TestKnownAnswers(t *testing.T) {
	if os.Getenv("KOMANDO_UPDATE_SEALVECTORS") == "1" {
		writeVectors(t)
	}
	b, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	seed, eseed, salt, nonce := vectorInputs()
	r := v.Recipient
	if r.Suite != Suite || r.KEMID != refKEMID || r.KDFID != refKDFID || r.AEADID != refAEADID || r.Info != Info ||
		r.PrivateKeySeed != hex.EncodeToString(seed) || r.EncapRandom != hex.EncodeToString(eseed) {
		t.Fatalf("recipient vector inputs: %+v", r)
	}
	_, _, pub := refKeys(t, seed)
	if hex.EncodeToString(pub) != r.PublicKey || KeyID(pub) != r.KeyID {
		t.Fatalf("public key or key_id differs from the vector")
	}
	// Go's X-Wing makes the same public key from the seed
	if k, err := hpke.MLKEM768X25519().NewPrivateKey(seed); err != nil || !bytes.Equal(k.PublicKey().Bytes(), pub) {
		t.Fatalf("crypto/hpke's public key differs: %v", err)
	}
	file := unhex(t, r.File)
	deflated := unhex(t, r.Deflated)
	if c, err := refInflate(deflated); err != nil || string(c) != r.Content {
		t.Fatalf("deflated_hex does not inflate to content: %v", err)
	}
	got, steps := refSealRecipient(t, deflated, pub, eseed, r.CreatedAt, r.MadeBy)
	if !bytes.Equal(got, file) {
		t.Fatalf("the reference sealer writes another file:\n%x", got)
	}
	for name, c := range map[string][2]string{
		"enc":           {hex.EncodeToString(steps.Enc), r.Enc},
		"shared secret": {hex.EncodeToString(steps.SharedSecret), r.SharedSecret},
		"key":           {hex.EncodeToString(steps.Key), r.Key},
		"base nonce":    {hex.EncodeToString(steps.BaseNonce), r.BaseNonce},
		"header":        {string(file[headerPrefix:r.AADLength]), r.Header},
	} {
		if c[0] != c[1] {
			t.Errorf("%s: %s, vector says %s", name, c[0], c[1])
		}
	}
	if len(steps.Enc) != EncSize {
		t.Errorf("enc %d bytes", len(steps.Enc))
	}
	if c, err := refOpenRecipient(t, file, seed); err != nil || string(c) != r.Content {
		t.Errorf("the reference does not open the vector: %v", err)
	}
	c, h, err := OpenRecipient(file, seed)
	if err != nil || string(c) != r.Content || h.KEM.KeyID != r.KeyID || h.V != 2 {
		t.Fatalf("recipient: %q %+v %v", c, h, err)
	}
	if s, e := headerAt(file); e != r.AADLength || s != 12 {
		t.Errorf("aad length %d, vector says %d", e, r.AADLength)
	}
	if !slices.Equal(CheckPhrase(file), r.CheckPhrase) {
		t.Errorf("check phrase %v, vector says %v", CheckPhrase(file), r.CheckPhrase)
	}

	p := v.Passphrase
	if p.Salt != hex.EncodeToString(salt) || p.Nonce != hex.EncodeToString(nonce) {
		t.Fatalf("passphrase vector inputs: %+v", p)
	}
	file = unhex(t, p.File)
	pz := unhex(t, p.Deflated)
	if c, err := refInflate(pz); err != nil || string(c) != p.Content {
		t.Fatalf("passphrase deflated_hex does not inflate to content: %v", err)
	}
	if got := refSealPassphrase(t, pz, p.Passphrase, salt, nonce, p.CreatedAt, p.MadeBy); !bytes.Equal(got, file) {
		t.Fatalf("the reference sealer writes another passphrase file:\n%x", got)
	}
	if string(file[headerPrefix:p.AADLength]) != p.Header {
		t.Errorf("passphrase header differs from the vector")
	}
	if c, _, err := OpenPassphrase(file, p.Passphrase); err != nil || string(c) != p.Content {
		t.Fatalf("passphrase: %q %v", c, err)
	}
	if !slices.Equal(CheckPhrase(file), p.CheckPhrase) {
		t.Errorf("passphrase check phrase %v, vector says %v", CheckPhrase(file), p.CheckPhrase)
	}

	if len(v.Refused) < 8 {
		t.Fatalf("%d refused vectors", len(v.Refused))
	}
	for _, x := range v.Refused {
		want, ok := refusedErrors[x.Error]
		if !ok {
			t.Fatalf("%s: unknown error %q", x.Name, x.Error)
		}
		f := unhex(t, x.File)
		var err error
		switch x.Open {
		case ModeRecipient:
			_, _, err = OpenRecipient(f, seed)
		case ModePassphrase:
			_, _, err = OpenPassphrase(f, p.Passphrase)
		default:
			t.Fatalf("%s: open %q", x.Name, x.Open)
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", x.Name, err, want)
		}
	}
}

func writeVectors(t *testing.T) {
	seed, eseed, salt, nonce := vectorInputs()
	_, _, pub := refKeys(t, seed)
	c := content()
	z, err := deflate(c)
	if err != nil {
		t.Fatal(err)
	}
	at := made.At.UTC().Format(time.RFC3339)
	rf, steps := refSealRecipient(t, z, pub, eseed, at, made.By)
	pf := refSealPassphrase(t, z, testPass, salt, nonce, at, made.By)
	_, re := headerAt(rf)
	_, pe := headerAt(pf)
	flip := func(f []byte, i int) string { g := slices.Clone(f); g[i] ^= 1; return hex.EncodeToString(g) }
	enc := slices.Clone(steps.Enc)
	enc[100] ^= 1 // in ML-KEM's ciphertext: implicit rejection, another shared secret
	encX := slices.Clone(steps.Enc)
	encX[EncSize-5] ^= 1 // in the X25519 part
	v := vectors{
		About: "Known answers for the komando sealed file (docs/design/sealed-file.md): recipient mode v2 " +
			"(HPKE base mode, X-Wing MLKEM768-X25519 + HKDF-SHA256 + AES-256-GCM) and passphrase mode v1. " +
			"Every byte is fixed: seal with the inputs and compare file_hex; open file_hex and compare content and check_phrase. " +
			"aad is the first aad_length bytes of the file (magic, header length, header). " +
			"The X-Wing private key is the 32-byte seed; encap_randomness is 32 bytes of ML-KEM-768 m, then the 32-byte X25519 ephemeral private key. " +
			"Each refused file must fail with its error and give no content.",
		WordList: "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
		Recipient: recipientVector{
			Suite: Suite, KEMID: refKEMID, KDFID: refKDFID, AEADID: refAEADID, Info: Info,
			PrivateKeySeed: hex.EncodeToString(seed), PublicKey: hex.EncodeToString(pub), KeyID: KeyID(pub),
			EncapRandom: hex.EncodeToString(eseed), Enc: hex.EncodeToString(steps.Enc), SharedSecret: hex.EncodeToString(steps.SharedSecret),
			Key: hex.EncodeToString(steps.Key), BaseNonce: hex.EncodeToString(steps.BaseNonce),
			CreatedAt: at, MadeBy: made.By, Header: string(rf[headerPrefix:re]), AADLength: re,
			Content: string(c), Deflated: hex.EncodeToString(z), File: hex.EncodeToString(rf), CheckPhrase: CheckPhrase(rf),
		},
		Passphrase: passphraseVector{
			Passphrase: testPass, Salt: hex.EncodeToString(salt), Nonce: hex.EncodeToString(nonce),
			CreatedAt: at, MadeBy: made.By, Header: string(pf[headerPrefix:pe]), AADLength: pe,
			Content: string(c), Deflated: hex.EncodeToString(z), File: hex.EncodeToString(pf), CheckPhrase: CheckPhrase(pf),
		},
		Refused: []refusedVector{
			{"a recipient file of komando 0.14.0 (v1, X25519 only)", ModeRecipient, "outdated", oldRecipientV1},
			{"the tag's last byte changed", ModeRecipient, "tampered", flip(rf, len(rf)-1)},
			{"a byte of the ciphertext changed", ModeRecipient, "tampered", flip(rf, re+3)},
			{"created_at changed", ModeRecipient, "tampered", hex.EncodeToString(withHeader(t, rf, func(h *Header) { h.CreatedAt = "2026-11-15T09:30:00Z" }))},
			{"a byte of enc's ML-KEM part changed", ModeRecipient, "tampered", hex.EncodeToString(withHeader(t, rf, func(h *Header) { h.KEM.Enc = base64.StdEncoding.EncodeToString(enc) }))},
			{"a byte of enc's X25519 part changed", ModeRecipient, "tampered", hex.EncodeToString(withHeader(t, rf, func(h *Header) { h.KEM.Enc = base64.StdEncoding.EncodeToString(encX) }))},
			{"enc cut short", ModeRecipient, "invalid", hex.EncodeToString(withHeader(t, rf, func(h *Header) { h.KEM.Enc = base64.StdEncoding.EncodeToString(steps.Enc[:32]) }))},
			{"key_id of another key", ModeRecipient, "wrong_key", hex.EncodeToString(withHeader(t, rf, func(h *Header) { h.KEM.KeyID = KeyID([]byte("another key")) }))},
			{"header v3", ModeRecipient, "unsupported", hex.EncodeToString(withHeader(t, rf, func(h *Header) { h.V = 3 }))},
			{"the old suite in a v2 header", ModeRecipient, "unsupported", hex.EncodeToString(withHeader(t, rf, func(h *Header) { h.KEM.Suite = "X25519-SHA256-AES256GCM" }))},
			{"the file cut inside the header", ModeRecipient, "invalid", hex.EncodeToString(rf[:re-10])},
			{"the passphrase file's tag changed", ModePassphrase, "wrong_passphrase", flip(pf, len(pf)-1)},
		},
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(vectorPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\r") {
		t.Fatal("a carriage return in the vectors")
	}
}
