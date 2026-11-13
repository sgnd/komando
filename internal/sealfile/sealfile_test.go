package sealfile

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
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

func recipientKey(t *testing.T) *ecdh.PrivateKey {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRecipientRoundTrip(t *testing.T) {
	k := recipientKey(t)
	f, err := SealRecipient(content(), k.PublicKey().Bytes(), made)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ReadHeader(f)
	if err != nil || h.Mode != ModeRecipient || h.KDF != nil || h.KEM.Suite != Suite || h.KEM.KeyID != KeyID(k.PublicKey().Bytes()) {
		t.Fatalf("%+v %v", h, err)
	}
	if enc, _ := base64.StdEncoding.DecodeString(h.KEM.Enc); len(enc) != 32 {
		t.Errorf("enc %d bytes", len(enc))
	}
	got, _, err := OpenRecipient(f, k.Bytes())
	if err != nil || !bytes.Equal(got, content()) {
		t.Fatalf("%s %v", got, err)
	}
	if _, _, err := OpenRecipient(f, recipientKey(t).Bytes()); !errors.Is(err, ErrWrongKey) {
		t.Errorf("another key: %v", err)
	}
	if _, _, err := OpenPassphrase(f, testPass); !errors.Is(err, ErrWrongMode) {
		t.Errorf("passphrase open of a recipient file: %v", err)
	}
	if _, err := SealRecipient(content(), []byte("short"), made); err == nil {
		t.Error("a key that is not 32 bytes was taken")
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

// A change to the header or the body is refused; nothing opens.
func TestTamperRefused(t *testing.T) {
	pf, err := SealPassphrase(content(), testPass, made)
	if err != nil {
		t.Fatal(err)
	}
	k := recipientKey(t)
	rf, err := SealRecipient(content(), k.PublicKey().Bytes(), made)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(f []byte, i int) []byte { g := slices.Clone(f); g[i] ^= 1; return g }
	pOpen := func(f []byte) error { _, _, err := OpenPassphrase(f, testPass); return err }
	rOpen := func(f []byte) error { _, _, err := OpenRecipient(f, k.Bytes()); return err }
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
		{"recipient created_at", rOpen(replaceInHeader(t, rf, "2026-11-14", "2026-11-15")), ErrTampered},
		{"recipient key_id", rOpen(replaceInHeader(t, rf, `"key_id":"`+KeyID(k.PublicKey().Bytes())[:4], `"key_id":"0000`)), ErrWrongKey},
		{"recipient suite", rOpen(replaceInHeader(t, rf, "X25519", "X448__")), ErrUnsupported},
		{"recipient version", rOpen(replaceInHeader(t, rf, `"v":1`, `"v":2`)), ErrUnsupported},
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

// vectors is testdata/vectors.json: known answers another implementation
// (the iPhone app's KomandoKit) opens to check that it reads the format
// the same way.
type vectors struct {
	About      string `json:"about"`
	WordList   string `json:"bip39_english_sha256"`
	Recipient  vector `json:"recipient"`
	Passphrase vector `json:"passphrase"`
}

type vector struct {
	PrivateKey  string   `json:"private_key_hex,omitempty"`
	PublicKey   string   `json:"public_key_hex,omitempty"`
	KeyID       string   `json:"key_id,omitempty"`
	Passphrase  string   `json:"passphrase,omitempty"`
	Info        string   `json:"info,omitempty"`
	AADLength   int      `json:"aad_length"`
	File        string   `json:"file_base64"`
	Content     string   `json:"content"`
	CheckPhrase []string `json:"check_phrase"`
}

var vectorPath = filepath.Join("testdata", "vectors.json")

// TestKnownAnswers opens the files in testdata/vectors.json. With
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
	r := v.Recipient
	priv, _ := hex.DecodeString(r.PrivateKey)
	f, _ := base64.StdEncoding.DecodeString(r.File)
	got, h, err := OpenRecipient(f, priv)
	if err != nil || string(got) != r.Content || h.KEM.KeyID != r.KeyID || r.Info != Info {
		t.Fatalf("recipient: %q %+v %v", got, h, err)
	}
	if s, e := headerAt(f); e != r.AADLength || s != 12 {
		t.Errorf("aad length %d, vector says %d", e, r.AADLength)
	}
	if !slices.Equal(CheckPhrase(f), r.CheckPhrase) {
		t.Errorf("check phrase %v, vector says %v", CheckPhrase(f), r.CheckPhrase)
	}
	p := v.Passphrase
	f, _ = base64.StdEncoding.DecodeString(p.File)
	if got, _, err := OpenPassphrase(f, p.Passphrase); err != nil || string(got) != p.Content {
		t.Fatalf("passphrase: %q %v", got, err)
	}
	if !slices.Equal(CheckPhrase(f), p.CheckPhrase) {
		t.Errorf("passphrase check phrase %v, vector says %v", CheckPhrase(f), p.CheckPhrase)
	}
}

func writeVectors(t *testing.T) {
	// a fixed private key, so the vector's key never changes
	priv := sha256.Sum256([]byte("komando sealed file test key v1"))
	sk, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		t.Fatal(err)
	}
	pub := sk.PublicKey().Bytes()
	c := string(content())
	rf, err := SealRecipient([]byte(c), pub, made)
	if err != nil {
		t.Fatal(err)
	}
	pf, err := SealPassphrase([]byte(c), testPass, made)
	if err != nil {
		t.Fatal(err)
	}
	_, re := headerAt(rf)
	_, pe := headerAt(pf)
	v := vectors{
		About: "Known answers for the komando sealed file v1 (docs/design/sealed-file.md). " +
			"aad is the first aad_length bytes of the file (magic, header length, header). " +
			"Open each file and compare with content and check_phrase.",
		WordList: "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
		Recipient: vector{PrivateKey: hex.EncodeToString(priv[:]), PublicKey: hex.EncodeToString(pub), KeyID: KeyID(pub), Info: Info,
			AADLength: re, File: base64.StdEncoding.EncodeToString(rf), Content: c, CheckPhrase: CheckPhrase(rf)},
		Passphrase: vector{Passphrase: testPass, AADLength: pe, File: base64.StdEncoding.EncodeToString(pf), Content: c, CheckPhrase: CheckPhrase(pf)},
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(vectorPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\r") {
		t.Fatal("a carriage return in the vectors")
	}
}
