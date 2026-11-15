package sealfile

// A second implementation of the recipient mode, written from the specs
// rather than through crypto/hpke: X-Wing (draft-connolly-cfrg-xwing-kem,
// as HPKE KEM 0x647a in draft-ietf-hpke-pq), the RFC 9180 key schedule
// with HKDF-SHA256, and AES-256-GCM. It takes the encapsulation randomness
// as an argument, so a known-answer vector can pin every byte of a file;
// SealRecipient draws it from crypto/rand. TestKnownAnswers checks that
// this sealer writes the vector's exact bytes and that OpenRecipient opens
// them, so the two implementations agree.

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
)

// The HPKE algorithm IDs of Suite.
const (
	refKEMID  = 0x647a // MLKEM768-X25519 (X-Wing)
	refKDFID  = 0x0001 // HKDF-SHA256
	refAEADID = 0x0002 // AES-256-GCM
)

// refXWingLabel is X-Wing's combiner label, the six bytes \./ /^\ .
var refXWingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// refKeys expands a 32-byte X-Wing seed: SHAKE256(seed) gives the 64-byte
// ML-KEM-768 seed (d || z), then the 32-byte X25519 private key.
func refKeys(t *testing.T, seed []byte) (*mlkem.DecapsulationKey768, *ecdh.PrivateKey, []byte) {
	t.Helper()
	x := sha3.NewSHAKE256()
	x.Write(seed)
	out := make([]byte, 96)
	x.Read(out)
	dk, err := mlkem.NewDecapsulationKey768(out[:64])
	if err != nil {
		t.Fatal(err)
	}
	sk, err := ecdh.X25519().NewPrivateKey(out[64:])
	if err != nil {
		t.Fatal(err)
	}
	pub := append(dk.EncapsulationKey().Bytes(), sk.PublicKey().Bytes()...)
	return dk, sk, pub
}

// refSteps is what the reference sealer works out on the way, kept in the
// vector so another implementation can find where it differs.
type refSteps struct {
	Enc, SharedSecret, Key, BaseNonce []byte
}

// refEncap is X-Wing's Encaps with eseed: ML-KEM-768 with m = eseed[:32],
// X25519 with the ephemeral private key eseed[32:]. ss = SHA3-256(ss_M ||
// ss_X || ct_X || pk_X || label); enc = ct_M || ct_X.
func refEncap(t *testing.T, pub, eseed []byte) (ss, enc []byte) {
	t.Helper()
	ek, err := mlkem.NewEncapsulationKey768(pub[:mlkem.EncapsulationKeySize768])
	if err != nil {
		t.Fatal(err)
	}
	ssM, ctM, err := mlkemtest.Encapsulate768(ek, eseed[:32])
	if err != nil {
		t.Fatal(err)
	}
	pkX, err := ecdh.X25519().NewPublicKey(pub[mlkem.EncapsulationKeySize768:])
	if err != nil {
		t.Fatal(err)
	}
	ekX, err := ecdh.X25519().NewPrivateKey(eseed[32:64])
	if err != nil {
		t.Fatal(err)
	}
	ssX, err := ekX.ECDH(pkX)
	if err != nil {
		t.Fatal(err)
	}
	ctX := ekX.PublicKey().Bytes()
	h := sha3.New256()
	for _, b := range [][]byte{ssM, ssX, ctX, pkX.Bytes(), refXWingLabel} {
		h.Write(b)
	}
	return h.Sum(nil), append(ctM, ctX...)
}

// refSuiteID is RFC 9180's suite_id of Suite: "HPKE", then the KEM, KDF
// and AEAD IDs, two bytes each, big endian.
func refSuiteID() []byte {
	suite := []byte("HPKE")
	suite = binary.BigEndian.AppendUint16(suite, refKEMID)
	suite = binary.BigEndian.AppendUint16(suite, refKDFID)
	return binary.BigEndian.AppendUint16(suite, refAEADID)
}

// refSchedule is RFC 9180's KeySchedule in base mode (no PSK) with
// HKDF-SHA256: the AEAD key (keyLen bytes) and the 12-byte base nonce.
func refSchedule(t *testing.T, suite, ss, info []byte, keyLen int) (key, nonce []byte) {
	t.Helper()
	extract := func(salt []byte, label string, ikm []byte) []byte {
		in := append(append(append([]byte("HPKE-v1"), suite...), label...), ikm...)
		prk, err := hkdf.Extract(sha256.New, in, salt)
		if err != nil {
			t.Fatal(err)
		}
		return prk
	}
	expand := func(prk []byte, label string, ctx []byte, n int) []byte {
		in := binary.BigEndian.AppendUint16(nil, uint16(n))
		in = append(append(append(append(in, "HPKE-v1"...), suite...), label...), ctx...)
		out, err := hkdf.Expand(sha256.New, prk, string(in), n)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	ctx := append([]byte{0}, extract(nil, "psk_id_hash", nil)...)
	ctx = append(ctx, extract(nil, "info_hash", info)...)
	secret := extract(ss, "secret", nil) // LabeledExtract(shared_secret, "secret", psk = "")
	return expand(secret, "key", ctx, keyLen), expand(secret, "base_nonce", ctx, 12)
}

// refHead is the start of a file: magic, header length (little endian)
// and the header JSON, written out by hand here rather than by the
// package's encoder. made_by must need no JSON escaping.
func refHead(t *testing.T, header string) []byte {
	t.Helper()
	if strings.ContainsAny(header, "\\<>&") {
		t.Fatalf("the reference header needs escaping: %s", header)
	}
	b := append([]byte("KMDSEAL1"), binary.LittleEndian.AppendUint32(nil, uint32(len(header)))...)
	return append(b, header...)
}

// refGCM is AES-256-GCM with key.
func refGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

// refSealRecipient writes a recipient file from the deflated content,
// with the encapsulation randomness eseed (64 bytes) given.
func refSealRecipient(t *testing.T, deflated, pub, eseed []byte, createdAt, madeBy string) ([]byte, refSteps) {
	t.Helper()
	ss, enc := refEncap(t, pub, eseed)
	key, nonce := refSchedule(t, refSuiteID(), ss, []byte("komando sealed file v2"), 32)
	id := sha256.Sum256(pub)
	head := refHead(t, fmt.Sprintf(`{"v":2,"mode":"recipient","kdf":null,"kem":{"suite":"MLKEM768X25519-SHA256-AES256GCM","enc":"%s","key_id":"%s"},`+
		`"compression":"deflate","created_at":"%s","made_by":"%s"}`, base64.StdEncoding.EncodeToString(enc), hex.EncodeToString(id[:]), createdAt, madeBy))
	// sequence number 0: the nonce is the base nonce
	ct := refGCM(t, key).Seal(nil, nonce, deflated, head)
	return append(head, ct...), refSteps{Enc: enc, SharedSecret: ss, Key: key, BaseNonce: nonce}
}

// refOpenRecipient opens a recipient file with the X-Wing seed: X-Wing
// Decaps, the key schedule and AES-256-GCM, then raw inflate.
func refOpenRecipient(t *testing.T, file, seed []byte) ([]byte, error) {
	t.Helper()
	if len(file) < 12 || string(file[:8]) != "KMDSEAL1" {
		return nil, errors.New("not sealed")
	}
	n := 12 + int(binary.LittleEndian.Uint32(file[8:12]))
	if len(file) < n {
		return nil, errors.New("cut short")
	}
	var h struct {
		KEM struct {
			Enc string `json:"enc"`
		} `json:"kem"`
	}
	if err := json.Unmarshal(file[12:n], &h); err != nil {
		return nil, err
	}
	enc, err := base64.StdEncoding.DecodeString(h.KEM.Enc)
	if err != nil || len(enc) != mlkem.CiphertextSize768+32 {
		return nil, errors.New("enc")
	}
	dk, sk, _ := refKeys(t, seed)
	ssM, err := dk.Decapsulate(enc[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, err
	}
	ctX := enc[mlkem.CiphertextSize768:]
	pe, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, err
	}
	ssX, err := sk.ECDH(pe)
	if err != nil {
		return nil, err
	}
	c := sha3.New256()
	for _, b := range [][]byte{ssM, ssX, ctX, sk.PublicKey().Bytes(), refXWingLabel} {
		c.Write(b)
	}
	key, nonce := refSchedule(t, refSuiteID(), c.Sum(nil), []byte("komando sealed file v2"), 32)
	z, err := refGCM(t, key).Open(nil, nonce, file[n:], file[:n])
	if err != nil {
		return nil, err
	}
	return refInflate(z)
}

// refInflate is raw DEFLATE (RFC 1951) read back.
func refInflate(z []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(z))
	defer r.Close()
	return io.ReadAll(r)
}

// refSealPassphrase writes a passphrase file from the deflated content,
// with the salt and nonce given: scrypt(N=2^17, r=8, p=1) and AES-256-GCM.
func refSealPassphrase(t *testing.T, deflated []byte, pass string, salt, nonce []byte, createdAt, madeBy string) []byte {
	t.Helper()
	key, err := scrypt.Key([]byte(pass), salt, 1<<17, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	head := refHead(t, fmt.Sprintf(`{"v":1,"mode":"passphrase","kdf":{"name":"scrypt","n":131072,"r":8,"p":1,"salt":"%s"},"kem":null,`+
		`"compression":"deflate","created_at":"%s","made_by":"%s"}`, base64.StdEncoding.EncodeToString(salt), createdAt, madeBy))
	return refGCM(t, key).Seal(append(head, nonce...), nonce, deflated, head)
}

// TestReferenceOpensSealRecipient opens SealRecipient's files with the
// reference, so the package's sealing side is checked too, not only its
// opening side.
func TestReferenceOpensSealRecipient(t *testing.T) {
	k, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := k.Bytes()
	for _, c := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("komando "), 5000)} {
		f, err := SealRecipient(c, k.PublicKey().Bytes(), Made{By: "komando test"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := refOpenRecipient(t, f, seed)
		if err != nil || !bytes.Equal(got, c) {
			t.Fatalf("%d bytes: %v", len(c), err)
		}
		f[len(f)-1] ^= 1
		if _, err := refOpenRecipient(t, f, seed); err == nil {
			t.Fatal("a changed tag opened")
		}
	}
}

// TestReferenceDraftVector checks the reference's X-Wing (key from seed,
// derandomized Encaps) and key schedule against draft-ietf-hpke-pq's own
// vector, so the reference is the standard and not just a copy of Go's.
func TestReferenceDraftVector(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "xwing_draft_vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	h := func(k string) []byte {
		x, err := hex.DecodeString(v[k])
		if err != nil || len(x) == 0 {
			t.Fatalf("%s: %v", k, err)
		}
		return x
	}
	_, _, pub := refKeys(t, h("skRm"))
	if !bytes.Equal(pub, h("pkRm")) {
		t.Fatal("public key from the seed differs")
	}
	ss, enc := refEncap(t, pub, h("ikmE"))
	if !bytes.Equal(enc, h("enc")) || !bytes.Equal(ss, h("shared_secret")) {
		t.Fatalf("encaps differs: ss %x", ss)
	}
	key, nonce := refSchedule(t, h("suite_id"), ss, h("info"), len(h("key")))
	if !bytes.Equal(key, h("key")) || !bytes.Equal(nonce, h("base_nonce")) {
		t.Fatalf("key schedule differs: key %x nonce %x", key, nonce)
	}
	if want := refSuiteID(); !bytes.Equal(want[:8], h("suite_id")[:8]) {
		t.Fatalf("suite_id %x", want)
	}
}
