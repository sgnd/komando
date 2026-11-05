package cloud

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"

	"github.com/sgnd/komando/internal/store"
)

// Bitwarden and Vaultwarden, with komando's own client: it logs in, syncs
// the vault once per run and decrypts on this computer, as Bitwarden's own
// clients do (the server never sees the master password or the values).
//
// The account comes from the environment:
//
//	KOMANDO_BW_SERVER         https://vault.bitwarden.com (default), .eu, or a Vaultwarden URL
//	KOMANDO_BW_EMAIL          the account's e-mail
//	KOMANDO_BW_PASSWORD       the master password (decrypts the vault)
//	KOMANDO_BW_CLIENT_ID      optional personal API key (user.xxx), with
//	KOMANDO_BW_CLIENT_SECRET  its secret: logs in without the password grant

// Bitwarden reads bw://ITEM/FIELD. FIELD is password, username, notes, uri,
// totp, or the name of a custom field. ITEM is the item's name or id.
func Bitwarden(ctx context.Context, ref string) (string, error) {
	item, field, ok := strings.Cut(strings.TrimPrefix(ref, "bw://"), "/")
	if !ok || item == "" || field == "" {
		return "", errors.New("bw:// references are bw://ITEM/FIELD, e.g. bw://shop-db/password")
	}
	v, err := bwOpen(ctx)
	if err != nil {
		return "", err
	}
	var hits []bwItem
	for _, it := range v {
		if it.ID == item || it.Name == item {
			hits = append(hits, it)
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("bitwarden: no item %q", item)
	case 1:
	default:
		return "", fmt.Errorf("bitwarden: %d items are named %q; use the item's id", len(hits), item)
	}
	it := hits[0]
	switch strings.ToLower(field) {
	case "password":
		return it.Password, nil
	case "username":
		return it.Username, nil
	case "notes":
		return it.Notes, nil
	case "uri", "url":
		return it.URI, nil
	case "totp":
		return it.TOTP, nil
	}
	for name, val := range it.Fields {
		if strings.EqualFold(name, field) {
			return val, nil
		}
	}
	return "", fmt.Errorf("bitwarden: item %q has no field %q", item, field)
}

type bwItem struct {
	ID, Name, Username, Password, Notes, URI, TOTP string
	Fields                                         map[string]string
}

var bwCache struct {
	sync.Mutex
	items []bwItem
}

func bwOpen(ctx context.Context) ([]bwItem, error) {
	bwCache.Lock()
	defer bwCache.Unlock()
	if bwCache.items != nil {
		return bwCache.items, nil
	}
	items, err := bwLoad(ctx)
	if err == nil {
		bwCache.items = items
	}
	return items, err
}

// bwEndpoints are the identity and API addresses for a server.
func bwEndpoints(server string) (identity, api string) {
	server = strings.TrimRight(server, "/")
	switch server {
	case "", "https://vault.bitwarden.com", "https://bitwarden.com":
		return "https://identity.bitwarden.com", "https://api.bitwarden.com"
	case "https://vault.bitwarden.eu", "https://bitwarden.eu":
		return "https://identity.bitwarden.eu", "https://api.bitwarden.eu"
	}
	return server + "/identity", server + "/api"
}

func bwLoad(ctx context.Context) ([]bwItem, error) {
	email, password := os.Getenv("KOMANDO_BW_EMAIL"), os.Getenv("KOMANDO_BW_PASSWORD")
	if email == "" || password == "" {
		return nil, errors.New("bitwarden: set KOMANDO_BW_EMAIL and KOMANDO_BW_PASSWORD (the master password decrypts the vault here)")
	}
	identity, api := bwEndpoints(os.Getenv("KOMANDO_BW_SERVER"))
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var pre struct {
		Kdf, KdfIterations int
		KdfMemory          *int
		KdfParallelism     *int
	}
	if err := bwJSON(ctx, "POST", identity+"/accounts/prelogin", "", map[string]string{"email": email}, &pre); err != nil {
		return nil, err
	}
	master, err := BitwardenMasterKey(password, email, pre.Kdf, pre.KdfIterations, deref(pre.KdfMemory, 64), deref(pre.KdfParallelism, 4))
	if err != nil {
		return nil, err
	}
	form := url.Values{"scope": {"api offline_access"}, "deviceType": {bwDeviceType()}, "deviceName": {"komando"},
		"deviceIdentifier": {bwDeviceID()}, "client_id": {"cli"}}
	if id, sec := os.Getenv("KOMANDO_BW_CLIENT_ID"), os.Getenv("KOMANDO_BW_CLIENT_SECRET"); id != "" && sec != "" {
		form.Set("grant_type", "client_credentials")
		form.Set("scope", "api")
		form.Set("client_id", id)
		form.Set("client_secret", sec)
	} else {
		form.Set("grant_type", "password")
		form.Set("username", email)
		form.Set("password", BitwardenPasswordHash(master, password))
	}
	var tok struct {
		AccessToken      string `json:"access_token"`
		ErrorDescription string `json:"error_description"`
		ErrorModel       *struct{ Message string }
	}
	if err := bwForm(ctx, identity+"/connect/token", email, form, &tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("bitwarden: login refused: %s", firstOf(tok.ErrorDescription, "no token"))
	}
	var sync struct {
		Profile struct {
			Key, PrivateKey string
			Organizations   []struct{ ID, Key string }
		}
		Ciphers []bwCipher
	}
	if err := bwJSON(ctx, "GET", api+"/sync?excludeDomains=true", tok.AccessToken, nil, &sync); err != nil {
		return nil, err
	}
	stretched := BitwardenStretch(master)
	userKey, err := BitwardenDecrypt(sync.Profile.Key, stretched)
	if err != nil || len(userKey) != 64 {
		return nil, errors.New("bitwarden: cannot decrypt the vault key (wrong master password?)")
	}
	orgKeys := map[string][]byte{}
	if sync.Profile.PrivateKey != "" && len(sync.Profile.Organizations) > 0 {
		der, err := BitwardenDecrypt(sync.Profile.PrivateKey, userKey)
		if err == nil {
			if pk, err := x509.ParsePKCS8PrivateKey(der); err == nil {
				if rk, ok := pk.(*rsa.PrivateKey); ok {
					for _, o := range sync.Profile.Organizations {
						if k, err := bwRSA(o.Key, rk); err == nil {
							orgKeys[o.ID] = k
						}
					}
				}
			}
		}
	}
	var items []bwItem
	for _, c := range sync.Ciphers {
		key := userKey
		if c.OrganizationID != "" {
			if key = orgKeys[c.OrganizationID]; key == nil {
				continue
			}
		}
		if c.Key != "" { // an item key, itself encrypted
			if k, err := BitwardenDecrypt(c.Key, key); err == nil && len(k) == 64 {
				key = k
			}
		}
		dec := func(s string) string {
			if s == "" {
				return ""
			}
			b, err := BitwardenDecrypt(s, key)
			if err != nil {
				return ""
			}
			return string(b)
		}
		it := bwItem{ID: c.ID, Name: dec(c.Name), Notes: dec(c.Notes), Fields: map[string]string{}}
		if c.Login != nil {
			it.Username, it.Password, it.TOTP = dec(c.Login.Username), dec(c.Login.Password), dec(c.Login.Totp)
			if len(c.Login.Uris) > 0 {
				it.URI = dec(c.Login.Uris[0].URI)
			}
		}
		for _, f := range c.Fields {
			it.Fields[dec(f.Name)] = dec(f.Value)
		}
		items = append(items, it)
	}
	return items, nil
}

type bwCipher struct {
	ID, OrganizationID, Key, Name, Notes string
	Login                                *struct {
		Username, Password, Totp string
		Uris                     []struct {
			URI string `json:"uri"`
		}
	}
	Fields []struct{ Name, Value string }
}

func deref(p *int, d int) int {
	if p == nil || *p == 0 {
		return d
	}
	return *p
}

// The KDF settings Bitwarden's own clients allow. The server sends them
// before login, so a hostile server could otherwise ask for settings that
// never finish, crash the Argon2 code (p=256 is 0 as a uint8) or wrap around
// to a weak key (m=4194304 MiB is 0 KiB as a uint32).
const (
	bwPBKDF2Max   = 2_000_000
	bwArgonMaxT   = 10
	bwArgonMaxMiB = 1024
	bwArgonMaxP   = 16
)

// BitwardenMasterKey derives the 32-byte master key: kdf 0 is PBKDF2-SHA256
// (salt: the e-mail in lower case), kdf 1 Argon2id (salt: its SHA-256;
// memory in MiB).
func BitwardenMasterKey(password, email string, kdf, iterations, memoryMiB, parallelism int) ([]byte, error) {
	salt := []byte(strings.ToLower(strings.TrimSpace(email)))
	switch kdf {
	case 0:
		if iterations < 5000 {
			return nil, fmt.Errorf("bitwarden: PBKDF2 with %d iterations is too weak to accept", iterations)
		}
		if iterations > bwPBKDF2Max {
			return nil, fmt.Errorf("bitwarden: the server asks for PBKDF2 with %d iterations; Bitwarden allows at most %d", iterations, bwPBKDF2Max)
		}
		return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New), nil
	case 1:
		if iterations < 2 || memoryMiB < 16 || parallelism < 1 {
			return nil, fmt.Errorf("bitwarden: Argon2 settings too weak to accept (t=%d m=%dMiB p=%d)", iterations, memoryMiB, parallelism)
		}
		if iterations > bwArgonMaxT || memoryMiB > bwArgonMaxMiB || parallelism > bwArgonMaxP {
			return nil, fmt.Errorf("bitwarden: the server asks for Argon2 settings Bitwarden does not allow (t=%d m=%dMiB p=%d; at most t=%d m=%dMiB p=%d)",
				iterations, memoryMiB, parallelism, bwArgonMaxT, bwArgonMaxMiB, bwArgonMaxP)
		}
		s := sha256.Sum256(salt)
		return argon2.IDKey([]byte(password), s[:], uint32(iterations), uint32(memoryMiB*1024), uint8(parallelism), 32), nil
	}
	return nil, fmt.Errorf("bitwarden: unknown key derivation %d", kdf)
}

// BitwardenPasswordHash is what the server checks at login: one more
// PBKDF2 round of the master key with the password as salt.
func BitwardenPasswordHash(master []byte, password string) string {
	return base64.StdEncoding.EncodeToString(pbkdf2.Key(master, []byte(password), 1, 32, sha256.New))
}

// BitwardenStretch expands the master key into an encryption and a MAC key
// (64 bytes: enc then mac), with HKDF-Expand.
func BitwardenStretch(master []byte) []byte {
	out := make([]byte, 64)
	io.ReadFull(hkdf.Expand(sha256.New, master, []byte("enc")), out[:32])
	io.ReadFull(hkdf.Expand(sha256.New, master, []byte("mac")), out[32:])
	return out
}

// BitwardenDecrypt opens a type 2 cipher string "2.IV|DATA|MAC"
// (AES-256-CBC with HMAC-SHA256, encrypt-then-MAC). key is 64 bytes.
func BitwardenDecrypt(s string, key []byte) ([]byte, error) {
	typ, rest, ok := strings.Cut(s, ".")
	if !ok || typ != "2" || len(key) != 64 {
		return nil, fmt.Errorf("bitwarden: unsupported cipher string type %q", typ)
	}
	parts := strings.Split(rest, "|")
	if len(parts) != 3 {
		return nil, errors.New("bitwarden: malformed cipher string")
	}
	iv, err1 := base64.StdEncoding.DecodeString(parts[0])
	ct, err2 := base64.StdEncoding.DecodeString(parts[1])
	mac, err3 := base64.StdEncoding.DecodeString(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, errors.New("bitwarden: malformed cipher string")
	}
	m := hmac.New(sha256.New, key[32:])
	m.Write(iv)
	m.Write(ct)
	if !hmac.Equal(m.Sum(nil), mac) {
		return nil, errors.New("bitwarden: integrity check failed")
	}
	if len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("bitwarden: malformed cipher string")
	}
	block, _ := aes.NewCipher(key[:32])
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(out) {
		return nil, errors.New("bitwarden: bad padding")
	}
	return out[:len(out)-pad], nil
}

// BitwardenEncrypt makes a type 2 cipher string (used by tests and the
// e2e seeding; komando itself only reads).
func BitwardenEncrypt(plain, key []byte) (string, error) {
	if len(key) != 64 {
		return "", errors.New("bitwarden: key must be 64 bytes")
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	buf := append(append([]byte{}, plain...), make([]byte, pad)...)
	for i := len(plain); i < len(buf); i++ {
		buf[i] = byte(pad)
	}
	block, _ := aes.NewCipher(key[:32])
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(buf, buf)
	m := hmac.New(sha256.New, key[32:])
	m.Write(iv)
	m.Write(buf)
	enc := base64.StdEncoding.EncodeToString
	return "2." + enc(iv) + "|" + enc(buf) + "|" + enc(m.Sum(nil)), nil
}

// bwRSA opens an organization key: "4.DATA" is RSA-OAEP with SHA-1.
func bwRSA(s string, k *rsa.PrivateKey) ([]byte, error) {
	typ, rest, ok := strings.Cut(s, ".")
	if !ok || typ != "4" {
		return nil, fmt.Errorf("bitwarden: unsupported organization key type %q", typ)
	}
	ct, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha1.New(), nil, k, ct, nil)
}

func bwDeviceType() string {
	// Bitwarden's device types for command-line clients
	switch runtime.GOOS {
	case "darwin":
		return "24"
	case "windows":
		return "23"
	}
	return "25"
}

// bwDeviceID is a stable id for this computer's komando, kept next to the
// state (the server lists it under the account's devices).
func bwDeviceID() string {
	p := store.Path("bitwarden-device")
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		return strings.TrimSpace(string(b))
	}
	b := make([]byte, 16)
	rand.Read(b)
	id := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	_ = os.MkdirAll(store.Home(), 0o700)
	_ = os.WriteFile(p, []byte(id), 0o600)
	return id
}

func bwJSON(ctx context.Context, method, u, token string, body, v any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return bwDo(req, v)
}

func bwForm(ctx context.Context, u, email string, form url.Values, v any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Email", base64.RawURLEncoding.EncodeToString([]byte(email)))
	return bwDo(req, v)
}

func bwDo(req *http.Request, v any) error {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Bitwarden-Client-Name", "komando")
	req.Header.Set("Bitwarden-Client-Version", "1.0.0")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("bitwarden: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			ErrorDescription string `json:"error_description"`
			Message          string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		return fmt.Errorf("bitwarden: %s %s", strconv.Itoa(resp.StatusCode), firstOf(e.ErrorDescription, e.Message, http.StatusText(resp.StatusCode)))
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(b, v)
}
