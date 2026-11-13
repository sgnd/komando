package cloud

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tobischo/gokeepasslib/v3"
	w "github.com/tobischo/gokeepasslib/v3/wrappers"
)

func TestOnePasswordConnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer conn-token" {
			rw.WriteHeader(http.StatusUnauthorized)
			io.WriteString(rw, `{"message":"invalid token"}`)
			return
		}
		switch {
		case r.URL.Path == "/v1/vaults" && strings.Contains(r.URL.RawQuery, "Shop"):
			io.WriteString(rw, `[{"id":"v1","name":"Shop"}]`)
		case r.URL.Path == "/v1/vaults":
			io.WriteString(rw, `[]`)
		case r.URL.Path == "/v1/vaults/v1/items":
			io.WriteString(rw, `[{"id":"i1","title":"shop-db"}]`)
		case r.URL.Path == "/v1/vaults/v1/items/i1":
			io.WriteString(rw, `{"fields":[{"id":"password","label":"password","value":"pw1"},
				{"id":"x","label":"password","value":"pw-admin","section":{"id":"s1","label":"Admin"}}]}`)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("OP_CONNECT_HOST", "")
	t.Setenv("OP_CONNECT_TOKEN", "")
	if _, err := OnePassword(context.Background(), "op://Shop/shop-db/password"); err != ErrNoConnect {
		t.Errorf("no Connect: %v", err)
	}
	t.Setenv("OP_CONNECT_HOST", srv.URL)
	t.Setenv("OP_CONNECT_TOKEN", "conn-token")
	for ref, want := range map[string]string{
		"op://Shop/shop-db/password":       "pw1",
		"op://Shop/shop-db/Admin/password": "pw-admin",
	} {
		if got, err := OnePassword(context.Background(), ref); err != nil || got != want {
			t.Errorf("%s: %q %v", ref, got, err)
		}
	}
	for ref, want := range map[string]string{"op://Nope/x/y": "no vault", "op://Shop/shop-db/nope": "no field", "op://Shop/x": "op://VAULT/ITEM/FIELD"} {
		if _, err := OnePassword(context.Background(), ref); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", ref, err, want)
		}
	}
}

func TestKeePass(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "team.kdbx")
	entry := gokeepasslib.NewEntry()
	entry.Values = append(entry.Values,
		gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: "web1"}},
		gokeepasslib.ValueData{Key: "UserName", Value: gokeepasslib.V{Content: "deploy"}},
		gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: "kp-secret", Protected: w.NewBoolWrapper(true)}},
		gokeepasslib.ValueData{Key: "sudo", Value: gokeepasslib.V{Content: "kp-sudo", Protected: w.NewBoolWrapper(true)}})
	servers := gokeepasslib.NewGroup()
	servers.Name = "Servers"
	servers.Entries = append(servers.Entries, entry)
	root := gokeepasslib.NewGroup()
	root.Name = "Team"
	root.Groups = append(root.Groups, servers)
	db := gokeepasslib.NewDatabase(gokeepasslib.WithDatabaseKDBXVersion40())
	db.Credentials = gokeepasslib.NewPasswordCredentials("master-pw")
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}
	if err := db.LockProtectedEntries(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		t.Fatal(err)
	}
	f.Close()

	t.Setenv("KOMANDO_KDBX_KEYFILE", "")
	t.Setenv("KOMANDO_KDBX_PASSWORD", "")
	if _, err := KeePass(file + "#Servers/web1"); err == nil || !strings.Contains(err.Error(), "KOMANDO_KDBX_PASSWORD") {
		t.Errorf("no password: %v", err)
	}
	t.Setenv("KOMANDO_KDBX_PASSWORD", "wrong")
	if _, err := KeePass(file + "#Servers/web1"); err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Errorf("wrong password: %v", err)
	}
	t.Setenv("KOMANDO_KDBX_PASSWORD", "master-pw")
	for ref, want := range map[string]string{
		file + "#Servers/web1":          "kp-secret",
		file + "#Team/Servers/web1":     "kp-secret",
		file + "#Servers/web1#UserName": "deploy",
		file + "#Servers/web1#sudo":     "kp-sudo",
	} {
		if got, err := KeePass(ref); err != nil || got != want {
			t.Errorf("%s: %q %v", ref, got, err)
		}
	}
	for ref, want := range map[string]string{file + "#Nope/web1": "no group", file + "#Servers/x": "no entry", file + "#Servers/web1#x": "no field", file: "references are"} {
		if _, err := KeePass(ref); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", ref, err, want)
		}
	}
}

func TestBitwardenCrypto(t *testing.T) {
	// the PBKDF2 test vector from Bitwarden's own documentation of the
	// key derivation: master key and the login hash for user@example.com
	mk, err := BitwardenMasterKey("password", "user@example.com", 0, 600000, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(mk) != 32 {
		t.Fatalf("master key %d bytes", len(mk))
	}
	if _, err := BitwardenMasterKey("password", "a@b", 0, 1000, 0, 0); err == nil {
		t.Error("weak PBKDF2 must be refused")
	}
	if _, err := BitwardenMasterKey("password", "a@b", 1, 3, 64, 4); err != nil {
		t.Errorf("argon2id: %v", err)
	}
	key := make([]byte, 64)
	rand.Read(key)
	for _, plain := range []string{"", "x", "exactly16bytes!!", strings.Repeat("long ", 50)} {
		s, err := BitwardenEncrypt([]byte(plain), key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := BitwardenDecrypt(s, key)
		if err != nil || string(got) != plain {
			t.Errorf("round trip %q: %q %v", plain, got, err)
		}
	}
	s, _ := BitwardenEncrypt([]byte("secret"), key)
	parts := strings.Split(s, "|")
	parts[1] = base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := BitwardenDecrypt(strings.Join(parts, "|"), key); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Errorf("tampered data: %v", err)
	}
	for _, bad := range []string{"0.abc", "2.only|two", "garbage"} {
		if _, err := BitwardenDecrypt(bad, key); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

// fakeBitwarden is a server holding one account, built with the same
// crypto a Bitwarden client uses: a personal item, an item with its own
// key, and an organization item.
func fakeBitwarden(t *testing.T, email, password string) *httptest.Server {
	t.Helper()
	master, _ := BitwardenMasterKey(password, email, 0, 600000, 0, 0)
	userKey := make([]byte, 64)
	rand.Read(userKey)
	encUserKey, _ := BitwardenEncrypt(userKey, BitwardenStretch(master))
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(rk)
	encPriv, _ := BitwardenEncrypt(der, userKey)
	orgKey := make([]byte, 64)
	rand.Read(orgKey)
	encOrg, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &rk.PublicKey, orgKey, nil)
	itemKey := make([]byte, 64)
	rand.Read(itemKey)
	e := func(s string, k []byte) string { c, _ := BitwardenEncrypt([]byte(s), k); return c }
	encItemKey, _ := BitwardenEncrypt(itemKey, userKey)
	sync := map[string]any{
		"profile": map[string]any{"key": encUserKey, "privateKey": encPriv,
			"organizations": []any{map[string]any{"id": "org1", "key": "4." + base64.StdEncoding.EncodeToString(encOrg)}}},
		"ciphers": []any{
			map[string]any{"id": "c1", "name": e("shop-db", userKey), "notes": e("the shop", userKey),
				"login": map[string]any{"username": e("app", userKey), "password": e("bw-pw", userKey),
					"uris": []any{map[string]any{"uri": e("postgres://db", userKey)}}},
				"fields": []any{map[string]any{"name": e("pin", userKey), "value": e("1234", userKey)}}},
			map[string]any{"id": "c2", "key": encItemKey, "name": e("keyed", itemKey),
				"login": map[string]any{"password": e("item-key-pw", itemKey)}},
			map[string]any{"id": "c3", "organizationId": "org1", "name": e("team-db", orgKey),
				"login": map[string]any{"password": e("org-pw", orgKey)}},
			map[string]any{"id": "c4", "organizationId": "unknown-org", "name": "2.x|y|z"},
		},
	}
	want := BitwardenPasswordHash(master, password)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/identity/accounts/prelogin":
			io.WriteString(rw, `{"kdf":0,"kdfIterations":600000}`)
		case "/identity/connect/token":
			r.ParseForm()
			if r.Form.Get("password") != want || !strings.EqualFold(r.Form.Get("username"), email) || r.Form.Get("grant_type") != "password" {
				rw.WriteHeader(http.StatusBadRequest)
				io.WriteString(rw, `{"error":"invalid_grant","error_description":"Username or password is incorrect. Try again."}`)
				return
			}
			io.WriteString(rw, `{"access_token":"at","token_type":"Bearer"}`)
		case "/api/sync":
			if r.Header.Get("Authorization") != "Bearer at" {
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			json.NewEncoder(rw).Encode(sync)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBitwarden(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("USERPROFILE", fakeHome) // os.UserHomeDir reads USERPROFILE on Windows
	srv := fakeBitwarden(t, "Dev@Example.com", "correct horse")
	resetBW := func() { bwCache.Lock(); bwCache.items = nil; bwCache.Unlock() }
	defer resetBW()
	t.Setenv("KOMANDO_BW_SERVER", srv.URL)
	t.Setenv("KOMANDO_BW_CLIENT_ID", "")
	t.Setenv("KOMANDO_BW_EMAIL", "dev@example.com")
	t.Setenv("KOMANDO_BW_PASSWORD", "wrong")
	if _, err := Bitwarden(context.Background(), "bw://shop-db/password"); err == nil || !strings.Contains(err.Error(), "incorrect") {
		t.Errorf("wrong password: %v", err)
	}
	resetBW()
	t.Setenv("KOMANDO_BW_PASSWORD", "correct horse")
	for ref, want := range map[string]string{
		"bw://shop-db/password": "bw-pw", "bw://shop-db/username": "app", "bw://shop-db/notes": "the shop",
		"bw://shop-db/uri": "postgres://db", "bw://shop-db/PIN": "1234", "bw://c1/password": "bw-pw",
		"bw://keyed/password": "item-key-pw", "bw://team-db/password": "org-pw",
	} {
		if got, err := Bitwarden(context.Background(), ref); err != nil || got != want {
			t.Errorf("%s: %q %v", ref, got, err)
		}
	}
	for ref, want := range map[string]string{"bw://nope/password": "no item", "bw://shop-db/nope": "no field", "bw://shop-db": "bw://ITEM/FIELD"} {
		if _, err := Bitwarden(context.Background(), ref); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", ref, err, want)
		}
	}
	if id, api := bwEndpoints("https://vault.bitwarden.com/"); id != "https://identity.bitwarden.com" || api != "https://api.bitwarden.com" {
		t.Errorf("cloud endpoints %s %s", id, api)
	}
}
