// Command bwseed creates a Vaultwarden account with one login item, the way
// a Bitwarden client does (keys made and encrypted here), for the e2e test
// of komando's bw:// references.
//
//	go run ./test/e2e/bwseed SERVER EMAIL PASSWORD ITEM ITEM_PASSWORD
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/sgnd/komando/internal/cloud"
)

func main() {
	if len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: bwseed SERVER EMAIL PASSWORD ITEM ITEM_PASSWORD")
		os.Exit(2)
	}
	server, email, password, item, itemPW := strings.TrimRight(os.Args[1], "/"), os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	must := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, "bwseed:", err)
			os.Exit(1)
		}
	}
	const iter = 600000
	master, err := cloud.BitwardenMasterKey(password, email, 0, iter, 0, 0)
	must(err)
	userKey := make([]byte, 64)
	rand.Read(userKey)
	encKey, err := cloud.BitwardenEncrypt(userKey, cloud.BitwardenStretch(master))
	must(err)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	pub, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	priv, _ := x509.MarshalPKCS8PrivateKey(rk)
	encPriv, err := cloud.BitwardenEncrypt(priv, userKey)
	must(err)

	post := func(path, ctype string, body []byte, token string, v any) {
		req, _ := http.NewRequest("POST", server+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", ctype)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		must(err)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode/100 != 2 {
			must(fmt.Errorf("%s: %s %s", path, resp.Status, b))
		}
		if v != nil {
			must(json.Unmarshal(b, v))
		}
	}
	j := func(v any) []byte { b, _ := json.Marshal(v); return b }
	post("/identity/accounts/register", "application/json", j(map[string]any{
		"email": email, "name": "e2e", "masterPasswordHash": cloud.BitwardenPasswordHash(master, password),
		"masterPasswordHint": "", "key": encKey, "kdf": 0, "kdfIterations": iter,
		"keys": map[string]string{"publicKey": base64.StdEncoding.EncodeToString(pub), "encryptedPrivateKey": encPriv},
	}), "", nil)

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	form := url.Values{"grant_type": {"password"}, "username": {email}, "password": {cloud.BitwardenPasswordHash(master, password)},
		"scope": {"api offline_access"}, "client_id": {"cli"}, "deviceType": {"25"}, "deviceName": {"bwseed"},
		"deviceIdentifier": {"00000000-0000-4000-8000-000000000001"}}
	post("/identity/connect/token", "application/x-www-form-urlencoded", []byte(form.Encode()), "", &tok)

	e := func(s string) string { c, err := cloud.BitwardenEncrypt([]byte(s), userKey); must(err); return c }
	post("/api/ciphers", "application/json", j(map[string]any{
		"type": 1, "name": e(item), "notes": nil, "favorite": false,
		"login": map[string]any{"username": e("agent"), "password": e(itemPW)},
	}), tok.AccessToken, nil)
	fmt.Println("seeded", item)
}
