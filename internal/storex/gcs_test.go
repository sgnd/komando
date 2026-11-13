package storex

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/sgnd/komando/internal/driver"
)

// fakeGCS is the part of the GCS JSON API komando uses, two items a page.
type fakeGCS struct {
	mu      sync.Mutex
	objs    map[string][]byte
	sawAuth bool // a request came with an Authorization header
}

func (f *fakeGCS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "" {
		f.sawAuth = true // an emulator: no login is sent to it
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p := r.URL.EscapedPath()
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/upload/storage/v1/b/media/o"):
		b, _ := io.ReadAll(r.Body)
		f.objs[r.URL.Query().Get("name")] = b
		w.Write([]byte(`{}`))
	case strings.HasPrefix(p, "/storage/v1/b/media/o/"):
		name, _ := url.PathUnescape(strings.TrimPrefix(p, "/storage/v1/b/media/o/"))
		b, ok := f.objs[name]
		switch {
		case !ok:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodDelete:
			delete(f.objs, name)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Query().Get("alt") == "media":
			w.Write(b)
		default:
			json.NewEncoder(w).Encode(map[string]any{"name": name, "size": itoa(len(b)), "updated": "2026-11-08T10:00:00Z"})
		}
	case p == "/storage/v1/b/media/o":
		f.list(w, r.URL.Query())
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func (f *fakeGCS) list(w http.ResponseWriter, q url.Values) {
	prefix, delim := q.Get("prefix"), q.Get("delimiter")
	seen := map[string]bool{}
	var entries []string // names and folder prefixes, in name order, as GCS pages them
	for n := range f.objs {
		if !strings.HasPrefix(n, prefix) {
			continue
		}
		if i := strings.Index(n[len(prefix):], "/"); delim == "/" && i >= 0 {
			n = n[:len(prefix)+i+1]
		}
		if !seen[n] {
			seen[n] = true
			entries = append(entries, n)
		}
	}
	sort.Strings(entries)
	start := 0
	if t := q.Get("pageToken"); t != "" {
		start, _ = strconv.Atoi(t)
	}
	page := map[string]any{"items": []any{}, "prefixes": []string{}}
	for i := start; i < len(entries) && i < start+2; i++ {
		n := entries[i]
		if _, file := f.objs[n]; !file {
			page["prefixes"] = append(page["prefixes"].([]string), n)
			continue
		}
		page["items"] = append(page["items"].([]any), map[string]any{"name": n, "size": itoa(len(f.objs[n])), "updated": "2026-11-08T10:00:00Z"})
	}
	if start+2 < len(entries) {
		page["nextPageToken"] = strconv.Itoa(start + 2)
	}
	json.NewEncoder(w).Encode(page)
}

func withGCSLogin(t *testing.T) {
	t.Helper()
	saved := gcsDefaultCredentials
	gcsDefaultCredentials = func(context.Context) (*google.Credentials, error) {
		return &google.Credentials{TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok"})}, nil
	}
	t.Cleanup(func() { gcsDefaultCredentials = saved })
}

func TestGCS(t *testing.T) {
	withGCSLogin(t)
	f := &fakeGCS{objs: map[string][]byte{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	tg, err := driver.Parse("gs://media/site?endpoint=" + srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenGCS(context.Background(), tg, "", nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, k := range []string{"a.txt", "b.txt", "c d.txt", "img/x.png", "img/y.png"} {
		if err := b.Put(ctx, k, strings.NewReader("data-"+k), int64(len("data-"+k)), ""); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}
	if _, ok := f.objs["site/img/x.png"]; !ok {
		t.Fatalf("keys live under the conn's folder: %v", f.objs)
	}
	keys := func(objs []Object) string {
		var k []string
		for _, o := range objs {
			k = append(k, o.Key)
		}
		return strings.Join(k, ",")
	}
	objs, more, err := b.List(ctx, "", false, 0)
	if err != nil || more || keys(objs) != "a.txt,b.txt,c d.txt,img/" {
		t.Fatalf("one level over two pages: %q %v %v", keys(objs), more, err)
	}
	if objs[0].Size != len64("data-a.txt") || objs[0].Modified.IsZero() || !objs[3].Dir {
		t.Errorf("entries: %+v", objs)
	}
	if objs, _, _ := b.List(ctx, "img/", true, 0); keys(objs) != "img/x.png,img/y.png" {
		t.Errorf("recursive: %q", keys(objs))
	}
	if objs, more, _ := b.List(ctx, "", true, 3); len(objs) != 3 || !more {
		t.Errorf("limit: %d %v", len(objs), more)
	}
	var buf bytes.Buffer
	if _, err := b.Get(ctx, "c d.txt", &buf); err != nil || buf.String() != "data-c d.txt" {
		t.Errorf("get: %q %v", buf.String(), err)
	}
	if o, err := b.Stat(ctx, "img/x.png"); err != nil || o.Size != len64("data-img/x.png") {
		t.Errorf("stat: %+v %v", o, err)
	}
	if ok, err := b.Exists(ctx, "nope"); ok || err != nil {
		t.Errorf("exists: %v %v", ok, err)
	}
	if err := b.Remove(ctx, "a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Stat(ctx, "a.txt"); code(err) != "OBJECT_NOT_FOUND" {
		t.Errorf("after remove: %v", err)
	}
	if _, err := b.Link(ctx, "b.txt", time.Hour); code(err) != "NOT_SUPPORTED" {
		t.Errorf("a link without a service account key: %v", err)
	}
	other, _ := driver.Parse("gs://other?endpoint=" + srv.URL)
	ob, _ := OpenGCS(ctx, other, "", nil, 10*time.Second)
	if _, _, err := ob.List(ctx, "", false, 0); code(err) != "BUCKET_NOT_FOUND" {
		t.Errorf("missing bucket: %v", err)
	}
	if f.sawAuth {
		t.Error("gcloud's login went to an endpoint that is not Google's")
	}
}

// gcloud's login (found on this computer) goes only to Google over HTTPS,
// and a service account key's token never travels unencrypted.
func TestGCSLoginStaysWithGoogle(t *testing.T) {
	for raw, want := range map[string]bool{
		"gs://media": true,
		"gs://media?endpoint=https://restricted.googleapis.com":  true,
		"gs://media?endpoint=https://storage-x.p.googleapis.com": true,
		"gs://media?endpoint=http://storage.googleapis.com":      false,
		"gs://media?endpoint=https://googleapis.com.evil.io":     false,
		"gs://media?endpoint=https://fake-gcs:4443":              false,
	} {
		tg, err := driver.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if gcsGoogleHost(tg) != want {
			t.Errorf("%s: Google's own: %v", raw, !want)
		}
	}
	tg, _ := driver.Parse("gs://media?endpoint=http://fake-gcs:4443")
	if _, err := OpenGCS(context.Background(), tg, `{"type":"service_account"}`, nil, time.Second); code(err) != "INSECURE_PROTOCOL" {
		t.Errorf("a key over http: %v", err)
	}
}

func len64(s string) int64 { return int64(len(s)) }

func TestGCSSignedLink(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "bot@proj.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	s := newGCSSigner(sa)
	if s == nil {
		t.Fatal("no signer from a service account key")
	}
	now := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	u, err := s.sign("media", "site/report q3.pdf", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "storage.googleapis.com" || u.EscapedPath() != "/media/site/report%20q3.pdf" ||
		q.Get("X-Goog-Credential") != "bot@proj.iam.gserviceaccount.com/20261108/auto/storage/goog4_request" ||
		q.Get("X-Goog-Date") != "20261108T100000Z" || q.Get("X-Goog-Expires") != "3600" {
		t.Errorf("link: %s", u)
	}
	// the signature verifies with the public key over the V4 string to sign
	raw := u.RawQuery[:strings.Index(u.RawQuery, "&X-Goog-Signature=")]
	creq := strings.Join([]string{"GET", u.EscapedPath(), raw, "host:storage.googleapis.com", "", "host", "UNSIGNED-PAYLOAD"}, "\n")
	h := sha256.Sum256([]byte(creq))
	toSign := "GOOG4-RSA-SHA256\n20261108T100000Z\n20261108/auto/storage/goog4_request\n" + hex.EncodeToString(h[:])
	d := sha256.Sum256([]byte(toSign))
	sig, _ := hex.DecodeString(q.Get("X-Goog-Signature"))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, d[:], sig); err != nil {
		t.Errorf("signature: %v", err)
	}
	if _, err := s.sign("media", "x", 8*24*time.Hour, now); code(err) != "USAGE" {
		t.Errorf("over 7 days: %v", err)
	}
	if newGCSSigner([]byte(`{"type":"authorized_user"}`)) != nil {
		t.Error("gcloud's user login cannot sign")
	}
}

func TestGCSURLs(t *testing.T) {
	tg, err := driver.Parse("gs://media/site/assets")
	if err != nil || tg.Bucket != "media" || tg.Prefix != "site/assets/" || tg.Address != "storage.googleapis.com:443" || !tg.Secure {
		t.Errorf("gs URL: %+v %v", tg, err)
	}
	for _, bad := range []string{"gs://user@media/x", "gs:///x", "gs://media?region=eu"} {
		if _, err := driver.Parse(bad); code(err) != "USAGE" {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestGCSKeyMustBeServiceAccount(t *testing.T) {
	tg, _ := driver.Parse("gs://media")
	for _, key := range []string{`{"type":"authorized_user","client_id":"x"}`, `not json`} {
		if _, err := OpenGCS(context.Background(), tg, key, nil, time.Second); code(err) != "STORAGE_AUTH" {
			t.Errorf("%s: %v", key, err)
		}
	}
}
