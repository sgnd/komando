package storex

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
)

// azuriteKey is the emulator's published development key (not a secret).
const azuriteKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

// fakeAzure is the part of the Blob API komando uses, two entries a page.
// It checks that requests are signed, not the signature itself: the
// Azurite test below does that.
type fakeAzure struct {
	mu     sync.Mutex
	blobs  map[string][]byte
	blocks map[string][]byte
	puts   int
}

func (f *fakeAzure) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "SharedKey acct:") || r.Header.Get("x-ms-version") == "" || r.Header.Get("x-ms-date") == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	name, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/media/"))
	switch {
	case r.URL.Path == "/media" && q.Get("comp") == "list":
		f.list(w, q)
	case !strings.HasPrefix(r.URL.Path, "/media"):
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodPut && q.Get("comp") == "block":
		b, _ := io.ReadAll(r.Body)
		f.blocks[q.Get("blockid")] = b
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPut && q.Get("comp") == "blocklist":
		var bl struct {
			Latest []string `xml:"Latest"`
		}
		xml.NewDecoder(r.Body).Decode(&bl)
		var all []byte
		for _, id := range bl.Latest {
			all = append(all, f.blocks[id]...)
		}
		f.blobs[name] = all
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPut:
		if r.Header.Get("x-ms-blob-type") != "BlockBlob" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.blobs[name] = b
		f.puts++
		w.WriteHeader(http.StatusCreated)
	default:
		b, ok := f.blobs[name]
		switch {
		case !ok:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodDelete:
			delete(f.blobs, name)
			w.WriteHeader(http.StatusAccepted)
		default:
			w.Header().Set("Content-Length", fmt.Sprint(len(b)))
			w.Header().Set("Last-Modified", "Sun, 08 Nov 2026 10:00:00 GMT")
			if r.Method == http.MethodGet {
				w.Write(b)
			}
		}
	}
}

func (f *fakeAzure) list(w http.ResponseWriter, q url.Values) {
	prefix, delim := q.Get("prefix"), q.Get("delimiter")
	seen := map[string]bool{}
	var entries []string
	for n := range f.blobs {
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
	fmt.Sscan(q.Get("marker"), &start)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>`)
	for i := start; i < len(entries) && i < start+2; i++ {
		n := entries[i]
		if data, file := f.blobs[n]; file {
			fmt.Fprintf(&b, "<Blob><Name>%s</Name><Properties><Last-Modified>Sun, 08 Nov 2026 10:00:00 GMT</Last-Modified><Content-Length>%d</Content-Length></Properties></Blob>", n, len(data))
		} else {
			fmt.Fprintf(&b, "<BlobPrefix><Name>%s</Name></BlobPrefix>", n)
		}
	}
	b.WriteString("</Blobs><NextMarker>")
	if start+2 < len(entries) {
		fmt.Fprint(&b, start+2)
	}
	b.WriteString("</NextMarker></EnumerationResults>")
	io.WriteString(w, b.String())
}

func TestAzureBlob(t *testing.T) {
	f := &fakeAzure{blobs: map[string][]byte{}, blocks: map[string][]byte{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	tg, err := driver.Parse("azblob://acct@media/site?endpoint=" + srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	saved, savedSingle := azBlock, azSingle
	azBlock, azSingle = 4, 12 // tiny blocks, so the test uploads in blocks
	defer func() { azBlock, azSingle = saved, savedSingle }()
	testBucket(t, func() Bucket {
		b, err := OpenAzure(tg, azuriteKey, nil, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}())
	if _, ok := f.blobs["site/img/x.png"]; !ok {
		t.Errorf("keys live under the conn's folder: %v", f.blobs)
	}
	if f.puts == 0 || len(f.blocks) == 0 {
		t.Errorf("small blobs go up in one request, others in blocks: %d puts, %d blocks", f.puts, len(f.blocks))
	}
	missing, _ := driver.Parse("azblob://acct@other?endpoint=" + srv.URL)
	b, _ := OpenAzure(missing, azuriteKey, nil, time.Second)
	if _, _, err := b.List(context.Background(), "", false, 0); code(err) != "BUCKET_NOT_FOUND" {
		t.Errorf("missing container: %v", err)
	}
	sas, _ := OpenAzure(tg, "sv=2021-08-06&sp=rl&sig=abc", nil, time.Second)
	if _, err := sas.Link(context.Background(), "b.txt", time.Hour); code(err) != "NOT_SUPPORTED" {
		t.Errorf("a SAS-token conn makes no links: %v", err)
	}
	if u := sas.(*azBucket).blobURL("a b.txt", nil); !strings.Contains(u, "/media/a%20b.txt?") || !strings.Contains(u, "sig=abc") {
		t.Errorf("SAS on every request: %s", u)
	}
	for _, bad := range []string{"", "not base64!"} {
		if _, err := OpenAzure(tg, bad, nil, time.Second); err == nil {
			t.Errorf("secret %q: want an error", bad)
		}
	}
}

// testBucket runs the same steps on any bucket: put (small and in
// blocks), list (pages, one level, recursive, limit), get, stat, exists,
// remove and link.
func testBucket(t *testing.T, b Bucket) {
	t.Helper()
	ctx := context.Background()
	for _, k := range []string{"a.txt", "b.txt", "c d.txt", "img/x.png", "img/y.png"} {
		body := "data-" + k
		size := int64(len(body))
		if k == "b.txt" {
			size = -1 // unknown: goes up in blocks
		}
		if err := b.Put(ctx, k, strings.NewReader(body), size, ""); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
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
		t.Fatalf("one level: %q %v %v", keys(objs), more, err)
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
	if _, err := b.Get(ctx, "b.txt", &buf); err != nil || buf.String() != "data-b.txt" {
		t.Errorf("get of a blob sent in blocks: %q %v", buf.String(), err)
	}
	if o, err := b.Stat(ctx, "c d.txt"); err != nil || o.Size != len64("data-c d.txt") || o.Modified.IsZero() {
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
	if err := b.Remove(ctx, "a.txt"); err != nil {
		t.Errorf("removing a missing blob: %v", err)
	}
	if _, err := b.Get(ctx, "../x", &buf); code(err) != "USAGE" {
		t.Errorf("a key may not leave the folder: %v", err)
	}
}

// TestAzurite runs the same steps against the Azure Storage emulator,
// which checks every Shared Key signature and the SAS of a link:
//
//	docker run -d -p 10000:10000 mcr.microsoft.com/azure-storage/azurite azurite-blob --blobHost 0.0.0.0
//	KOMANDO_TEST_AZURITE=http://127.0.0.1:10000 go test ./internal/storex -run Azurite
func TestAzurite(t *testing.T) {
	base := os.Getenv("KOMANDO_TEST_AZURITE")
	if base == "" {
		t.Skip("KOMANDO_TEST_AZURITE is not set")
	}
	container := os.Getenv("KOMANDO_TEST_AZURITE_CONTAINER") // the e2e's, which its conn then uses
	if container == "" {
		container = fmt.Sprintf("komando%d", time.Now().UnixNano())
	}
	tg, err := driver.Parse("azblob://devstoreaccount1@" + container + "/site?endpoint=" + base + "/devstoreaccount1")
	if err != nil {
		t.Fatal(err)
	}
	bk, err := OpenAzure(tg, azuriteKey, nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b := bk.(*azBucket)
	ctx := context.Background()
	resp, err := b.send(ctx, http.MethodPut, b.blobURL("", url.Values{"restype": {"container"}}), nil, -1, nil, http.StatusCreated, http.StatusConflict)
	if err != nil {
		t.Fatalf("create the container (a Shared Key signature Azurite checks): %v", err)
	}
	resp.Body.Close()
	saved, savedSingle := azBlock, azSingle
	azBlock, azSingle = 4, 12
	defer func() { azBlock, azSingle = saved, savedSingle }()
	testBucket(t, b)

	link, err := b.Link(ctx, "c d.txt", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.Get(link.String()) // no credentials: the SAS alone
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || string(body) != "data-c d.txt" || !strings.Contains(r.Header.Get("Content-Disposition"), "c d.txt") {
		t.Errorf("link: %s %q %q", r.Status, body, r.Header.Get("Content-Disposition"))
	}

	// the emulator really checks the signature: another key is refused
	wrong, _ := OpenAzure(tg, "d3Jvbmcta2V5LXdyb25nLWtleS13cm9uZy1rZXk=", nil, 30*time.Second)
	if _, _, err := wrong.List(ctx, "", false, 0); code(err) != "STORAGE_AUTH" {
		t.Errorf("a wrong key: %v", err)
	}
}
