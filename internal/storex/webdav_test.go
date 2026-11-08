package storex

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/webdav"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// davServer is a real WebDAV server (x/net/webdav) under /dav, with basic
// auth alice:pw.
func davServer(t *testing.T) *url.URL {
	t.Helper()
	h := &webdav.Handler{Prefix: "/dav", FileSystem: webdav.NewMemFS(), LockSystem: webdav.NewMemLS()}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "alice" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u
}

func openDav(t *testing.T, u *url.URL, pw string) Bucket {
	t.Helper()
	tg, err := driver.Parse("webdav://alice@" + u.Host + "/dav?insecure=1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenWebDAV(tg, pw, nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func code(err error) string {
	if oe, ok := err.(*out.Error); ok {
		return oe.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func TestWebDAV(t *testing.T) {
	ctx := context.Background()
	b := openDav(t, davServer(t), "pw")
	for key, body := range map[string]string{"a/b.txt": "hello", "a/deep/c.txt": "deep", "top file é.txt": "top"} {
		if err := b.Put(ctx, key, strings.NewReader(body), int64(len(body)), "text/plain"); err != nil {
			t.Fatalf("put %s: %v", key, err)
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
	if err != nil || more || keys(objs) != "a/,top file é.txt" {
		t.Fatalf("one level: %q %v %v", keys(objs), more, err)
	}
	if objs[1].Size != 3 || objs[1].Modified.IsZero() || !objs[0].Dir {
		t.Errorf("entries: %+v", objs)
	}
	objs, _, err = b.List(ctx, "a", true, 0)
	if err != nil || keys(objs) != "a/b.txt,a/deep/,a/deep/c.txt" {
		t.Errorf("recursive under a: %q %v", keys(objs), err)
	}
	if objs, more, _ = b.List(ctx, "", true, 2); len(objs) != 2 || !more {
		t.Errorf("limit: %d %v", len(objs), more)
	}
	if _, _, err = b.List(ctx, "nope", false, 0); code(err) != "FOLDER_NOT_FOUND" {
		t.Errorf("missing folder: %v", err)
	}

	var buf bytes.Buffer
	if n, err := b.Get(ctx, "a/deep/c.txt", &buf); err != nil || n != 4 || buf.String() != "deep" {
		t.Errorf("get: %d %q %v", n, buf.String(), err)
	}
	if o, err := b.Stat(ctx, "top file é.txt"); err != nil || o.Key != "top file é.txt" || o.Size != 3 {
		t.Errorf("stat: %+v %v", o, err)
	}
	if _, err := b.Stat(ctx, "a"); code(err) != "USAGE" {
		t.Errorf("stat of a folder: %v", err)
	}
	if ok, err := b.Exists(ctx, "nope.txt"); ok || err != nil {
		t.Errorf("exists of a missing file: %v %v", ok, err)
	}
	if _, err := b.Get(ctx, "nope.txt", &buf); code(err) != "OBJECT_NOT_FOUND" {
		t.Errorf("get of a missing file: %v", err)
	}
	if err := b.Remove(ctx, "a/b.txt"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := b.Exists(ctx, "a/b.txt"); ok {
		t.Error("removed file still there")
	}
	if err := b.Remove(ctx, "a/deep"); code(err) != "USAGE" {
		t.Errorf("remove of a folder: %v", err)
	}
	if _, err := b.Stat(ctx, "../etc/passwd"); code(err) != "USAGE" {
		t.Errorf("a key may not leave the folder: %v", err)
	}
	if _, err := b.Link(ctx, "a/deep/c.txt", time.Hour); code(err) != "NOT_SUPPORTED" {
		t.Errorf("link: %v", err)
	}
}

func TestWebDAVWrongPassword(t *testing.T) {
	b := openDav(t, davServer(t), "wrong")
	if _, _, err := b.List(context.Background(), "", false, 0); code(err) != "STORAGE_AUTH" {
		t.Errorf("wrong password: %v", err)
	}
}

func TestWebDAVURLs(t *testing.T) {
	for raw, want := range map[string]string{
		"webdavs://alice@cloud.example.com/remote.php/dav/files/alice": "cloud.example.com:443 remote.php/dav/files/alice/ alice true",
		"webdavs://nas.lan:5006/home?tls=skip-verify":                  "nas.lan:5006 home/  true",
		"webdav://bob@10.0.0.5/dav?insecure=1":                         "10.0.0.5:80 dav/ bob false",
	} {
		tg, err := driver.Parse(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		got := strings.Join([]string{tg.Address, tg.Prefix, tg.User, map[bool]string{true: "true", false: "false"}[tg.Secure]}, " ")
		if got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
	for raw, wantCode := range map[string]string{
		"webdav://bob@10.0.0.5/dav":     "INSECURE_PROTOCOL",
		"webdavs://bob@host/x?tls=yes":  "USAGE",
		"webdavs://bob@host/x?bucket=1": "USAGE",
		"webdavs://bob:secret@host/x":   "URL_HAS_PASSWORD",
	} {
		if _, err := driver.Parse(raw); code(err) != wantCode {
			t.Errorf("%s: %v, want %s", raw, err, wantCode)
		}
	}
}

func TestWebDAVMakesTheConnFolder(t *testing.T) {
	u := davServer(t)
	tg, _ := driver.Parse("webdav://alice@" + u.Host + "/dav/new?insecure=1")
	b, _ := OpenWebDAV(tg, "pw", nil, 10*time.Second)
	ctx := context.Background()
	if err := b.Put(ctx, "x/y.txt", strings.NewReader("hi"), 2, ""); err != nil {
		t.Fatalf("upload into a conn folder that is not there yet: %v", err)
	}
	if objs, _, err := b.List(ctx, "x", false, 0); err != nil || len(objs) != 1 || objs[0].Key != "x/y.txt" {
		t.Errorf("list: %+v %v", objs, err)
	}
}
