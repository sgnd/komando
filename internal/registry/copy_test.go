package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// fakeRegistry is the part of the OCI distribution API that Copy uses.
type fakeRegistry struct {
	mu        sync.Mutex
	manifests map[string][]byte // repo@ref -> body
	ctypes    map[string]string
	blobs     map[string][]byte // digest -> content
	repoBlobs map[string]bool   // repo@digest
	uploads   map[string]string // upload id -> repo
}

func newFake() (*fakeRegistry, *httptest.Server) {
	f := &fakeRegistry{manifests: map[string][]byte{}, ctypes: map[string]string{}, blobs: map[string][]byte{},
		repoBlobs: map[string]bool{}, uploads: map[string]string{}}
	return f, httptest.NewServer(f)
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func (f *fakeRegistry) addBlob(repo string, b []byte) descriptor {
	d := digestOf(b)
	f.blobs[d], f.repoBlobs[repo+"@"+d] = b, true
	return descriptor{MediaType: "application/octet-stream", Digest: d, Size: int64(len(b))}
}

func (f *fakeRegistry) addManifest(repo, ref, ctype string, v any) string {
	b, _ := json.Marshal(v)
	d := digestOf(b)
	for _, r := range []string{ref, d} {
		f.manifests[repo+"@"+r], f.ctypes[repo+"@"+r] = b, ctype
	}
	return d
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v2/")
	switch {
	case strings.Contains(p, "/manifests/"):
		repo, ref, _ := strings.Cut(p, "/manifests/")
		key := repo + "@" + ref
		if r.Method == "PUT" {
			b, _ := io.ReadAll(r.Body)
			d := digestOf(b)
			for _, k := range []string{key, repo + "@" + d} {
				f.manifests[k], f.ctypes[k] = b, r.Header.Get("Content-Type")
			}
			w.WriteHeader(201)
			return
		}
		b, ok := f.manifests[key]
		if !ok {
			http.Error(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, 404)
			return
		}
		w.Header().Set("Content-Type", f.ctypes[key])
		w.Header().Set("Docker-Content-Digest", digestOf(b))
		if r.Method == "GET" {
			w.Write(b)
		}
	case strings.Contains(p, "/blobs/uploads/"):
		repo, id, _ := strings.Cut(p, "/blobs/uploads/")
		switch r.Method {
		case "POST":
			if m := r.URL.Query().Get("mount"); m != "" && f.repoBlobs[r.URL.Query().Get("from")+"@"+m] {
				f.repoBlobs[repo+"@"+m] = true
				w.WriteHeader(201)
				return
			}
			id := fmt.Sprint(len(f.uploads) + 1)
			f.uploads[id] = repo
			w.Header().Set("Location", "/v2/"+repo+"/blobs/uploads/"+id)
			w.WriteHeader(202)
		case "PUT":
			b, _ := io.ReadAll(r.Body)
			if want := r.URL.Query().Get("digest"); digestOf(b) != want {
				http.Error(w, "digest mismatch", 400)
				return
			}
			f.addBlob(f.uploads[id], b)
			w.WriteHeader(201)
		case "DELETE":
			w.WriteHeader(204)
		}
	case strings.Contains(p, "/blobs/"):
		repo, d, _ := strings.Cut(p, "/blobs/")
		if !f.repoBlobs[repo+"@"+d] {
			http.Error(w, `{"errors":[{"code":"BLOB_UNKNOWN"}]}`, 404)
			return
		}
		if r.Method == "GET" {
			w.Write(f.blobs[d])
		}
	default:
		http.NotFound(w, r)
	}
}

func client(t *testing.T, s *httptest.Server) *Client {
	u, _ := url.Parse(s.URL)
	return New(u.Host, TLS{Plain: true}, "", "", nil)
}

func TestCopyMultiPlatform(t *testing.T) {
	src, srcSrv := newFake()
	defer srcSrv.Close()
	dst, dstSrv := newFake()
	defer dstSrv.Close()

	shared := src.addBlob("app", []byte("shared base layer"))
	var children []descriptor
	for _, arch := range []string{"amd64", "arm64"} {
		cfg := src.addBlob("app", []byte(`{"architecture":"`+arch+`"}`))
		layer := src.addBlob("app", []byte("layer for "+arch))
		d := src.addManifest("app", arch, "application/vnd.oci.image.manifest.v1+json",
			manifestDoc{MediaType: "application/vnd.oci.image.manifest.v1+json", Config: &cfg, Layers: []descriptor{shared, layer}})
		children = append(children, descriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: d})
	}
	indexDigest := src.addManifest("app", "1.0", "application/vnd.oci.image.index.v1+json",
		manifestDoc{MediaType: "application/vnd.oci.image.index.v1+json", Manifests: children})

	ctx := context.Background()
	res, err := Copy(ctx, client(t, srcSrv), "app", "1.0", client(t, dstSrv), "mirror/app", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Digest != indexDigest || res.Manifests != 3 || res.BlobsCopied != 5 || res.BlobsSkipped != 1 || res.Replaced {
		t.Errorf("first copy: %+v", res)
	}
	if got := dst.manifests["mirror/app@1.0"]; digestOf(got) != indexDigest {
		t.Error("destination index has a different digest")
	}
	for _, c := range children {
		if _, ok := dst.manifests["mirror/app@"+c.Digest]; !ok {
			t.Errorf("platform manifest %s missing", c.Digest)
		}
	}

	res, err = Copy(ctx, client(t, srcSrv), "app", "1.0", client(t, dstSrv), "mirror/app", "1.0")
	if err != nil || res.BlobsCopied != 0 || res.BlobsSkipped != 6 || res.Replaced {
		t.Errorf("second copy should only skip: %+v %v", res, err)
	}

	same := client(t, srcSrv)
	res, err = Copy(ctx, same, "app", "amd64", same, "other", "x")
	if err != nil || res.BlobsMounted != 3 || res.BlobsCopied != 0 {
		t.Errorf("same-registry copy should mount: %+v %v", res, err)
	}

	if _, err := Copy(ctx, client(t, srcSrv), "app", "missing", client(t, dstSrv), "app", "x"); err == nil {
		t.Error("copying a missing tag succeeded")
	}
}

func TestCopyRefusesWrongContent(t *testing.T) {
	src, srcSrv := newFake()
	defer srcSrv.Close()
	_, dstSrv := newFake()
	defer dstSrv.Close()
	cfg := src.addBlob("app", []byte("cfg"))
	good := src.addManifest("app", "img", "application/vnd.oci.image.manifest.v1+json", manifestDoc{Config: &cfg})
	src.addManifest("app", "1.0", "application/vnd.oci.image.index.v1+json",
		manifestDoc{Manifests: []descriptor{{Digest: good}}})
	// the registry serves different bytes under the child's digest
	src.manifests["app@"+good] = []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`)
	if _, err := Copy(context.Background(), client(t, srcSrv), "app", "1.0", client(t, dstSrv), "app", "1.0"); err == nil {
		t.Error("tampered child manifest was copied")
	}
	src.addManifest("app", "2.0", "application/vnd.oci.image.index.v1+json",
		manifestDoc{Manifests: []descriptor{{Digest: "sha256:../../../v2/_catalog"}}})
	if _, err := Copy(context.Background(), client(t, srcSrv), "app", "2.0", client(t, dstSrv), "app", "2.0"); err == nil {
		t.Error("malformed digest was used")
	}
}

func TestHostPort(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"https://ghcr.io/x", "https://ghcr.io:443/y", true},
		{"http://reg:5000/x", "http://reg:5000/y", true},
		{"https://reg/x", "http://reg/y", false},
		{"https://reg/x", "https://other/y", false},
	} {
		a, _ := url.Parse(c.a)
		b, _ := url.Parse(c.b)
		if (hostPort(a) == hostPort(b) && a.Scheme == b.Scheme) != c.same {
			t.Errorf("%s vs %s", c.a, c.b)
		}
	}
}

// An index (what docker buildx pushes) has no config of its own: Inspect
// gives the build date of its first image, which prune needs.
func TestInspectIndexCreated(t *testing.T) {
	f, srv := newFake()
	defer srv.Close()
	cfg := f.addBlob("app", []byte(`{"created":"2026-01-02T03:04:05Z","architecture":"amd64","os":"linux"}`))
	d := f.addManifest("app", "one", "application/vnd.oci.image.manifest.v1+json",
		manifestDoc{MediaType: "application/vnd.oci.image.manifest.v1+json", Config: &cfg})
	f.addManifest("app", "v1", "application/vnd.oci.image.index.v1+json",
		manifestDoc{MediaType: "application/vnd.oci.image.index.v1+json", Manifests: []descriptor{{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: d}}})
	m, err := client(t, srv).Inspect(context.Background(), "app", "v1")
	if err != nil || m.Created != "2026-01-02T03:04:05Z" {
		t.Errorf("index created %q %v", m.Created, err)
	}
}
