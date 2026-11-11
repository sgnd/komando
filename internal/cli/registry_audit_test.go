package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A refused registry reads as `komando test` says it.
func TestRegistryErrWords(t *testing.T) {
	addr := closedAddr(t)
	_, err := http.Get("http://" + addr + "/")
	if e := toErr(registryErr(err)); e.Code != "REGISTRY_UNREACHABLE" || e.Message != "cannot reach "+addr+": connection refused" {
		t.Errorf("registry refused: %+v", e)
	}
}

// fakeRegistry serves app:1 and answers 404 for anything else.
func fakeRegistry(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(200)
		case "/v2/app/manifests/1", "/v2/b/manifests/1":
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			digest := "sha256:" + strings.Repeat("a", 64)
			if strings.HasPrefix(r.URL.Path, "/v2/b/") {
				digest = "sha256:" + strings.Repeat("b", 64)
			}
			w.Header().Set("Docker-Content-Digest", digest)
			io.WriteString(w, `{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{"size":2048}]}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"unknown"}]}`)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// registry copy --dry-run reads both registries; a copy onto itself and a
// delete without a tag are refused; ls -n 0 is refused.
func TestRegistryChecks(t *testing.T) {
	invHome(t)
	mustRun(t, "registry", "add", "lreg", "registry://"+fakeRegistry(t)+"?tls=false")
	mustRun(t, "registry", "add", "dead", "registry://"+closedAddr(t)+"?tls=false")
	d, e := invRun(t, "--dry-run", "registry", "copy", "lreg:app:1", "lreg:b")
	if e != nil || d["to"] != "lreg:b:1" || d["would_replace"] != true || d["source"] == nil {
		t.Errorf("dry run: %v %+v", d, e)
	}
	if d, e := invRun(t, "--dry-run", "registry", "copy", "lreg:app:1", "lreg:c:2"); e != nil || d["would_replace"] != nil {
		t.Errorf("new tag: %v %+v", d, e)
	}
	if _, e := invRun(t, "--dry-run", "registry", "copy", "lreg:nope:1", "lreg:c:2"); e == nil || e.Code != "REGISTRY_NOT_FOUND" {
		t.Errorf("missing source: %+v", e)
	}
	if _, e := invRun(t, "--dry-run", "registry", "copy", "dead:a:1", "lreg:b:1"); e == nil || e.Code != "REGISTRY_UNREACHABLE" {
		t.Errorf("unreachable source: %+v", e)
	}
	wantCode(t, "USAGE", "--dry-run", "registry", "copy", "lreg:app:1", "lreg:")
	wantCode(t, "USAGE", "--dry-run", "registry", "copy", "lreg:app:1", "lreg:app:1")
	if e := wantCode(t, "USAGE", "--dry-run", "registry", "rm", "lreg", "app"); !strings.Contains(e.Message, "name the tag") {
		t.Errorf("rm: %+v", e)
	}
	wantCode(t, "USAGE", "registry", "ls", "lreg", "-n", "0")
}

func TestCutList(t *testing.T) {
	if l, cut := cutList(nil, 5); l == nil || cut {
		t.Errorf("nil: %v %v", l, cut)
	}
	if l, cut := cutList([]string{"a", "b", "c"}, 2); len(l) != 2 || !cut {
		t.Errorf("cut: %v %v", l, cut)
	}
}
