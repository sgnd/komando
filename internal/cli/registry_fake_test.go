package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/registry"
)

// memRegistry is a small registry:2 in memory: tags, image manifests with
// a config (build date), indexes, catalog paging and deletes by digest.
type memRegistry struct {
	mu        sync.Mutex
	manifests map[string][]byte            // digest -> body
	ctypes    map[string]string            // digest -> media type
	tags      map[string]map[string]string // repo -> tag -> digest
	blobs     map[string][]byte            // digest -> content
	gets      int                          // manifest GETs (Docker Hub counts them as pulls)
	status    int                          // when set, every request gets this status
	header    http.Header                  // and these headers
}

func newMemRegistry(t *testing.T) (*memRegistry, string) {
	m := &memRegistry{manifests: map[string][]byte{}, ctypes: map[string]string{},
		tags: map[string]map[string]string{}, blobs: map[string][]byte{}}
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return m, strings.TrimPrefix(srv.URL, "http://")
}

func memDigest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// image adds an image built at created under repo:tag and returns its digest.
func (m *memRegistry) image(repo, tag string, created time.Time) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, _ := json.Marshal(map[string]any{"created": created.UTC().Format(time.RFC3339Nano), "os": "linux", "architecture": "amd64"})
	cd := memDigest(cfg)
	m.blobs[cd] = cfg
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"digest": cd, "size": len(cfg)}, "layers": []any{map[string]any{"digest": cd, "size": 1000}}})
	return m.put(repo, tag, man, "application/vnd.oci.image.manifest.v1+json")
}

// index adds a multi-platform index over the given image digests.
func (m *memRegistry) index(repo, tag string, images ...string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ms []any
	for _, d := range images {
		ms = append(ms, map[string]any{"digest": d, "mediaType": "application/vnd.oci.image.manifest.v1+json",
			"platform": map[string]any{"os": "linux", "architecture": "amd64"}})
	}
	b, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": ms})
	return m.put(repo, tag, b, "application/vnd.oci.image.index.v1+json")
}

func (m *memRegistry) put(repo, tag string, b []byte, ctype string) string {
	d := memDigest(b)
	m.manifests[d], m.ctypes[d] = b, ctype
	if m.tags[repo] == nil {
		m.tags[repo] = map[string]string{}
	}
	if tag != "" {
		m.tags[repo][tag] = d
	}
	return d
}

func (m *memRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status != 0 {
		for k, v := range m.header {
			w.Header()[k] = v
		}
		w.WriteHeader(m.status)
		io.WriteString(w, `{"errors":[{"code":"TOOMANYREQUESTS","message":"You have reached your pull rate limit."}]}`)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v2/")
	notFound := func(code string) {
		w.WriteHeader(404)
		fmt.Fprintf(w, `{"errors":[{"code":%q,"message":"unknown"}]}`, code)
	}
	page := func(field string, all []string) {
		sort.Strings(all)
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		last := r.URL.Query().Get("last")
		var items []string
		for _, s := range all {
			if s > last {
				items = append(items, s)
			}
		}
		if n > 0 && len(items) > n {
			items = items[:n]
			w.Header().Set("Link", fmt.Sprintf(`<%s?n=%d&last=%s>; rel="next"`, r.URL.Path, n, items[n-1]))
		}
		json.NewEncoder(w).Encode(map[string]any{field: items})
	}
	switch {
	case p == "":
		w.WriteHeader(200)
	case p == "_catalog":
		var repos []string
		for repo := range m.tags {
			repos = append(repos, repo)
		}
		page("repositories", repos)
	case strings.HasSuffix(p, "/tags/list"):
		repo := strings.TrimSuffix(p, "/tags/list")
		if m.tags[repo] == nil {
			notFound("NAME_UNKNOWN")
			return
		}
		var l []string
		for t := range m.tags[repo] {
			l = append(l, t)
		}
		page("tags", l)
	case strings.Contains(p, "/manifests/"):
		repo, ref, _ := strings.Cut(p, "/manifests/")
		d := ref
		if !strings.HasPrefix(ref, "sha256:") {
			d = m.tags[repo][ref]
		}
		b, ok := m.manifests[d]
		if !ok {
			notFound("MANIFEST_UNKNOWN")
			return
		}
		switch r.Method {
		case "DELETE":
			delete(m.manifests, d)
			for t, td := range m.tags[repo] {
				if td == d {
					delete(m.tags[repo], t)
				}
			}
			w.WriteHeader(202)
			return
		case "GET":
			m.gets++
		}
		w.Header().Set("Content-Type", m.ctypes[d])
		w.Header().Set("Docker-Content-Digest", d)
		if r.Method == "GET" {
			w.Write(b)
		}
	case strings.Contains(p, "/blobs/"):
		_, d, _ := strings.Cut(p, "/blobs/")
		b, ok := m.blobs[d]
		if !ok {
			notFound("BLOB_UNKNOWN")
			return
		}
		w.Write(b)
	default:
		notFound("NAME_UNKNOWN")
	}
}

// textRun runs komando with -o text and returns what it printed.
func textRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	tcl.flags.dryRun, tcl.flags.yes, tcl.flags.allowDangerous = false, false, false
	root := newRoot(tcl)
	root.SetArgs(append([]string{"-o", "text"}, args...))
	var buf bytes.Buffer
	saved := tcl.out.W
	tcl.out.W = &buf
	root.SetOut(&buf)
	root.SetErr(&buf)
	defer func() { tcl.out.W, tcl.out.Format = saved, "json" }()
	err := root.Execute()
	return buf.String(), err
}

// memRepo fills a registry: shop/api v1..v5 built a day apart, v9 and
// latest on the newest image, and multi/app with two indexes.
func memRepo(t *testing.T) (*memRegistry, string) {
	m, addr := newMemRegistry(t)
	now := time.Now()
	for i := 1; i <= 5; i++ {
		m.image("shop/api", fmt.Sprintf("v%d", i), now.Add(-time.Duration(10-i)*24*time.Hour))
	}
	d := m.image("shop/api", "v9", now)
	m.mu.Lock()
	m.tags["shop/api"]["latest"] = d
	m.mu.Unlock()
	m.index("multi/app", "old", m.image("multi/app", "", now.Add(-40*24*time.Hour)))
	m.index("multi/app", "new", m.image("multi/app", "", now))
	mustRun(t, "registry", "add", "mem", "registry://"+addr+"?tls=false")
	return m, addr
}

// Docker Hub's pull limit (429) is its own error, with when to retry.
func TestRegistryRateLimit(t *testing.T) {
	invHome(t)
	m, _ := memRepo(t)
	m.mu.Lock()
	m.status, m.header = 429, http.Header{"Retry-After": {"120"}}
	m.mu.Unlock()
	e := wantCode(t, "REGISTRY_RATE_LIMIT", "registry", "ls", "mem", "shop/api")
	if !strings.Contains(e.Hint, "after 2m0s") || !strings.Contains(e.Hint, "--password-ref") {
		t.Errorf("hint: %s", e.Hint)
	}
}

// Names are checked before they go into a URL path or a token scope.
func TestRegistryNamesChecked(t *testing.T) {
	invHome(t)
	memRepo(t)
	for _, args := range [][]string{
		{"registry", "ls", "mem", "../_catalog"},
		{"registry", "ls", "mem", "shop/api:v1"},
		{"registry", "inspect", "mem", "shop/api:v1/../../x"},
		{"registry", "inspect", "mem", "shop/api@sha256:short"},
		{"registry", "inspect", "mem", "a/b:-x"},
		{"--dry-run", "registry", "rm", "mem", "shop/../api:v1"},
		{"--dry-run", "registry", "prune", "mem", "shop/api?n=1", "--keep", "1"},
		{"--dry-run", "registry", "copy", "mem:shop/api:v1", "mem:x/../y:1"},
	} {
		wantCode(t, "USAGE", args...)
	}
	if e := wantCode(t, "USAGE", "registry", "inspect", "mem", "Shop/API:v1"); !strings.Contains(e.Message, "shop/api") {
		t.Errorf("upper case: %s", e.Message)
	}
	mustRun(t, "registry", "inspect", "mem", "shop/api@"+mustRun(t, "registry", "inspect", "mem", "shop/api:v1")["digest"].(string))
}

// prune reads each image once (Docker Hub counts every manifest read as a
// pull), and a multi-platform index has a build date, so it can go.
func TestRegistryPruneReadsAndIndexes(t *testing.T) {
	invHome(t)
	m, _ := memRepo(t)
	d := mustRun(t, "--dry-run", "registry", "prune", "mem", "shop/api", "--keep", "2")
	if m.gets != 6 { // 7 tags on 6 images
		t.Errorf("manifest reads: %d, want 6", m.gets)
	}
	if del := d["delete"].([]any); len(del) != 4 {
		t.Errorf("delete: %v", del)
	}
	d = mustRun(t, "--dry-run", "registry", "prune", "mem", "multi/app", "--older-than", "30d")
	del := d["delete"].([]any)
	if len(del) != 1 || fmt.Sprint(del[0].(map[string]any)["tags"]) != "[old]" {
		t.Errorf("index: %v", d)
	}
}

// What a person reads: a cut list says so, rm names every tag that goes
// (latest above all), prune lists what goes and why the rest stays.
func TestRegistryText(t *testing.T) {
	invHome(t)
	memRepo(t)
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"registry", "ls", "mem", "shop/api", "-n", "3"}, []string{"latest\nv1\nv2\n", "the first 3 tags in shop/api; there are more: raise -n"}},
		{[]string{"registry", "ls", "mem"}, []string{"multi/app\nshop/api\n"}},
		{[]string{"--dry-run", "registry", "rm", "mem", "shop/api:v9"}, []string{"would delete shop/api@sha256:", "with it goes every tag on that image: latest, v9", "latest is one of them"}},
		{[]string{"--dry-run", "registry", "prune", "mem", "shop/api", "--keep", "2"}, []string{"shop/api: would delete 4 images of 7 tags", "  - v4 ", "  = latest", "latest is always kept"}},
		{[]string{"registry", "inspect", "mem", "shop/api:v9"}, []string{"created: " + time.Now().Format("2006-01-02")}},
	} {
		s, err := textRun(t, c.args...)
		if err != nil {
			t.Errorf("%v: %v", c.args, err)
		}
		for _, w := range c.want {
			if !strings.Contains(s, strings.ReplaceAll(w, "\\n", "\n")) {
				t.Errorf("%v: no %q in\n%s", c.args, w, s)
			}
		}
		if strings.Contains(s, "Next:") {
			t.Errorf("%v: a Next: line on stdout:\n%s", c.args, s)
		}
	}
	// the Next: line a person gets on stderr names a command for one item
	for args, want := range map[string]string{"registry ls mem shop/api": "komando registry inspect mem shop/api:TAG", "registry ls mem": "komando registry list mem REPO"} {
		if _, err := textRun(t, strings.Fields(args)...); err != nil || !slices.Equal(tcl.nextNow, []string{want}) {
			t.Errorf("%s: Next: %q, %v", args, tcl.nextNow, err)
		}
	}
}

// import docker: a credHelpers entry alone counts; ECR and gcloud logins
// are hour-long tokens, so the conn logs in with the cloud each time; a
// helper name that is a path is not run.
func TestImportDockerRegistries(t *testing.T) {
	invHome(t)
	auth := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cfg := fmt.Sprintf(`{"auths":{
	  "ghcr.io":{"auth":%q},
	  "https://index.docker.io/v1/":{"auth":%q},
	  "europe-west1-docker.pkg.dev":{"auth":%q},
	  "myreg.azurecr.io":{"auth":%q,"identitytoken":"x"},
	  "other.example.com":{}
	 },
	 "credsStore":"../../tmp/evil",
	 "credHelpers":{"123456789012.dkr.ecr.eu-west-1.amazonaws.com":"ecr-login"}}`,
		auth("octo:tok1"), auth("me:tok2"), auth("oauth2accesstoken:ya29"), auth("00000000-0000-0000-0000-000000000000:"))
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := importDocker(tcl, path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range p.Conns {
		got[c.Name] = c.URL + " " + c.PasswordRef
	}
	want := map[string]string{
		"123456789012":        "registry://123456789012.dkr.ecr.eu-west-1.amazonaws.com ",
		"dockerhub":           "registry://me@docker.io secret:dockerhub-pass",
		"europe-west1-docker": "registry://europe-west1-docker.pkg.dev ",
		"ghcr":                "registry://octo@ghcr.io secret:ghcr-pass",
		"myreg":               "registry://myreg.azurecr.io ",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("conns:\n got %v\nwant %v", got, want)
	}
	if len(p.Secrets) != 2 {
		t.Errorf("secrets: %v", p.Secrets)
	}
	if notes := strings.Join(p.Notes, "\n"); !strings.Contains(notes, "other.example.com") || !strings.Contains(notes, "not a program name") {
		t.Errorf("notes: %s", notes)
	}
}

func TestCatalogErr(t *testing.T) {
	hub := registry.New("docker.io", registry.TLS{}, "", "", nil)
	if e := toErr(catalogErr(hub, &registry.Error{Status: 401})); e.Code != "REGISTRY_UNSUPPORTED" || !strings.Contains(e.Hint, "library/nginx") {
		t.Errorf("hub: %+v", e)
	}
	own := registry.New("harbor.example.com", registry.TLS{}, "", "", nil)
	if e := toErr(catalogErr(own, &registry.Error{Status: 403})); e.Code != "REGISTRY_AUTH" || !strings.Contains(e.Hint, "registry list CONN REPO") {
		t.Errorf("own: %+v", e)
	}
	if own.Repo("nginx") != "nginx" || hub.Repo("nginx") != "library/nginx" || hub.Repo("me/app") != "me/app" {
		t.Error("Repo")
	}
}

// A blocked delete says which image and which tags it would take, so the
// person asked (or approving an agent) sees that latest goes too; an
// unreachable registry still gives the safety stop first.
func TestRegistryRmSaysWhatGoes(t *testing.T) {
	invHome(t)
	memRepo(t)
	e := wantCode(t, "POLICY_BLOCKED", "registry", "rm", "mem", "shop/api:v9")
	if !strings.Contains(e.Message, "deletes shop/api@sha256:") || !strings.Contains(e.Message, "every tag on it: latest, v9") {
		t.Errorf("message: %s", e.Message)
	}
	mustRun(t, "registry", "add", "dead", "registry://"+closedAddr(t)+"?tls=false")
	wantCode(t, "POLICY_BLOCKED", "registry", "rm", "dead", "shop/api:v9")
	if e := wantCode(t, "POLICY_BLOCKED", "registry", "prune", "mem", "shop/api", "--keep", "1"); !strings.Contains(e.Message, "old images of shop/api") {
		t.Errorf("prune: %s", e.Message)
	}
}

// prune reads build dates only for images a matching tag may take, reads
// every tag of a big repository (it used to stop at 1000), and past
// 10000 tags says --match does not help.
func TestRegistryPruneMatchAndCap(t *testing.T) {
	invHome(t)
	m, _ := memRepo(t)
	mustRun(t, "--dry-run", "registry", "prune", "mem", "shop/api", "--keep", "0", "--match", "^v[12]$")
	if m.gets != 2 {
		t.Errorf("manifest reads: %d, want 2", m.gets)
	}
	d := m.image("big/app", "t0", time.Now())
	old := m.image("big/app", "old", time.Now().Add(-48*time.Hour))
	m.mu.Lock()
	for i := 1; i <= 1200; i++ {
		m.tags["big/app"][fmt.Sprintf("t%d", i)] = d
	}
	m.mu.Unlock()
	pd := mustRun(t, "--dry-run", "registry", "prune", "mem", "big/app", "--keep", "1")
	if b, _ := json.Marshal(pd); !strings.Contains(string(b), shortDigest(old)) || strings.Contains(string(b), shortDigest(d)) {
		t.Errorf("1202 tags: the old image should go, the one 1201 tags keep should stay: %s", b)
	}
	// rm sees a tag far down the list too (it used to read only 200)
	m.image("big/app", "zz-late", time.Now().Add(-72*time.Hour))
	rd := mustRun(t, "--dry-run", "registry", "rm", "mem", "big/app:zz-late")
	if b, _ := json.Marshal(rd); !strings.Contains(string(b), "zz-late") || strings.Contains(string(b), "only the first") {
		t.Errorf("rm of a late tag in 1203: %s", b)
	}
	m.mu.Lock()
	for i := 1201; i <= 10000; i++ {
		m.tags["big/app"][fmt.Sprintf("t%d", i)] = d
	}
	m.mu.Unlock()
	if e := wantCode(t, "TOO_MANY_TAGS", "--dry-run", "registry", "prune", "mem", "big/app", "--keep", "1", "--match", "^t1$"); !strings.Contains(e.Hint, "registry rm") {
		t.Errorf("hint: %s", e.Hint)
	}
}
