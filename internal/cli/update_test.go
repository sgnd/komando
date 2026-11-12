package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

func TestReleaseTags(t *testing.T) {
	for v, want := range map[string]bool{
		"v0.6.0": true, "v1.20.3": true, "v1.0.0-rc.1": true, "v1.0.0-beta2": true,
		"dev": false, "0.6.0": false, "v0.6.0-3-g975c9e7": false, "v0.6.0-dirty": false,
		"v0.6.0-3-g975c9e7-dirty": false, "v0.0.0-20261108-abcdef": false, "v0.6": false, "v0.6.0+meta": false,
	} {
		if isReleaseTag(v) != want {
			t.Errorf("isReleaseTag(%q) = %v, want %v", v, !want, want)
		}
	}
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v0.6.0", "v0.6.0", 0}, {"v0.7.0", "v0.6.0", 1}, {"v0.6.0", "v0.7.0", -1},
		{"v0.10.0", "v0.9.0", 1}, {"v1.0.0", "v0.99.99", 1}, {"v0.6.1", "v0.6.0", 1},
		{"v1.0.0-rc.1", "v1.0.0", -1}, {"v1.0.0", "v1.0.0-rc.1", 1}, {"v1.0.0-rc.10", "v1.0.0-rc.9", 1},
		{"v1.0.0-beta.1", "v1.0.0-rc.1", -1}, {"v1.0.0-alpha.3", "v1.0.0-beta.1", -1},
	} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// fakeReleases serves releases like GitHub does: /releases/latest
// redirects to the newest tag, and each tag has checksums.txt and one
// archive for this computer, whose komando is a script that prints the
// version (or what says[tag] tells it to print).
type fakeReleases struct {
	newest    string
	tags      []string
	says      map[string]string // the version the binary prints, when not its tag
	sums      string            // "" right; "bad" every line wrong; "other" only another platform's line right; "missing" no line for this platform
	noBinary  bool              // the archive has no komando
	fail      atomic.Int32      // answer this many requests with 503 first
	slow      time.Duration     // wait this long before /releases/latest answers
	downloads atomic.Int32      // archives served
	requests  atomic.Int32
}

func (f *fakeReleases) archive(tag string) []byte {
	says := tag
	if s, ok := f.says[tag]; ok {
		says = s
	}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	tw := tar.NewWriter(zw)
	// like `tar -czf X -C dir .` in the Makefile: a ./ folder and ./ names
	_ = tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755})
	files := []struct{ name, body string }{{"./LICENSE", "license text\n"}, {"./komando", "#!/bin/sh\necho " + says + "\n"}}
	if f.noBinary {
		files = files[:1]
	}
	for _, e := range files {
		_ = tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(e.body))})
		_, _ = tw.Write([]byte(e.body))
	}
	_ = tw.Close()
	_ = zw.Close()
	return b.Bytes()
}

func (f *fakeReleases) checksums(data []byte, name string) string {
	right := sha256.Sum256(data)
	wrong := sha256.Sum256([]byte("something else"))
	r, w := hex.EncodeToString(right[:]), hex.EncodeToString(wrong[:])
	switch f.sums {
	case "bad":
		return w + "  komando_other_arch.tar.gz\n" + w + "  " + name + "\n"
	case "other":
		return r + "  komando_other_arch.tar.gz\n" + w + "  " + name + "\n"
	case "missing":
		return r + "  komando_other_arch.tar.gz\n"
	}
	return w + "  komando_other_arch.tar.gz\n" + r + "  " + name + "\n"
}

func (f *fakeReleases) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	if f.fail.Load() > 0 {
		f.fail.Add(-1)
		http.Error(w, "gateway timeout", http.StatusServiceUnavailable)
		return
	}
	name := "komando_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	if r.URL.Path == "/releases/latest" {
		select {
		case <-time.After(f.slow):
		case <-r.Context().Done():
			return
		}
		http.Redirect(w, r, "/releases/tag/"+f.newest, http.StatusFound)
		return
	}
	for _, tag := range f.tags {
		data := f.archive(tag)
		switch r.URL.Path {
		case "/releases/download/" + tag + "/" + name:
			f.downloads.Add(1)
			_, _ = w.Write(data)
			return
		case "/releases/download/" + tag + "/checksums.txt":
			_, _ = w.Write([]byte(f.checksums(data, name)))
			return
		}
	}
	http.NotFound(w, r)
}

// updateLab runs `komando update` against fake releases, with a stand-in
// for the running komando in a folder of its own. It returns the
// stand-in's path and KOMANDO_HOME.
func updateLab(t *testing.T, running string, f *fakeReleases) (exe, home string) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	exe = filepath.Join(t.TempDir(), "komando")
	if err := os.WriteFile(exe, []byte("old komando"), 0o755); err != nil {
		t.Fatal(err)
	}
	savedSite, savedSelf, savedVersion, savedPlatforms, savedWait, savedRoot := releaseSite, selfPath, Version, releasePlatforms, retryWait, asRoot
	releaseSite, Version, retryWait = srv.URL, running, time.Millisecond
	releasePlatforms = map[string]bool{platform(): true} // the tests run where no release is made, too
	selfPath = func() (string, error) { return exe, nil }
	asRoot = func() bool { return false }
	home = filepath.Join(t.TempDir(), "home")
	t.Setenv("KOMANDO_HOME", home)
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	t.Cleanup(func() {
		releaseSite, selfPath, Version, releasePlatforms, retryWait, asRoot = savedSite, savedSelf, savedVersion, savedPlatforms, savedWait, savedRoot
		g.dryRun, g.yes, g.timeout, store.DryRun = false, false, 0, false
	})
	return exe, home
}

func updateJSON(t *testing.T, args ...string) (map[string]any, map[string]any) {
	t.Helper()
	s, err := runCache(t, append([]string{"-o", "json", "update"}, args...)...)
	if err != nil {
		t.Fatalf("update %v: %v\n%s", args, err, s)
	}
	var env struct {
		Data map[string]any `json:"data"`
		Meta map[string]any `json:"meta"`
	}
	if err := json.Unmarshal([]byte(s), &env); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	return env.Data, env.Meta
}

func updateFails(t *testing.T, args ...string) *out.Error {
	t.Helper()
	s, err := runCache(t, append([]string{"-o", "json", "update"}, args...)...)
	var e *out.Error
	if !errors.As(err, &e) {
		t.Fatalf("update %v: want a komando error, got %v\n%s", args, err, s)
	}
	return e
}

func fileText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// onlyFile fails when anything but the komando file is left in its folder
// (a temporary file after a failure, say).
func onlyFile(t *testing.T, exe string) {
	t.Helper()
	es, _ := os.ReadDir(filepath.Dir(exe))
	if len(es) != 1 {
		var names []string
		for _, e := range es {
			names = append(names, e.Name())
		}
		t.Errorf("left in the folder: %v", names)
	}
}

func TestUpdateInstallsNewest(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}}
	exe, _ := updateLab(t, "v0.6.0", f)
	d, _ := updateJSON(t)
	if d["action"] != "updated" || d["from"] != "v0.6.0" || d["to"] != "v0.7.0" || d["path"] != exe {
		t.Errorf("data = %v", d)
	}
	if !strings.HasSuffix(d["release"].(string), "/releases/tag/v0.7.0") || d["next"] != "komando guide install (gives your AI agents this version's skill)" {
		t.Errorf("release/next = %v / %v", d["release"], d["next"])
	}
	if got := fileText(t, exe); !strings.Contains(got, "echo v0.7.0") {
		t.Errorf("komando was not replaced: %q", got)
	}
	if fi, _ := os.Stat(exe); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, want 0755", fi.Mode().Perm())
	}
	onlyFile(t, exe)
	// like any other change, it is in the audit log
	if a := auditText(t); !strings.Contains(a, `"command":"update"`) || !strings.Contains(a, `"to":"v0.7.0"`) {
		t.Errorf("audit: %s", a)
	}
}

// sudo komando update: HOME may still be the person's, and root must not
// leave files there that they cannot change.
func TestUpdateAsRootLeavesHomeAlone(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}}
	exe, home := updateLab(t, "v0.6.0", f)
	asRoot = func() bool { return true }
	d, _ := updateJSON(t)
	if d["action"] != "updated" || !strings.Contains(d["next"].(string), "without sudo") || !strings.Contains(fileText(t, exe), "echo v0.7.0") {
		t.Errorf("data = %v", d)
	}
	if _, err := os.Stat(home); err == nil {
		t.Errorf("sudo komando update made %s", home)
	}
}

func TestUpdateText(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}}
	updateLab(t, "v0.6.0", f)
	s, err := runCache(t, "-o", "text", "update")
	if err != nil || !strings.HasPrefix(s, "updated komando v0.6.0 → v0.7.0\n") || !strings.Contains(s, "what changed: ") {
		t.Errorf("text = %q, %v", s, err)
	}
	Version = "v0.7.0" // what the new komando would say
	s, err = runCache(t, "-o", "text", "update", "latest")
	if err != nil || s != "komando v0.7.0 is the newest version\n" {
		t.Errorf("second run: %q, %v", s, err)
	}
}

func TestUpdateDryRunChangesNothing(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}}
	exe, _ := updateLab(t, "v0.6.0", f)
	d, m := updateJSON(t, "--dry-run")
	if d["action"] != "updated" || d["to"] != "v0.7.0" || m["dry_run"] != true || d["next"] != nil {
		t.Errorf("data = %v, meta = %v", d, m)
	}
	if fileText(t, exe) != "old komando" || f.downloads.Load() != 0 {
		t.Errorf("a dry run downloaded (%d) or replaced komando", f.downloads.Load())
	}
	s, _ := runCache(t, "-o", "text", "update", "--dry-run")
	if !strings.HasPrefix(s, "would update komando v0.6.0 → v0.7.0\n") {
		t.Errorf("text = %q", s)
	}
	onlyFile(t, exe)
	if a := auditText(t); strings.Contains(a, `"command":"update"`) {
		t.Errorf("a dry run went into the audit: %s", a)
	}
	// a dry run finds a version that does not exist, as the real run would
	if e := updateFails(t, "v9.9.9", "--dry-run"); e.Code != "VERSION_NOT_FOUND" || e.Exit != out.ExitNotFound || !strings.Contains(e.Message, "there is no komando release v9.9.9") {
		t.Errorf("dry run of a missing version: %v", e)
	}
}

func TestUpdateNewestAlready(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}}
	exe, _ := updateLab(t, "v0.7.0", f)
	d, _ := updateJSON(t)
	if d["action"] != "unchanged" || fileText(t, exe) != "old komando" || f.downloads.Load() != 0 {
		t.Errorf("data = %v, downloads = %d", d, f.downloads.Load())
	}
	s, _ := runCache(t, "-o", "text", "update", "v0.7.0")
	if s != "komando v0.7.0 is already installed\n" {
		t.Errorf("text = %q", s)
	}
}

// Without a VERSION update never goes back, also when the newest release
// is older than this komando (a pre-release, a tag pushed out of order).
func TestUpdateNeverGoesBackByItself(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}}
	exe, _ := updateLab(t, "v0.8.0-rc.1", f)
	d, _ := updateJSON(t, "--yes")
	if d["action"] != "unchanged" || d["to"] != "v0.7.0" || fileText(t, exe) != "old komando" || f.downloads.Load() != 0 {
		t.Errorf("data = %v, downloads = %d", d, f.downloads.Load())
	}
	s, _ := runCache(t, "-o", "text", "update")
	if s != "komando v0.8.0-rc.1 is newer than the newest release (v0.7.0)\n" {
		t.Errorf("text = %q", s)
	}
}

func TestUpdateOlderNeedsYes(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.5.0", "v0.7.0"}}
	exe, _ := updateLab(t, "v0.7.0", f)
	e := updateFails(t, "v0.5.0")
	if e.Code != "SAFETY_SETTING" || e.Exit != out.ExitPolicy || !strings.Contains(e.Message, "going back to the older komando v0.5.0") || strings.Count(e.Message, "safety checks") != 1 {
		t.Errorf("going back without --yes: %v (exit %d)", e, e.Exit)
	}
	if fileText(t, exe) != "old komando" || f.downloads.Load() != 0 {
		t.Fatal("komando was downloaded or replaced without a yes")
	}
	d, m := updateJSON(t, "0.5.0", "--dry-run")
	if d["action"] != "downgraded" || m["would_be_blocked"] == nil {
		t.Errorf("dry run: data = %v, meta = %v", d, m)
	}
	d, _ = updateJSON(t, "v0.5.0", "--yes")
	if d["action"] != "downgraded" || d["to"] != "v0.5.0" || !strings.Contains(fileText(t, exe), "echo v0.5.0") {
		t.Errorf("data = %v, file = %q", d, fileText(t, exe))
	}
}

// An AI agent going back needs the person's "Allow once" in the window.
func TestUpdateOlderAgentNeedsWindow(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.5.0", "v0.7.0"}}
	exe, _ := updateLab(t, "v0.7.0", f)
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	savedArgs, savedAsk := os.Args, askOnScreen
	var texts []string
	allow := false
	askOnScreen = func(text string) (bool, bool) { texts = append(texts, text); return allow, true }
	t.Cleanup(func() { os.Args, askOnScreen = savedArgs, savedAsk; resetApproval() })
	os.Args = []string{"komando", "update", "v0.5.0", "--yes"}
	if e := updateFails(t, "v0.5.0", "--yes"); e.Code != "SAFETY_SETTING" || e.Exit != out.ExitPolicy {
		t.Errorf("denied: %v", e)
	}
	if len(texts) != 1 || !strings.Contains(texts[0], "komando update v0.5.0 --yes") || fileText(t, exe) != "old komando" {
		t.Fatalf("windows %q; file %q", texts, fileText(t, exe))
	}
	allow = true
	if d, _ := updateJSON(t, "v0.5.0", "--yes"); d["action"] != "downgraded" || !strings.Contains(fileText(t, exe), "echo v0.5.0") {
		t.Errorf("allowed: data = %v", d)
	}
}

func TestUpdateRefusesBadDownloads(t *testing.T) {
	for _, c := range []struct {
		name, code string
		f          *fakeReleases
	}{
		{"wrong checksum", "CHECKSUM_MISMATCH", &fakeReleases{sums: "bad"}},
		{"only another archive's checksum is right", "CHECKSUM_MISMATCH", &fakeReleases{sums: "other"}},
		{"no checksum for this computer", "VERSION_NOT_FOUND", &fakeReleases{sums: "missing"}},
		{"binary says another version", "BAD_RELEASE", &fakeReleases{says: map[string]string{"v0.7.0": "v0.6.9"}}},
		{"no binary in the archive", "BAD_RELEASE", &fakeReleases{noBinary: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.f.newest, c.f.tags = "v0.7.0", []string{"v0.7.0"}
			exe, _ := updateLab(t, "v0.6.0", c.f)
			if e := updateFails(t); e.Code != c.code {
				t.Errorf("got %v, want %s", e, c.code)
			}
			if fileText(t, exe) != "old komando" {
				t.Error("komando was replaced by a bad download")
			}
			onlyFile(t, exe)
		})
	}
}

// GitHub's downloads answer 5xx now and then: update tries again.
func TestUpdateTriesAgain(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}}
	exe, _ := updateLab(t, "v0.6.0", f)
	f.fail.Store(2)
	if d, _ := updateJSON(t); d["action"] != "updated" || !strings.Contains(fileText(t, exe), "echo v0.7.0") {
		t.Errorf("after two 503s: %v", d)
	}
	f.fail.Store(3)
	Version = "v0.6.0"
	if e := updateFails(t); e.Code != "RELEASES_UNREACHABLE" || e.Exit != out.ExitConnect {
		t.Errorf("after three 503s: %v", e)
	}
}

func TestUpdateTimeout(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}, slow: 5 * time.Second}
	exe, _ := updateLab(t, "v0.6.0", f)
	e := updateFails(t, "--timeout", "100ms")
	if e.Code != "TIMEOUT" || e.Exit != out.ExitTimeout || e.Message != "the update took longer than 100ms" || !strings.Contains(e.Hint, "nothing was changed") {
		t.Errorf("got %v (exit %d, hint %q)", e, e.Exit, e.Hint)
	}
	if fileText(t, exe) != "old komando" {
		t.Error("replaced after a timeout")
	}
}

func TestUpdateErrors(t *testing.T) {
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}}
	updateLab(t, "v0.6.0", f)
	if e := updateFails(t, "v9.9.9"); e.Code != "VERSION_NOT_FOUND" || e.Exit != out.ExitNotFound {
		t.Errorf("unknown version: %v", e)
	}
	if e := updateFails(t, "banana"); e.Code != "USAGE" || !strings.Contains(e.Message, `"banana"`) {
		t.Errorf("not a version: %v", e)
	}
	for _, v := range []string{"dev", "v0.6.0-3-g975c9e7-dirty"} {
		Version = v
		if e := updateFails(t); e.Code != "SOURCE_BUILD" || e.Exit != out.ExitConflict {
			t.Errorf("%s: %v", v, e)
		}
	}
	Version = "v0.6.0"
	releasePlatforms = map[string]bool{}
	before := f.requests.Load()
	if e := updateFails(t); e.Code != "UNSUPPORTED_PLATFORM" || e.Exit != out.ExitConflict || f.requests.Load() != before {
		t.Errorf("no release for this computer: %v", e)
	}
	releasePlatforms = map[string]bool{platform(): true}
	f.newest = "not-a-tag"
	if e := updateFails(t); e.Code != "RELEASES_UNREACHABLE" {
		t.Errorf("bad redirect: %v", e)
	}
	releaseSite = "http://127.0.0.1:1"
	if e := updateFails(t); e.Code != "RELEASES_UNREACHABLE" || e.Exit != out.ExitConnect {
		t.Errorf("no server: %v", e)
	}
}

func TestUpdateNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may write anywhere")
	}
	f := &fakeReleases{newest: "v0.7.0", tags: []string{"v0.7.0"}}
	exe, _ := updateLab(t, "v0.6.0", f)
	dir := filepath.Dir(exe)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	e := updateFails(t)
	// the full path: sudo's PATH may find another komando, or none
	if e.Code != "NOT_WRITABLE" || e.Exit != out.ExitConflict || e.Hint != "run `sudo "+exe+" update`" || !strings.Contains(e.Message, "you may not write to "+dir) {
		t.Errorf("got %v (hint %q)", e, e.Hint)
	}
	if f.downloads.Load() != 0 {
		t.Error("it downloaded before it knew it could write")
	}
	_, m := updateJSON(t, "--dry-run")
	if b, _ := m["would_be_blocked"].(map[string]any); b == nil || b["code"] != "NOT_WRITABLE" {
		t.Errorf("dry run: meta = %v", m)
	}
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	if e := updateFails(t, "v0.7.0"); e.Hint != "ask the user to run `sudo "+exe+" update v0.7.0` in their own terminal: it needs their password" {
		t.Errorf("agent hint: %q", e.Hint)
	}
}

// komando update follows a redirect only while it stays on HTTPS, so a
// release download can never be pulled over plain HTTP.
func TestUpdateRedirectStaysHTTPS(t *testing.T) {
	req := func(u string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if err := httpsOnlyRedirect(req("https://objects.githubusercontent.com/x"), nil); err != nil {
		t.Errorf("an HTTPS redirect must be allowed: %v", err)
	}
	if err := httpsOnlyRedirect(req("http://evil.example/x"), nil); err == nil {
		t.Error("a redirect to HTTP must be refused")
	}
	many := make([]*http.Request, 10)
	if err := httpsOnlyRedirect(req("https://example.com/x"), many); err == nil {
		t.Error("too many redirects must be refused")
	}
}

// update knows every platform `make dist` builds: a release has an archive
// for each, so update must not say there is none (Windows did, while its
// .zip was already in every release).
func TestReleasePlatformsMatchMakefile(t *testing.T) {
	mk, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	var built []string
	for _, line := range strings.Split(string(mk), "\n") {
		if v, ok := strings.CutPrefix(line, "PLATFORMS := "); ok {
			built = strings.Fields(v)
		}
	}
	if len(built) == 0 {
		t.Fatal("no PLATFORMS line in the Makefile")
	}
	got := mapKeys(releasePlatforms)
	slices.Sort(got)
	slices.Sort(built)
	if !slices.Equal(got, built) {
		t.Errorf("releasePlatforms = %v, make dist builds %v", got, built)
	}
}

// `komando update web1` names a server, not a version: a usage error that
// points at `pkg upgrade` (S-3.6, C-V16), before anything is fetched.
func TestUpdateRefusesATarget(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:1", "-g", "web")
	mustRun(t, "conn", "add", "db1", "postgres://u@127.0.0.1:1/app")
	for _, w := range []string{"web1", "WEB1", "db1", "@web"} {
		e := wantCode(t, "USAGE", "update", w)
		if e.Hint != "komando pkg upgrade "+w || !strings.Contains(e.Message, "not a komando version") {
			t.Errorf("update %s: %+v", w, e)
		}
	}
	if err := updateNotATarget("v0.6.0"); err != nil {
		t.Errorf("a version: %v", err)
	}
}
