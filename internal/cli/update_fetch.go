package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
)

// releaseSite is where komando's releases are published (install.sh uses
// the same place). Tests point it at a local server.
var releaseSite = "https://github.com/sgnd/komando"

// retryWait is the pause before a failed request is tried again (twice
// that before the third try). Tests make it short.
var retryWait = 2 * time.Second

const (
	maxArchive   = 256 << 20 // a release archive is about 20 MB
	maxChecksums = 1 << 20
	maxBinary    = 512 << 20
)

// newestRelease reads the newest release's tag from where GitHub sends
// /releases/latest (a redirect to /releases/tag/vX.Y.Z), which needs no
// API token and has no rate limit.
func newestRelease(ctx context.Context) (string, error) {
	c := updateClient()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := send(ctx, c, http.MethodHead, releaseSite+"/releases/latest", "the newest release")
	if err != nil {
		return "", releaseErr(err)
	}
	_ = resp.Body.Close()
	hint := "try again later; the releases are at " + releaseSite + "/releases"
	loc, err := resp.Location()
	if err != nil {
		return "", out.Errf(out.ExitConnect, "RELEASES_UNREACHABLE", hint,
			"cannot find the newest release (HTTP %d, no redirect)", resp.StatusCode)
	}
	tag, _ := url.PathUnescape(path.Base(loc.Path))
	if !strings.Contains(loc.Path, "/releases/tag/") || !isReleaseTag(tag) {
		return "", out.Errf(out.ExitConnect, "RELEASES_UNREACHABLE", hint,
			"cannot find the newest release (it points to %s)", loc.Redacted())
	}
	return tag, nil
}

func updateClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone() // honours HTTPS_PROXY
	return &http.Client{Transport: t, CheckRedirect: httpsOnlyRedirect}
}

// httpsOnlyRedirect follows a redirect only when it stays on HTTPS, so a
// release download (GitHub sends it on to its CDN) can never be pulled over
// plain HTTP, and keeps net/http's usual limit of ten hops.
func httpsOnlyRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing a redirect to %s (komando update downloads over HTTPS only)", req.URL.Redacted())
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// send sends one request, and again (up to three tries) when the network
// fails on the way or the server answers 5xx: GitHub's downloads do that
// now and then (HTTP 504). what names the file in the note on stderr.
func send(ctx context.Context, c *http.Client, method, u, what string) (*http.Response, error) {
	for try := 1; ; try++ {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "komando/"+Version)
		resp, err := c.Do(req)
		failed := err != nil && ctx.Err() == nil || err == nil && resp.StatusCode >= 500
		if !failed || try == 3 {
			return resp, err
		}
		why := ""
		if err != nil {
			why = flatText(err.Error())
		} else {
			why = "HTTP " + strconv.Itoa(resp.StatusCode)
			_ = resp.Body.Close()
		}
		wait := time.Duration(try) * retryWait
		if term.IsTerminal(int(os.Stderr.Fd())) {
			fmt.Fprintf(os.Stderr, "%s: %s; trying again in %s\n", what, why, wait)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// releaseErr turns a failed request into komando's error. A timeout and
// Ctrl-C stay as they are: updateErr says them in words.
func releaseErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	hint := "check this computer's internet connection (and HTTPS_PROXY), then try again"
	if asRoot() && os.Getenv("HTTPS_PROXY") == "" && os.Getenv("https_proxy") == "" {
		hint = "check this computer's internet connection; behind a proxy, keep it for sudo: sudo --preserve-env=HTTPS_PROXY komando update"
	}
	return out.Errf(out.ExitConnect, "RELEASES_UNREACHABLE", hint, "cannot reach komando's releases: %s", flatText(err.Error()))
}

func flatText(s string) string { return strings.Join(strings.Fields(s), " ") }

// releaseSums is checksums.txt of release tag. It also shows that the
// release exists and has an archive for this computer.
func releaseSums(ctx context.Context, tag string) ([]byte, error) {
	sums, err := fetch(ctx, tag, "checksums.txt", maxChecksums, "")
	if err != nil {
		return nil, err
	}
	if sumFor(sums, archiveName()) == "" {
		return nil, out.Errf(out.ExitNotFound, "VERSION_NOT_FOUND", "pick another version from "+releaseSite+"/releases",
			"komando %s has no download for %s", tag, platform())
	}
	return sums, nil
}

func archiveName() string { return "komando_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz" }

// fetch downloads one release file, up to max bytes. label, when set, shows
// progress on a terminal.
func fetch(ctx context.Context, tag, name string, max int64, label string) ([]byte, error) {
	resp, err := send(ctx, updateClient(), http.MethodGet, releaseSite+"/releases/download/"+tag+"/"+name, name)
	if err != nil {
		return nil, releaseErr(err)
	}
	defer resp.Body.Close()
	bad := "nothing was changed; report it at " + releaseSite + "/issues"
	switch {
	case resp.StatusCode == http.StatusNotFound && name == "checksums.txt":
		return nil, out.Errf(out.ExitNotFound, "VERSION_NOT_FOUND", "pick a version from "+releaseSite+"/releases",
			"there is no komando release %s", tag)
	case resp.StatusCode == http.StatusNotFound:
		return nil, out.Errf(out.ExitNotFound, "VERSION_NOT_FOUND", "pick another version from "+releaseSite+"/releases",
			"komando %s has no %s", tag, name)
	case resp.StatusCode != http.StatusOK:
		return nil, out.Errf(out.ExitConnect, "RELEASES_UNREACHABLE", "GitHub did not answer as it should; try again in a few minutes",
			"downloading %s failed: HTTP %d", name, resp.StatusCode)
	case resp.ContentLength > max:
		return nil, out.Errf(out.ExitError, "BAD_RELEASE", bad, "%s is %d bytes, more than komando accepts", name, resp.ContentLength)
	}
	var body io.Reader = io.LimitReader(resp.Body, max+1)
	if label != "" && term.IsTerminal(int(os.Stderr.Fd())) {
		p := &progress{label: label, total: resp.ContentLength}
		defer p.done()
		body = io.TeeReader(body, p)
	}
	b, err := io.ReadAll(body)
	if err != nil {
		return nil, releaseErr(err)
	}
	if int64(len(b)) > max {
		return nil, out.Errf(out.ExitError, "BAD_RELEASE", bad, "%s is more than %d bytes, more than komando accepts", name, max)
	}
	return b, nil
}

// progress shows a download on stderr, at most a few times a second.
type progress struct {
	label     string
	total, n  int64
	last      time.Time
	wroteLine bool
}

func (p *progress) Write(b []byte) (int, error) {
	p.n += int64(len(b))
	if time.Since(p.last) < 200*time.Millisecond && p.n != p.total {
		return len(b), nil
	}
	p.last = time.Now()
	mb := func(n int64) string { return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) }
	if p.total > 0 {
		fmt.Fprintf(os.Stderr, "\r%s: %s of %s MB", p.label, mb(p.n), mb(p.total))
	} else {
		fmt.Fprintf(os.Stderr, "\r%s: %s MB", p.label, mb(p.n))
	}
	p.wroteLine = true
	return len(b), nil
}

func (p *progress) done() {
	if p.wroteLine {
		fmt.Fprintln(os.Stderr)
	}
}
