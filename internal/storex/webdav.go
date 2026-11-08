package storex

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// davBucket is a folder on a WebDAV server (Nextcloud, ownCloud, Apache
// mod_dav, nginx, a NAS). Keys are paths under the conn's folder, like on
// SFTP: a folder lists as "name/".
type davBucket struct {
	c          *http.Client
	base       *url.URL // the conn's folder, ending in /
	user, pass string
	baseMade   bool // the conn's folder was made (or found) by an upload
}

// OpenWebDAV prepares a client; it does not contact the server.
func OpenWebDAV(t driver.Target, password string, dial DialFunc, timeout time.Duration) (Bucket, error) {
	scheme := "http"
	if t.Secure {
		scheme = "https"
	}
	base := &url.URL{Scheme: scheme, Host: t.Address, Path: "/" + t.Prefix}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	return &davBucket{c: webClient(dial, timeout, t.TLS == "skip-verify"), base: base, user: t.User, pass: password}, nil
}

func (b *davBucket) Close() error { return nil }

// url is the address of rel under the conn's folder.
func (b *davBucket) url(rel string, dir bool) (*url.URL, error) {
	rel = strings.Trim(rel, "/")
	if rel != "" {
		if _, err := keyIn("", rel); err != nil {
			return nil, err
		}
	}
	u := *b.base
	u.Path += rel
	if dir && rel != "" {
		u.Path += "/"
	}
	u.RawPath = ""
	return &u, nil
}

func (b *davBucket) request(ctx context.Context, method string, u *url.URL, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if b.user != "" {
		req.SetBasicAuth(b.user, b.pass)
	}
	req.Header.Set("User-Agent", "komando")
	return req, nil
}

type davMultistatus struct {
	Responses []struct {
		Href     string `xml:"href"`
		Propstat []struct {
			Prop struct {
				ResourceType struct {
					Collection *struct{} `xml:"collection"`
				} `xml:"resourcetype"`
				Length   string `xml:"getcontentlength"`
				Modified string `xml:"getlastmodified"`
			} `xml:"prop"`
			Status string `xml:"status"`
		} `xml:"propstat"`
	} `xml:"response"`
}

const davProps = `<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/></d:prop></d:propfind>`

// propfind lists u and, with depth 1, what is directly in it. Keys are
// relative to the conn's folder; a folder's ends in /.
func (b *davBucket) propfind(ctx context.Context, u *url.URL, depth string) ([]Object, error) {
	req, err := b.request(ctx, "PROPFIND", u, strings.NewReader(davProps))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Depth", depth)
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	resp, err := do(b.c, "webdav", req, http.StatusMultiStatus)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var ms davMultistatus
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&ms); err != nil {
		return nil, out.Errf(out.ExitRemote, "STORAGE_ERROR", "check that the conn URL points at a WebDAV folder", "webdav: unreadable listing: %v", err)
	}
	var objs []Object
	for _, r := range ms.Responses {
		h, err := url.Parse(r.Href)
		if err != nil {
			continue
		}
		p := h.Path // absolute, or relative to the server
		rel, ok := strings.CutPrefix(p, b.base.Path)
		if !ok && strings.TrimSuffix(p, "/")+"/" != b.base.Path {
			continue // outside the conn's folder
		}
		o := Object{Key: rel}
		for _, ps := range r.Propstat {
			if !strings.Contains(ps.Status, " 200") {
				continue
			}
			if ps.Prop.ResourceType.Collection != nil {
				o.Dir = true
			}
			o.Size, _ = strconv.ParseInt(ps.Prop.Length, 10, 64)
			if t, err := http.ParseTime(ps.Prop.Modified); err == nil {
				o.Modified = t.UTC()
			}
		}
		if o.Dir {
			o.Key, o.Size = strings.TrimSuffix(o.Key, "/")+"/", 0
		}
		objs = append(objs, o)
	}
	return objs, nil
}

func (b *davBucket) List(ctx context.Context, prefix string, recursive bool, limit int) ([]Object, bool, error) {
	root := strings.Trim(prefix, "/")
	objs := []Object{}
	queue := []string{root}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		u, err := b.url(dir, true)
		if err != nil {
			return nil, false, err
		}
		got, err := b.propfind(ctx, u, "1")
		if err != nil {
			if oe, ok := err.(*out.Error); ok && oe.Code == "OBJECT_NOT_FOUND" && dir == root {
				return nil, false, FolderNotFound(prefix)
			}
			return nil, false, err
		}
		self := strings.TrimSuffix(dir, "/")
		sort.Slice(got, func(i, j int) bool { return got[i].Key < got[j].Key })
		for _, o := range got {
			if strings.TrimSuffix(o.Key, "/") == self {
				continue // the listed folder itself
			}
			if limit > 0 && len(objs) >= limit {
				return objs, true, nil
			}
			objs = append(objs, o)
			if recursive && o.Dir {
				queue = append(queue, strings.TrimSuffix(o.Key, "/"))
			}
		}
	}
	return objs, false, nil
}

func (b *davBucket) Stat(ctx context.Context, rel string) (Object, error) {
	u, err := b.url(rel, false)
	if err != nil {
		return Object{}, err
	}
	got, err := b.propfind(ctx, u, "0")
	if err != nil {
		return Object{}, err
	}
	if len(got) == 0 {
		return Object{}, out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list files with `komando storage ls CONN [FOLDER]`", "%s not found", rel)
	}
	if got[0].Dir {
		return Object{}, isFolder(rel)
	}
	o := got[0]
	o.Key = strings.Trim(rel, "/")
	return o, nil
}

func (b *davBucket) Exists(ctx context.Context, key string) (bool, error) {
	_, err := b.Stat(ctx, key)
	if oe, ok := err.(*out.Error); ok && oe.Code == "OBJECT_NOT_FOUND" {
		return false, nil
	}
	return err == nil, err
}

func (b *davBucket) Get(ctx context.Context, key string, w io.Writer) (int64, error) {
	u, err := b.url(key, false)
	if err != nil {
		return 0, err
	}
	req, err := b.request(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := do(b.c, "webdav", req, http.StatusOK)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(w, resp.Body)
	return n, webErr("webdav", nil, err)
}

// Put makes the missing parent folders (MKCOL), then writes the file.
func (b *davBucket) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	u, err := b.url(key, false)
	if err != nil {
		return err
	}
	if err := b.mkdirs(ctx, path.Dir(strings.Trim(key, "/"))); err != nil {
		return err
	}
	req, err := b.request(ctx, http.MethodPut, u, r)
	if err != nil {
		return err
	}
	if size >= 0 {
		req.ContentLength = size
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := do(b.c, "webdav", req, http.StatusOK, http.StatusCreated, http.StatusNoContent)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// mkdirs creates dir and its parents, from the top; a folder that is
// already there is fine.
func (b *davBucket) mkdirs(ctx context.Context, dir string) error {
	if !b.baseMade {
		// the conn's folder itself, as SFTP makes it; a server that does not
		// allow it (above the user's own folder) answers the upload instead
		b.baseMade = true
		if req, err := b.request(ctx, "MKCOL", b.base, nil); err == nil {
			if resp, err := b.c.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
	if dir == "." || dir == "" {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(dir, "/") {
		cur = path.Join(cur, part)
		u, err := b.url(cur, true)
		if err != nil {
			return err
		}
		req, err := b.request(ctx, "MKCOL", u, nil)
		if err != nil {
			return err
		}
		// 405: it exists; 301: a server redirecting to the folder's URL
		resp, err := do(b.c, "webdav", req, http.StatusCreated, http.StatusMethodNotAllowed, http.StatusMovedPermanently)
		if err != nil {
			return err
		}
		resp.Body.Close()
	}
	return nil
}

func (b *davBucket) Remove(ctx context.Context, key string) error {
	u, err := b.url(key, false)
	if err != nil {
		return err
	}
	if o, err := b.Stat(ctx, key); err != nil {
		return err
	} else if o.Dir {
		return isFolder(key)
	}
	req, err := b.request(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	resp, err := do(b.c, "webdav", req, http.StatusOK, http.StatusNoContent, http.StatusAccepted)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (b *davBucket) Link(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, noLinks("WebDAV")
}
