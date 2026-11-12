package storex

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
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

// azBucket is a container (and folder) on Azure Blob Storage, through its
// REST API. The login is the storage account's key (Shared Key) or a SAS
// token; only a key can sign download links.
type azBucket struct {
	c         *http.Client
	base      string // https://ACCOUNT.blob.core.windows.net, or an emulator's URL with its path
	account   string
	container string
	prefix    string
	key       []byte     // the account key, or nil with a SAS token
	sas       url.Values // the SAS token's parameters, or nil
	now       func() time.Time
}

const azVersion = "2021-08-06"

// OpenAzure prepares a client; it does not contact the container. secret
// is the account key (base64) or a SAS token (sv=...&sig=...).
func OpenAzure(t driver.Target, secret string, dial DialFunc, timeout time.Duration) (Bucket, error) {
	scheme := map[bool]string{true: "https", false: "http"}[t.Secure]
	b := &azBucket{c: webClient(dial, timeout, false), base: scheme + "://" + hostOf(t), account: t.User,
		container: t.Bucket, prefix: t.Prefix, now: time.Now}
	if err := trustCA(b.c.Transport.(*http.Transport), t); err != nil {
		return nil, err
	}
	if t.Path != "" {
		b.base += "/" + t.Path
	}
	secret = strings.TrimSpace(secret)
	switch {
	case secret == "":
		return nil, out.Errf(out.ExitConnect, "STORAGE_AUTH",
			"store the account key or a SAS token with `komando secret set NAME` and pass --password-ref secret:NAME",
			"an azblob conn needs the storage account's key or a SAS token")
	case strings.Contains(secret, "sig=") && !t.Secure:
		// a SAS token goes in every request as it is (the account key only
		// signs): over http anyone on the way could reuse it
		return nil, out.Errf(out.ExitUsage, "INSECURE_PROTOCOL",
			"use an https:// endpoint, or the account key (it signs each request and is never sent)",
			"azblob: the endpoint is http://, so the SAS token would travel unencrypted")
	case strings.Contains(secret, "sig="):
		q, err := url.ParseQuery(strings.TrimPrefix(secret, "?"))
		if err != nil {
			return nil, out.Usage("azblob: the SAS token is not a query string (sv=...&sig=...)")
		}
		b.sas = q
	default:
		k, err := base64.StdEncoding.DecodeString(secret)
		if err != nil || len(k) == 0 {
			return nil, out.Usage("azblob: the account key is not base64 (copy key1 or key2 from the portal, or use a SAS token)")
		}
		b.key = k
	}
	return b, nil
}

func (b *azBucket) Close() error { return nil }

// blobURL is the address of a blob, or of the container when name is "".
func (b *azBucket) blobURL(name string, q url.Values) string {
	u := b.base + "/" + escapeSegment(b.container)
	if name != "" {
		u += "/" + pathEscape(name)
	}
	if b.sas != nil {
		if q == nil {
			q = url.Values{}
		}
		for k, v := range b.sas {
			q[k] = v
		}
	}
	if len(q) > 0 {
		u += "?" + strings.ReplaceAll(q.Encode(), "+", "%20")
	}
	return u
}

// send signs (Shared Key) and sends a request; ok are the statuses that
// count as success.
func (b *azBucket) send(ctx context.Context, method, u string, body io.Reader, size int64, hdr http.Header, ok ...int) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if size >= 0 && body != nil {
		req.ContentLength = size
	}
	req.Header.Set("x-ms-version", azVersion)
	req.Header.Set("x-ms-date", b.now().UTC().Format(http.TimeFormat))
	if b.key != nil {
		req.Header.Set("Authorization", "SharedKey "+b.account+":"+b.signature(req))
	}
	return do(b.c, "azure", req, ok...)
}

// signature is the Shared Key signature of req (learn.microsoft.com:
// "Authorize with Shared Key", version 2009-09-19 and later).
func (b *azBucket) signature(req *http.Request) string {
	h := req.Header
	length := ""
	if req.ContentLength > 0 {
		length = strconv.FormatInt(req.ContentLength, 10)
	}
	var ms []string
	for k := range h {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-ms-") {
			ms = append(ms, lk)
		}
	}
	sort.Strings(ms)
	var canon strings.Builder
	for _, k := range ms {
		canon.WriteString(k + ":" + strings.TrimSpace(h.Get(k)) + "\n")
	}
	res := "/" + b.account + req.URL.EscapedPath()
	q := req.URL.Query()
	var names []string
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		res += "\n" + strings.ToLower(k) + ":" + strings.Join(vals, ",")
	}
	toSign := strings.Join([]string{req.Method, h.Get("Content-Encoding"), h.Get("Content-Language"), length,
		h.Get("Content-MD5"), h.Get("Content-Type"), "", h.Get("If-Modified-Since"), h.Get("If-Match"),
		h.Get("If-None-Match"), h.Get("If-Unmodified-Since"), h.Get("Range")}, "\n") + "\n" + canon.String() + res
	m := hmac.New(sha256.New, b.key)
	m.Write([]byte(toSign))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

type azList struct {
	Blobs struct {
		Blob []struct {
			Name       string `xml:"Name"`
			Properties struct {
				Modified string `xml:"Last-Modified"`
				Length   int64  `xml:"Content-Length"`
			} `xml:"Properties"`
		} `xml:"Blob"`
		Prefix []struct {
			Name string `xml:"Name"`
		} `xml:"BlobPrefix"`
	} `xml:"Blobs"`
	NextMarker string `xml:"NextMarker"`
}

func (b *azBucket) List(ctx context.Context, prefix string, recursive bool, limit int) ([]Object, bool, error) {
	full := b.prefix + strings.TrimPrefix(prefix, "/")
	objs := []Object{}
	marker := ""
	for {
		q := url.Values{"restype": {"container"}, "comp": {"list"}, "prefix": {full}}
		if !recursive {
			q.Set("delimiter", "/")
		}
		if marker != "" {
			q.Set("marker", marker)
		}
		resp, err := b.send(ctx, http.MethodGet, b.blobURL("", q), nil, -1, nil, http.StatusOK)
		if err != nil {
			return nil, false, azContainerMissing(err)
		}
		var page azList
		err = xml.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, false, webErr("azure", nil, err)
		}
		var got []Object
		for _, p := range page.Blobs.Prefix {
			got = append(got, Object{Key: strings.TrimPrefix(p.Name, b.prefix), Dir: true})
		}
		for _, it := range page.Blobs.Blob {
			if isMarker(it.Name, full, recursive) {
				continue
			}
			o := Object{Key: strings.TrimPrefix(it.Name, b.prefix), Size: it.Properties.Length}
			if t, err := http.ParseTime(it.Properties.Modified); err == nil {
				o.Modified = t.UTC()
			}
			got = append(got, o)
		}
		sort.Slice(got, func(i, j int) bool { return got[i].Key < got[j].Key })
		for _, o := range got {
			if o.Key == "" {
				continue
			}
			if limit > 0 && len(objs) >= limit {
				return objs, true, nil
			}
			objs = append(objs, o)
		}
		if marker = page.NextMarker; marker == "" {
			return objs, false, nil
		}
	}
}

func azContainerMissing(err error) error {
	if oe, ok := err.(*out.Error); ok && oe.Code == "OBJECT_NOT_FOUND" {
		return out.Errf(out.ExitNotFound, "BUCKET_NOT_FOUND", "check the container name in the conn URL (`komando conn show NAME`)", "container does not exist")
	}
	return err
}

func (b *azBucket) Stat(ctx context.Context, rel string) (Object, error) {
	full, err := keyIn(b.prefix, rel)
	if err != nil {
		return Object{}, err
	}
	resp, err := b.send(ctx, http.MethodHead, b.blobURL(full, nil), nil, -1, nil, http.StatusOK)
	if err != nil {
		if oe, ok := err.(*out.Error); ok && oe.Code == "OBJECT_NOT_FOUND" {
			return Object{}, out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list objects with `komando storage ls CONN [PREFIX]`", "%s not found", rel)
		}
		return Object{}, err
	}
	resp.Body.Close()
	o := Object{Key: strings.TrimPrefix(rel, "/"), Size: resp.ContentLength}
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		o.Modified = t.UTC()
	}
	return o, nil
}

func (b *azBucket) Exists(ctx context.Context, key string) (bool, error) {
	_, err := b.Stat(ctx, key)
	if oe, ok := err.(*out.Error); ok && oe.Code == "OBJECT_NOT_FOUND" {
		return false, nil
	}
	return err == nil, err
}

func (b *azBucket) Get(ctx context.Context, key string, w io.Writer) (int64, error) {
	full, err := keyIn(b.prefix, key)
	if err != nil {
		return 0, err
	}
	resp, err := b.send(ctx, http.MethodGet, b.blobURL(full, nil), nil, -1, nil, http.StatusOK)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(w, resp.Body)
	return n, webErr("azure", nil, err)
}

// azBlock is the size of one block when a blob goes up in blocks: a blob
// of unknown size, or one larger than azSingle.
var azBlock, azSingle int64 = 16 << 20, 256 << 20

// Put uploads a blob in one request when its size is known and small
// enough, otherwise in blocks (which needs no temporary file).
func (b *azBucket) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	full, err := keyIn(b.prefix, key)
	if err != nil {
		return err
	}
	ct := cmp.Or(contentType, "application/octet-stream")
	if size >= 0 && size <= azSingle {
		hdr := http.Header{"X-Ms-Blob-Type": {"BlockBlob"}, "Content-Type": {ct}}
		if size == 0 {
			r = http.NoBody
		}
		resp, err := b.send(ctx, http.MethodPut, b.blobURL(full, nil), r, size, hdr, http.StatusCreated)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	var ids []string
	buf := make([]byte, azBlock)
	for i := 0; ; i++ {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			id := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("komando-%08d", i)))
			q := url.Values{"comp": {"block"}, "blockid": {id}}
			resp, err := b.send(ctx, http.MethodPut, b.blobURL(full, q), bytes.NewReader(buf[:n]), int64(n), nil, http.StatusCreated)
			if err != nil {
				return err
			}
			resp.Body.Close()
			ids = append(ids, id)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return webErr("azure", nil, rerr)
		}
	}
	var list bytes.Buffer
	list.WriteString(`<?xml version="1.0" encoding="utf-8"?><BlockList>`)
	for _, id := range ids {
		list.WriteString("<Latest>" + id + "</Latest>")
	}
	list.WriteString("</BlockList>")
	hdr := http.Header{"X-Ms-Blob-Content-Type": {ct}, "Content-Type": {"application/xml"}}
	resp, err := b.send(ctx, http.MethodPut, b.blobURL(full, url.Values{"comp": {"blocklist"}}), bytes.NewReader(list.Bytes()), int64(list.Len()), hdr, http.StatusCreated)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// Remove deletes one blob; a missing one is not an error, as in S3.
func (b *azBucket) Remove(ctx context.Context, key string) error {
	full, err := keyIn(b.prefix, key)
	if err != nil {
		return err
	}
	resp, err := b.send(ctx, http.MethodDelete, b.blobURL(full, nil), nil, -1, nil, http.StatusAccepted, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// Link makes a read-only SAS URL for one blob, signed with the account
// key. A conn that logs in with a SAS token cannot make one.
func (b *azBucket) Link(ctx context.Context, key string, expires time.Duration) (*url.URL, error) {
	if b.key == nil {
		return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"store the account key instead of a SAS token to make links, or make one in the portal",
			"azure links are signed with the account key, and this conn has a SAS token")
	}
	if _, err := b.Stat(ctx, key); err != nil {
		return nil, err
	}
	full, _ := keyIn(b.prefix, key)
	return b.sasLink(full, expires, b.now().UTC())
}

// sasLink is a service SAS for reading one blob (version 2020-12-06 and
// later: the string to sign ends with the response headers).
func (b *azBucket) sasLink(full string, expires time.Duration, now time.Time) (*url.URL, error) {
	expiry := now.Add(expires).Format("2006-01-02T15:04:05Z")
	disp := contentDisposition(path.Base(full))
	proto := "https"
	if strings.HasPrefix(b.base, "http://") {
		proto = "https,http" // an emulator without TLS
	}
	canon := "/blob/" + b.account + "/" + b.container + "/" + full
	toSign := strings.Join([]string{"r", "", expiry, canon, "", "", proto, azVersion, "b", "", "", "", disp, "", "", ""}, "\n")
	m := hmac.New(sha256.New, b.key)
	m.Write([]byte(toSign))
	q := url.Values{"sv": {azVersion}, "sr": {"b"}, "sp": {"r"}, "se": {expiry}, "spr": {proto}, "rscd": {disp},
		"sig": {base64.StdEncoding.EncodeToString(m.Sum(nil))}}
	return url.Parse(b.base + "/" + escapeSegment(b.container) + "/" + pathEscape(full) + "?" + strings.ReplaceAll(q.Encode(), "+", "%20"))
}
