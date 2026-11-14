package storex

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"

	"github.com/sgnd/komando/internal/out"
)

// mkdir, mv and folders on the object stores (S3, Google Cloud Storage,
// Azure Blob). They have no folders, only keys: a folder is every key
// under name/, and an empty "name/" object (a folder marker) when it holds
// nothing yet. A move is a copy on the server, checked, then a delete.

// S3

func (s *s3Bucket) Lookup(ctx context.Context, rel string) (Object, bool, error) {
	r := strings.Trim(rel, "/")
	full, err := keyIn(s.prefix, r)
	if err != nil {
		return Object{}, false, err
	}
	i, err := s.c.StatObject(ctx, s.bucket, full, minio.StatObjectOptions{})
	if err == nil {
		return Object{Key: r, Size: i.Size, Modified: i.LastModified.UTC()}, true, nil
	}
	if code := minio.ToErrorResponse(err).Code; code != "NoSuchKey" && code != "NotFound" {
		return Object{}, false, toErr(err)
	}
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// the first key under rel/ (its marker too) is enough
	o, ok := <-s.c.ListObjects(lctx, s.bucket, minio.ListObjectsOptions{Prefix: full + "/", Recursive: true, MaxKeys: 1})
	switch {
	case !ok:
		return Object{}, false, nil
	case o.Err != nil:
		return Object{}, false, toErr(o.Err)
	}
	return Object{Key: r + "/", Dir: true}, true, nil
}

func (s *s3Bucket) Mkdir(ctx context.Context, rel string) (bool, error) {
	return markerMkdir(ctx, s, rel)
}

func (s *s3Bucket) Move(ctx context.Context, src, dst string, o MoveOpts) (Moved, error) {
	return copyMove(ctx, s, src, dst, o, "S3")
}

// s3MaxCopy is the largest object one CopyObject request copies; a larger
// one is copied in parts.
const s3MaxCopy = 5 << 30

func (s *s3Bucket) copyObject(ctx context.Context, src, dst string, _ bool) error {
	from, err := keyIn(s.prefix, src)
	if err != nil {
		return err
	}
	to, err := keyIn(s.prefix, dst)
	if err != nil {
		return err
	}
	i, err := s.c.StatObject(ctx, s.bucket, from, minio.StatObjectOptions{})
	if err != nil {
		return toErr(err)
	}
	// MatchETag: the copy fails rather than take a src changed meanwhile
	srcOpts := minio.CopySrcOptions{Bucket: s.bucket, Object: from, MatchETag: i.ETag}
	dstOpts := minio.CopyDestOptions{Bucket: s.bucket, Object: to}
	if i.Size > s3MaxCopy {
		_, err = s.c.ComposeObject(ctx, dstOpts, srcOpts)
	} else {
		_, err = s.c.CopyObject(ctx, dstOpts, srcOpts)
	}
	return toErr(err)
}

// fingerprint: an S3 ETag is the MD5 of the content for an object sent in
// one piece without KMS encryption; for others it says nothing a copy
// keeps, so only the size is compared.
func (s *s3Bucket) fingerprint(ctx context.Context, rel string) (int64, string, error) {
	full, err := keyIn(s.prefix, rel)
	if err != nil {
		return 0, "", err
	}
	i, err := s.c.StatObject(ctx, s.bucket, full, minio.StatObjectOptions{})
	if err != nil {
		return 0, "", toErr(err)
	}
	etag := strings.Trim(i.ETag, `"`)
	if len(etag) != 32 || strings.Contains(etag, "-") || i.Metadata.Get("X-Amz-Server-Side-Encryption") == "aws:kms" {
		etag = ""
	}
	return i.Size, etag, nil
}

// Google Cloud Storage

func (b *gcsBucket) Lookup(ctx context.Context, rel string) (Object, bool, error) {
	r := strings.Trim(rel, "/")
	full, err := b.object(r)
	if err != nil {
		return Object{}, false, err
	}
	o, err := b.Stat(ctx, r)
	if err == nil {
		return o, true, nil
	}
	if oe, ok := err.(*out.Error); !ok || oe.Code != "OBJECT_NOT_FOUND" {
		return Object{}, false, err
	}
	q := url.Values{"prefix": {full + "/"}, "maxResults": {"1"}, "fields": {"items(name),prefixes"}}
	resp, err := b.get(ctx, b.base+"/storage/v1/b/"+url.PathEscape(b.bucket)+"/o?"+q.Encode(), http.StatusOK)
	if err != nil {
		return Object{}, false, bucketMissing(err)
	}
	defer resp.Body.Close()
	var page struct {
		Items    []gcsObject `json:"items"`
		Prefixes []string    `json:"prefixes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return Object{}, false, webErr("gcs", nil, err)
	}
	if len(page.Items)+len(page.Prefixes) > 0 {
		return Object{Key: r + "/", Dir: true}, true, nil
	}
	return Object{}, false, nil
}

func (b *gcsBucket) Mkdir(ctx context.Context, rel string) (bool, error) {
	return markerMkdir(ctx, b, rel)
}

func (b *gcsBucket) Move(ctx context.Context, src, dst string, o MoveOpts) (Moved, error) {
	return copyMove(ctx, b, src, dst, o, "Google Cloud Storage")
}

// copyObject rewrites src to dst. A large object may take several calls,
// each one going on from the last one's token. Without overwrite, the
// copy is made only while dst does not exist (ifGenerationMatch=0).
func (b *gcsBucket) copyObject(ctx context.Context, src, dst string, overwrite bool) error {
	from, err := b.object(src)
	if err != nil {
		return err
	}
	to, err := b.object(dst)
	if err != nil {
		return err
	}
	token := ""
	for {
		q := url.Values{}
		if !overwrite {
			q.Set("ifGenerationMatch", "0")
		}
		if token != "" {
			q.Set("rewriteToken", token)
		}
		u := b.objectURL(from) + "/rewriteTo/b/" + url.PathEscape(b.bucket) + "/o/" + url.PathEscape(to)
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
		if err != nil {
			return err
		}
		resp, err := do(b.c, "gcs", req, http.StatusOK, http.StatusPreconditionFailed)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusPreconditionFailed {
			resp.Body.Close()
			return fileInTheWay(dst)
		}
		var r struct {
			Done         bool   `json:"done"`
			RewriteToken string `json:"rewriteToken"`
		}
		err = json.NewDecoder(resp.Body).Decode(&r)
		resp.Body.Close()
		if err != nil {
			return webErr("gcs", nil, err)
		}
		if r.Done {
			return nil
		}
		if token = r.RewriteToken; token == "" {
			return out.Errf(out.ExitRemote, "MOVE_FAILED", "run it again: `komando storage mv CONN SRC DST`", "gcs: the copy did not finish and gave no token to go on; %q was kept", src)
		}
	}
}

// fingerprint: GCS keeps a CRC32C of every object, which a copy keeps.
func (b *gcsBucket) fingerprint(ctx context.Context, rel string) (int64, string, error) {
	full, err := b.object(rel)
	if err != nil {
		return 0, "", err
	}
	resp, err := b.get(ctx, b.objectURL(full)+"?fields=size,crc32c,md5Hash", http.StatusOK)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var o struct {
		Size   string `json:"size"`
		CRC32C string `json:"crc32c"`
		MD5    string `json:"md5Hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&o); err != nil {
		return 0, "", webErr("gcs", nil, err)
	}
	n, _ := strconv.ParseInt(o.Size, 10, 64)
	sum := ""
	if o.CRC32C != "" || o.MD5 != "" {
		sum = o.CRC32C + "/" + o.MD5
	}
	return n, sum, nil
}

// Azure Blob

func (b *azBucket) Lookup(ctx context.Context, rel string) (Object, bool, error) {
	r := strings.Trim(rel, "/")
	full, err := keyIn(b.prefix, r)
	if err != nil {
		return Object{}, false, err
	}
	o, err := b.Stat(ctx, r)
	if err == nil {
		return o, true, nil
	}
	if oe, ok := err.(*out.Error); !ok || oe.Code != "OBJECT_NOT_FOUND" {
		return Object{}, false, err
	}
	q := url.Values{"restype": {"container"}, "comp": {"list"}, "prefix": {full + "/"}, "maxresults": {"1"}}
	resp, err := b.send(ctx, http.MethodGet, b.blobURL("", q), nil, -1, nil, http.StatusOK)
	if err != nil {
		return Object{}, false, azContainerMissing(err)
	}
	defer resp.Body.Close()
	var page azList
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&page); err != nil {
		return Object{}, false, webErr("azure", nil, err)
	}
	if len(page.Blobs.Blob)+len(page.Blobs.Prefix) > 0 {
		return Object{Key: r + "/", Dir: true}, true, nil
	}
	return Object{}, false, nil
}

func (b *azBucket) Mkdir(ctx context.Context, rel string) (bool, error) {
	return markerMkdir(ctx, b, rel)
}

func (b *azBucket) Move(ctx context.Context, src, dst string, o MoveOpts) (Moved, error) {
	return copyMove(ctx, b, src, dst, o, "Azure Blob")
}

// azCopyWait is how long komando waits between looks at a copy the
// service finishes later (a large blob).
var azCopyWait = time.Second

// copyObject asks the service to copy src to dst (Copy Blob) and waits
// until the copy is done. Without overwrite, the copy is made only while
// dst does not exist (If-None-Match: *).
func (b *azBucket) copyObject(ctx context.Context, src, dst string, overwrite bool) error {
	from, err := keyIn(b.prefix, src)
	if err != nil {
		return err
	}
	to, err := keyIn(b.prefix, dst)
	if err != nil {
		return err
	}
	// the source is in the same account: the request's own Shared Key
	// signature (or the SAS token in the URL) covers it
	hdr := http.Header{"X-Ms-Copy-Source": {b.blobURL(from, nil)}}
	if !overwrite {
		hdr.Set("If-None-Match", "*")
	}
	resp, err := b.send(ctx, http.MethodPut, b.blobURL(to, nil), nil, -1, hdr, http.StatusAccepted, http.StatusCreated, http.StatusConflict, http.StatusPreconditionFailed)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusPreconditionFailed {
		return fileInTheWay(dst)
	}
	status := resp.Header.Get("X-Ms-Copy-Status")
	for status == "pending" {
		select {
		case <-ctx.Done():
			return webErr("azure", nil, ctx.Err())
		case <-time.After(azCopyWait):
		}
		resp, err := b.send(ctx, http.MethodHead, b.blobURL(to, nil), nil, -1, nil, http.StatusOK)
		if err != nil {
			return err
		}
		resp.Body.Close()
		status = resp.Header.Get("X-Ms-Copy-Status")
	}
	if status != "" && status != "success" {
		return out.Errf(out.ExitRemote, "MOVE_FAILED", "run it again: `komando storage mv CONN SRC DST`", "azure: the copy ended %s; %q was kept", status, src)
	}
	return nil
}

// fingerprint: Azure keeps the MD5 of a blob sent in one piece, and a
// copy keeps it.
func (b *azBucket) fingerprint(ctx context.Context, rel string) (int64, string, error) {
	full, err := keyIn(b.prefix, rel)
	if err != nil {
		return 0, "", err
	}
	resp, err := b.send(ctx, http.MethodHead, b.blobURL(full, nil), nil, -1, nil, http.StatusOK)
	if err != nil {
		return 0, "", err
	}
	resp.Body.Close()
	return resp.ContentLength, resp.Header.Get("Content-Md5"), nil
}
