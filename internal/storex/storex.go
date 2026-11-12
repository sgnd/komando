// Package storex gives `komando storage` one interface over S3-compatible
// object storage (AWS S3, MinIO, R2, Wasabi, Spaces, B2), Google Cloud
// Storage, Azure Blob, FTP/FTPS, SFTP, WebDAV and SMB shares. Keys are
// relative to the conn's folder, so a conn can be limited to one folder,
// and no key may leave it.
package storex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// DialFunc opens a TCP connection, possibly through an SSH host.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Bucket is one storage conn: a bucket or a folder on a file server.
type Bucket interface {
	// List returns entries under prefix: one level, or everything with
	// recursive. more is true when limit was hit.
	List(ctx context.Context, prefix string, recursive bool, limit int) (objs []Object, more bool, err error)
	Get(ctx context.Context, key string, w io.Writer) (int64, error)
	Exists(ctx context.Context, key string) (bool, error)
	// Stat describes one object (not a folder) without reading it.
	Stat(ctx context.Context, key string) (Object, error)
	// Put stores r at key, replacing any old object; size is -1 if unknown.
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	Remove(ctx context.Context, key string) error
	// Link makes a temporary download URL; file servers have none.
	Link(ctx context.Context, key string, expires time.Duration) (*url.URL, error)
	Close() error
}

// keyIn joins a key relative to the conn with the conn's folder, refusing
// keys that try to leave it. A \ counts as a separator too: SMB servers
// read it as one, so a\..\..\x would climb out of the folder.
func keyIn(prefix, rel string) (string, error) {
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "", out.Usage("empty key")
	}
	for _, part := range strings.FieldsFunc(rel, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return "", out.Usage("key %q leaves the conn's folder", rel)
		}
	}
	return prefix + rel, nil
}

// s3Bucket is a bucket (and prefix) on S3-compatible storage.
type s3Bucket struct {
	c      *minio.Client
	bucket string
	prefix string
	creds  *credentials.Credentials // kept to sign links for another address (LinkAt)
	region string
	temp   bool // temporary keys (a session token): links end when they do
}

// TemporaryKeys reports whether the bucket logs in with temporary keys
// (SSO, an assumed role): a link signed with them stops working when they
// expire, which can be before the link's own time is up.
func (s *s3Bucket) TemporaryKeys() bool { return s.temp }

func init() {
	// a CLI call should fail fast and let the caller decide to retry
	minio.MaxRetry = 2
}

// OpenS3 prepares a client; it does not contact the server.
func OpenS3(t driver.Target, secret string, dial DialFunc, timeout time.Duration) (Bucket, error) {
	return OpenS3Creds(t, t.User, secret, "", dial, timeout)
}

// OpenS3Creds is OpenS3 with explicit credentials, including the session
// token of temporary ones (SSO, an assumed role).
func OpenS3Creds(t driver.Target, accessKey, secret, sessionToken string, dial DialFunc, timeout time.Duration) (Bucket, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = timeout
	if dial != nil {
		tr.DialContext = dial
		tr.Proxy = nil // the --via host is the way out
	}
	creds := credentials.NewStaticV4(accessKey, secret, sessionToken)
	c, err := minio.New(t.Address, &minio.Options{
		Creds:     creds,
		Secure:    t.Secure,
		Region:    t.Region,
		Transport: tr,
	})
	if err != nil {
		return nil, out.Usage("invalid storage settings: %v", err)
	}
	return &s3Bucket{c: c, bucket: t.Bucket, prefix: t.Prefix, creds: creds, region: t.Region, temp: sessionToken != ""}, nil
}

// BucketInfo is one bucket an account can see, and where it lives.
type BucketInfo struct{ Name, Region string }

// ListBuckets lists the buckets the keys can see at endpoint (a URL, ""
// for AWS), each with its region.
func ListBuckets(ctx context.Context, endpoint, accessKey, secret, sessionToken, region string) ([]BucketInfo, error) {
	host, secure := "s3.amazonaws.com", true
	if endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("bad S3 endpoint %q", endpoint)
		}
		host, secure = u.Host, u.Scheme == "https"
	}
	c, err := minio.New(host, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secret, sessionToken), Secure: secure, Region: region})
	if err != nil {
		return nil, err
	}
	bs, err := c.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]BucketInfo, 0, len(bs))
	for _, b := range bs {
		r, err := c.GetBucketLocation(ctx, b.Name)
		if err != nil || r == "" {
			r = region
		}
		out = append(out, BucketInfo{Name: b.Name, Region: r})
	}
	return out, nil
}

func (s *s3Bucket) Key(rel string) (string, error) { return keyIn(s.prefix, rel) }

func (s *s3Bucket) rel(full string) string { return strings.TrimPrefix(full, s.prefix) }

func (s *s3Bucket) Close() error { return nil }

// Object is one listed object (or, with Dir, a folder).
type Object struct {
	Key      string    `json:"key"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified,omitempty"`
	Dir      bool      `json:"dir,omitempty"`
}

// List returns objects under prefix. Without recursive it lists one level
// and returns sub-folders as Dir entries. more is true when the limit was hit.
func (s *s3Bucket) List(ctx context.Context, prefix string, recursive bool, limit int) (objs []Object, more bool, err error) {
	full := s.prefix + strings.TrimPrefix(prefix, "/")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	objs = []Object{}
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: full, Recursive: recursive}) {
		if o.Err != nil {
			return nil, false, toErr(o.Err)
		}
		if limit > 0 && len(objs) >= limit {
			return objs, true, nil
		}
		obj := Object{Key: s.rel(o.Key), Size: o.Size, Modified: o.LastModified.UTC()}
		if strings.HasSuffix(o.Key, "/") {
			// a folder: either a common prefix (one level), or an empty
			// "folder marker" object that consoles create; a marker is no file
			// and is left out (and so is the marker of the listed folder itself)
			if isMarker(o.Key, full, recursive) {
				continue
			}
			obj.Dir = true
		}
		if obj.Key == "" {
			continue
		}
		objs = append(objs, obj)
	}
	return objs, false, nil
}

// Get writes an object to w and returns its size.
func (s *s3Bucket) Get(ctx context.Context, key string, w io.Writer) (int64, error) {
	full, err := s.Key(key)
	if err != nil {
		return 0, err
	}
	o, err := s.c.GetObject(ctx, s.bucket, full, minio.GetObjectOptions{})
	if err != nil {
		return 0, toErr(err)
	}
	defer o.Close()
	n, err := io.Copy(w, o)
	if err != nil {
		return n, toErr(err)
	}
	return n, nil
}

// Exists reports whether key exists (to tell a new upload from a replace).
func (s *s3Bucket) Exists(ctx context.Context, key string) (bool, error) {
	full, err := s.Key(key)
	if err != nil {
		return false, err
	}
	_, err = s.c.StatObject(ctx, s.bucket, full, minio.StatObjectOptions{})
	if err == nil {
		return true, nil
	}
	if code := minio.ToErrorResponse(err).Code; code == "NoSuchKey" || code == "NotFound" {
		return false, nil
	}
	return false, toErr(err)
}

// Put uploads r (size bytes, -1 if unknown) to key.
func (s *s3Bucket) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	full, err := s.Key(key)
	if err != nil {
		return err
	}
	_, err = s.c.PutObject(ctx, s.bucket, full, r, size, minio.PutObjectOptions{ContentType: contentType})
	return toErr(err)
}

// Remove deletes one object. Deleting a missing key is not an error in S3.
func (s *s3Bucket) Remove(ctx context.Context, key string) error {
	full, err := s.Key(key)
	if err != nil {
		return err
	}
	return toErr(s.c.RemoveObject(ctx, s.bucket, full, minio.RemoveObjectOptions{}))
}

// Link makes a temporary download URL that works without credentials.
func (s *s3Bucket) Link(ctx context.Context, key string, expires time.Duration) (*url.URL, error) {
	full, err := s.Key(key)
	if err != nil {
		return nil, err
	}
	if _, err := s.c.StatObject(ctx, s.bucket, full, minio.StatObjectOptions{}); err != nil {
		return nil, toErr(err)
	}
	u, err := s.c.PresignedGetObject(ctx, s.bucket, full, expires, url.Values{
		"response-content-disposition": {contentDisposition(path.Base(full))},
	})
	return u, toErr(err)
}

// LinkAt is Link for people who reach the storage at another address than
// komando does (komando goes through --via; they use the public name). The
// link is signed for that address; nothing is sent to it.
func (s *s3Bucket) LinkAt(ctx context.Context, key string, expires time.Duration, endpoint *url.URL) (*url.URL, error) {
	full, err := s.Key(key)
	if err != nil {
		return nil, err
	}
	if _, err := s.c.StatObject(ctx, s.bucket, full, minio.StatObjectOptions{}); err != nil {
		return nil, toErr(err)
	}
	region := s.region
	if region == "" {
		// the signature names the region: ask the server komando reaches
		if region, err = s.c.GetBucketLocation(ctx, s.bucket); err != nil {
			return nil, toErr(err)
		}
	}
	pub, err := minio.New(endpoint.Host, &minio.Options{Creds: s.creds, Secure: endpoint.Scheme == "https", Region: region})
	if err != nil {
		return nil, out.Usage("--endpoint %s: %v", endpoint, err)
	}
	u, err := pub.PresignedGetObject(ctx, s.bucket, full, expires, url.Values{
		"response-content-disposition": {contentDisposition(path.Base(full))},
	})
	return u, toErr(err)
}

func toErr(err error) error {
	if err == nil {
		return nil
	}
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout, or leave it unset for large transfers", "storage did not answer in time")
	}
	r := minio.ToErrorResponse(err)
	if err := regionErr(r); err != nil {
		return err
	}
	switch r.Code {
	case "NoSuchKey", "NotFound":
		return out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list objects with `komando storage ls CONN [PREFIX]`", "object not found")
	case "NoSuchBucket":
		return out.Errf(out.ExitNotFound, "BUCKET_NOT_FOUND", "check the bucket name in the conn URL (`komando conn show NAME`)", "bucket does not exist")
	case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "InvalidToken", "ExpiredToken":
		return out.Errf(out.ExitConnect, "STORAGE_AUTH", "check the access key ID in the URL and the secret key reference; the key may lack permission for this action", "%s: %s", r.Code, r.Message)
	}
	var ne net.Error
	if errors.As(err, &ne) || strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
		return out.Errf(out.ExitConnect, "STORAGE_CONNECT", "run `komando conn test NAME` to check reachability", "%v", err)
	}
	if r.Code != "" {
		return out.Errf(out.ExitRemote, "STORAGE_ERROR", "run `komando conn test NAME` to check the conn", "%s: %s", r.Code, r.Message)
	}
	return out.Errf(out.ExitRemote, "STORAGE_ERROR", "run `komando conn test NAME` to check the conn", "%v", err)
}

// regionErr names the bucket's region when the conn's is wrong (AWS says
// which one it is), or nil when the answer was about something else.
func regionErr(r minio.ErrorResponse) error {
	switch r.Code {
	case "AuthorizationHeaderMalformed", "PermanentRedirect", "InvalidRegion", "IllegalLocationConstraintException", "AuthorizationQueryParametersError":
		if r.Region == "" && r.Code != "PermanentRedirect" && r.Code != "InvalidRegion" && !strings.Contains(strings.ToLower(r.Message), "region") {
			return nil
		}
	default:
		// an answer without a body (HEAD): the status, and the region
		// header AWS adds
		if r.Region == "" || (r.StatusCode != http.StatusBadRequest && r.StatusCode != http.StatusMovedPermanently) {
			return nil
		}
	}
	if r.Region == "" {
		return out.Errf(out.ExitRemote, "STORAGE_ERROR",
			"set the bucket's region in the conn URL (region=...) with `komando conn edit NAME --url URL`; `komando conn show NAME` shows the URL now",
			"the bucket is not in the region the conn uses (%s: %s)", r.Code, r.Message)
	}
	return out.Errf(out.ExitRemote, "STORAGE_ERROR",
		"set region="+r.Region+" in the conn URL (and leave out a regional endpoint) with `komando conn edit NAME --url URL`; `komando conn show NAME` shows the URL now",
		"the bucket is in region %s, not in the one the conn uses", r.Region)
}
