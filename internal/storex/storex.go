// Package storex gives `komando storage` one interface over S3-compatible
// object storage (AWS S3, MinIO, R2, Wasabi, Spaces, B2), FTP/FTPS and
// SFTP. Keys are relative to the conn's folder, so a conn can be limited to
// one folder, and no key may leave it.
package storex

import (
	"context"
	"errors"
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
	// Put stores r at key, replacing any old object; size is -1 if unknown.
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	Remove(ctx context.Context, key string) error
	// Link makes a temporary download URL; file servers have none.
	Link(ctx context.Context, key string, expires time.Duration) (*url.URL, error)
	Close() error
}

// keyIn joins a key relative to the conn with the conn's folder, refusing
// keys that try to leave it.
func keyIn(prefix, rel string) (string, error) {
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "", out.Usage("empty key")
	}
	for _, part := range strings.Split(rel, "/") {
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
}

func init() {
	// a CLI call should fail fast and let the caller decide to retry
	minio.MaxRetry = 2
}

// OpenS3 prepares a client; it does not contact the server.
func OpenS3(t driver.Target, secret string, dial DialFunc, timeout time.Duration) (Bucket, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = timeout
	if dial != nil {
		tr.DialContext = dial
		tr.Proxy = nil // the --via host is the way out
	}
	c, err := minio.New(t.Address, &minio.Options{
		Creds:     credentials.NewStaticV4(t.User, secret, ""),
		Secure:    t.Secure,
		Region:    t.Region,
		Transport: tr,
	})
	if err != nil {
		return nil, out.Usage("invalid storage settings: %v", err)
	}
	return &s3Bucket{c: c, bucket: t.Bucket, prefix: t.Prefix}, nil
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
		if strings.HasSuffix(o.Key, "/") && o.Size == 0 && o.LastModified.IsZero() {
			obj.Dir = true
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
		"response-content-disposition": {`attachment; filename="` + strings.ReplaceAll(path.Base(full), `"`, "") + `"`},
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
		return out.Errf(out.ExitRemote, "STORAGE_ERROR", "", "%s: %s", r.Code, r.Message)
	}
	return out.Errf(out.ExitRemote, "STORAGE_ERROR", "", "%v", err)
}
