package storex

import (
	"context"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

// ObjectVersion is one version of an object in a bucket that keeps
// versions (S3 versioning): every overwrite and delete leaves the old
// content (or a delete marker) behind, which a plain list never shows.
type ObjectVersion struct {
	Key          string    `json:"key"`
	VersionID    string    `json:"version_id"`
	Size         int64     `json:"size"`
	Modified     time.Time `json:"modified,omitempty"`
	Latest       bool      `json:"latest,omitempty"`
	DeleteMarker bool      `json:"delete_marker,omitempty"`
}

// Versioned is a bucket whose old versions komando can list and remove
// (S3 and S3-compatible stores; others keep no versions komando can see).
type Versioned interface {
	Versions(ctx context.Context, prefix string, limit int) (vs []ObjectVersion, more bool, err error)
	RemoveVersion(ctx context.Context, key, versionID string) error
}

// Versions lists every version and delete marker under prefix, newest
// first per key; more is true when limit was hit.
func (s *s3Bucket) Versions(ctx context.Context, prefix string, limit int) ([]ObjectVersion, bool, error) {
	full := s.prefix + strings.TrimPrefix(prefix, "/")
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	vs := []ObjectVersion{}
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: full, Recursive: true, WithVersions: true}) {
		if o.Err != nil {
			return nil, false, toErr(o.Err)
		}
		if limit > 0 && len(vs) >= limit {
			return vs, true, nil
		}
		key := s.rel(o.Key)
		if key == "" || strings.HasSuffix(o.Key, "/") {
			continue
		}
		vs = append(vs, ObjectVersion{Key: key, VersionID: o.VersionID, Size: o.Size, Modified: o.LastModified.UTC(),
			Latest: o.IsLatest, DeleteMarker: o.IsDeleteMarker})
	}
	return vs, false, nil
}

// RemoveVersion deletes one version (or delete marker) of key for good.
func (s *s3Bucket) RemoveVersion(ctx context.Context, key, versionID string) error {
	full, err := s.Key(key)
	if err != nil {
		return err
	}
	return toErr(s.c.RemoveObject(ctx, s.bucket, full, minio.RemoveObjectOptions{VersionID: versionID}))
}
