package storex

import (
	"context"
	"net/url"
	"path"
	"strings"

	"github.com/jlaffaye/ftp"
	"github.com/minio/minio-go/v7"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// CheckKey refuses a key that is empty or leaves the conn's folder, so a
// dry run can say so before contacting the server.
func CheckKey(rel string) error {
	_, err := keyIn("", rel)
	return err
}

// FolderNotFound is the one error for a folder that is not there, on every
// kind of storage.
func FolderNotFound(prefix string) error {
	return out.Errf(out.ExitNotFound, "FOLDER_NOT_FOUND", "list what exists with `komando storage list CONN` (or a parent folder)",
		"nothing under %q", prefix)
}

// contentDisposition makes the download name of a link: an ASCII fallback
// for old clients and the exact UTF-8 name (RFC 6266, RFC 5987).
func contentDisposition(name string) string {
	var ascii strings.Builder
	for _, r := range name {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			ascii.WriteByte('_')
		} else {
			ascii.WriteRune(r)
		}
	}
	return `attachment; filename="` + ascii.String() + `"; filename*=UTF-8''` + url.PathEscape(name)
}

// Stat describes one object (size and time) without reading it.
func (s *s3Bucket) Stat(ctx context.Context, rel string) (Object, error) {
	full, err := keyIn(s.prefix, rel)
	if err != nil {
		return Object{}, err
	}
	i, err := s.c.StatObject(ctx, s.bucket, full, minio.StatObjectOptions{})
	if err != nil {
		return Object{}, toErr(err)
	}
	return Object{Key: rel, Size: i.Size, Modified: i.LastModified.UTC()}, nil
}

func (b *sftpBucket) Stat(_ context.Context, rel string) (Object, error) {
	p, err := b.path(rel)
	if err != nil {
		return Object{}, err
	}
	fi, err := b.c.Stat(p)
	if err != nil {
		return Object{}, sftpErr(err)
	}
	if fi.IsDir() {
		return Object{}, isFolder(rel)
	}
	return Object{Key: rel, Size: fi.Size(), Modified: fi.ModTime().UTC()}, nil
}

func (b *ftpBucket) Stat(_ context.Context, rel string) (Object, error) {
	p, err := b.path(rel)
	if err != nil {
		return Object{}, err
	}
	entries, err := b.c.List(path.Dir(p))
	if err != nil && !isMissingDir(err) {
		return Object{}, ftpErr(err, driver.Target{})
	}
	for _, e := range entries {
		if e.Name != path.Base(p) {
			continue
		}
		if e.Type == ftp.EntryTypeFolder {
			return Object{}, isFolder(rel)
		}
		return Object{Key: rel, Size: int64(e.Size), Modified: e.Time.UTC()}, nil
	}
	return Object{}, out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list files with `komando storage list CONN [FOLDER]`", "%s not found", rel)
}

// isMarker reports a listed key ending in / that is a folder marker (an
// empty object consoles create), not a folder of the listing: in a
// recursive listing every such key is one, in a one-level listing the
// listed folder's own marker. listed is the full prefix that was listed.
func isMarker(key, listed string, recursive bool) bool {
	return strings.HasSuffix(key, "/") && (recursive || key == listed)
}

func isFolder(rel string) error {
	return out.Usage("%q is a folder; give a file, or use -r for everything in it", rel)
}
