package cli

import (
	"context"
	"io"
	"mime"
	"path"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/storex"
)

// Sync side: a prefix in a storage conn.

type bucketSide struct {
	b      storex.Bucket
	prefix string // "" or "folder/" inside the conn
}

func (b bucketSide) key(rel string) string { return b.prefix + rel }

func (b bucketSide) list(ctx context.Context) (map[string]syncFile, error) {
	objs, more, err := b.b.List(ctx, b.prefix, true, 1_000_000)
	if err != nil {
		if toErr(err).Exit == out.ExitNotFound {
			return map[string]syncFile{}, errSideMissing // SFTP/FTP: the folder is not there yet
		}
		return nil, err
	}
	if more {
		return nil, out.Usage("more than a million objects under %q; sync a smaller prefix", b.prefix)
	}
	files := map[string]syncFile{}
	for _, o := range objs {
		rel := strings.TrimPrefix(o.Key, b.prefix)
		// folder markers: the prefix itself, or a key ending in / (S3
		// consoles create them); they hold no file
		if o.Dir || rel == "" || strings.HasSuffix(rel, "/") || o.Key+"/" == b.prefix {
			continue
		}
		files[rel] = syncFile{Size: o.Size, Mtime: o.Modified}
	}
	if len(files) == 0 {
		return files, errSideMissing // nothing under the prefix: S3 has no empty folders
	}
	return files, nil
}

func (b bucketSide) open(ctx context.Context, rel string) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	go func() {
		_, err := b.b.Get(ctx, b.key(rel), pw)
		pw.CloseWithError(err)
	}()
	return pr, nil
}

func (b bucketSide) write(ctx context.Context, rel string, r io.Reader, f syncFile) error {
	return b.b.Put(ctx, b.key(rel), r, f.Size, mime.TypeByExtension(path.Ext(rel)))
}

func (b bucketSide) remove(ctx context.Context, rel string) error {
	return b.b.Remove(ctx, b.key(rel))
}
