package storex

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// `storage mkdir`, `storage mv` and `storage chmod`: what every kind
// shares. Each kind's own steps are next to the rest of its code.

// MoveOpts says how Move goes.
type MoveOpts struct {
	// Overwrite replaces a file at dst. A folder is never replaced, and a
	// folder never replaces a file.
	Overwrite bool
	// DryRun only checks, changes nothing and says what would happen.
	DryRun bool
}

// Moved is what Move did, or in a dry run would do.
type Moved struct {
	Folder   bool  // src is a folder (file servers only)
	Replaced bool  // a file at dst was (or would be) replaced
	Size     int64 // src's size; 0 for a folder
	Copied   bool  // an object store: copied, checked, then src deleted (or would be)
}

// Modes is a store whose files have Unix modes: SFTP. Other kinds have
// none (an object store controls access per bucket, not per file).
type Modes interface {
	Mode(ctx context.Context, rel string) (fs.FileMode, error)
	Chmod(ctx context.Context, rel string, mode fs.FileMode) error
}

type lookuper interface {
	Lookup(ctx context.Context, rel string) (Object, bool, error)
}

// cleanRel is rel without its leading and trailing slashes, checked to
// stay inside the conn's folder.
func cleanRel(rel string) (string, error) {
	r := strings.Trim(rel, "/")
	if err := CheckKey(r); err != nil {
		return "", err
	}
	if r == "." || path.Clean(r) != r {
		return "", out.Usage("write %q without . or // in it", rel)
	}
	return r, nil
}

// renameOver replaces the file at pd with ps by renames only: the old file
// goes aside first (.komando-old-NAME) and comes back when the rename
// fails, so a failed --overwrite never loses it. s and d name them in
// messages; wrap turns the store's own errors into komando's.
func renameOver(rename func(from, to string) error, remove func(p string) error, wrap func(error) error, ps, pd, s, d string) error {
	old := path.Join(path.Dir(pd), ".komando-old-"+path.Base(pd))
	_ = remove(old) // left by a move or upload that was cut off
	if err := rename(pd, old); err != nil {
		return wrap(err)
	}
	if err := rename(ps, pd); err != nil {
		if rerr := rename(old, pd); rerr != nil {
			aside := path.Join(path.Dir(d), path.Base(old))
			return out.Errf(out.ExitRemote, "MOVE_FAILED", "put the old file back: `komando storage mv CONN "+arg(aside)+" "+arg(d)+"`",
				"could not rename %q to %q (%v), nor put the old %q back from %q (%v)", s, d, err, d, aside, rerr)
		}
		return wrap(err)
	}
	_ = remove(old)
	return nil
}

// copyFailed is the error for a server-side copy that ended badly; src
// stays where it was.
func copyFailed(store, src, dst, why string) error {
	return out.Errf(out.ExitRemote, "MOVE_FAILED", fmt.Sprintf("run it again: `komando storage mv CONN %s %s`", arg(src), arg(dst)),
		"the copy on the server (%s) ended badly: %s; %q was kept", store, why, src)
}

// entry is what a file server says about rel, as a Lookup answer.
func entry(rel string, fi fs.FileInfo) Object {
	if fi.IsDir() {
		return Object{Key: rel + "/", Dir: true, Modified: fi.ModTime().UTC()}
	}
	return Object{Key: rel, Size: fi.Size(), Modified: fi.ModTime().UTC()}
}

// plainWord is a word a shell takes as it is.
var plainWord = regexp.MustCompile(`^[A-Za-z0-9._/@%+=:,-]+$`)

// arg is s as one shell word, for a command in a hint.
func arg(s string) string {
	if plainWord.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// NotThere is the error for a name with nothing at it.
func NotThere(rel string) error {
	return out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list what is there with `komando storage list CONN [PREFIX]`",
		"no file or folder named %q", rel)
}

func fileInTheWay(rel string) error {
	return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another name; `komando storage list CONN [PREFIX]` shows what is there",
		"a file named %q is already there", rel)
}

// checkMove is the part of Move every kind shares, and all a dry run
// does. objectStore names a kind that has no folders to rename ("" for
// a file server).
func checkMove(ctx context.Context, b lookuper, src, dst string, o MoveOpts, objectStore string) (Moved, error) {
	s, err := cleanRel(src)
	if err != nil {
		return Moved{}, err
	}
	d, err := cleanRel(dst)
	if err != nil {
		return Moved{}, err
	}
	if s == d {
		return Moved{}, out.Usage("SRC and DST are the same (%q)", s)
	}
	if strings.HasPrefix(d+"/", s+"/") {
		return Moved{}, out.Usage("cannot move %q into itself (%q)", s, d)
	}
	so, found, err := b.Lookup(ctx, s)
	if err != nil {
		return Moved{}, err
	}
	if !found {
		return Moved{}, NotThere(s)
	}
	if so.Dir && objectStore != "" {
		return Moved{}, out.Errf(out.ExitUsage, "STORAGE_UNSUPPORTED",
			fmt.Sprintf("list the objects in it with `komando storage list CONN %s --recursive` and move them one at a time", arg(s+"/")),
			"%q is a folder: %s has no folders to rename, only objects, and mv moves one object", s, objectStore)
	}
	do, found, err := b.Lookup(ctx, d)
	if err != nil {
		return Moved{}, err
	}
	switch {
	case found && do.Dir:
		return Moved{}, out.Errf(out.ExitConflict, "FILE_EXISTS",
			fmt.Sprintf("to move it into that folder, end DST with /: `komando storage mv CONN %s %s`", arg(s), arg(d+"/")),
			"%q is a folder", d)
	case found && so.Dir:
		return Moved{}, out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another DST; a folder never replaces a file",
			"a file named %q is already there", d)
	case found && !o.Overwrite:
		return Moved{}, out.Errf(out.ExitConflict, "FILE_EXISTS",
			fmt.Sprintf("replace it with `komando storage mv CONN %s %s --overwrite`, or pick another DST", arg(s), arg(d)),
			"a file named %q is already there", d)
	}
	return Moved{Folder: so.Dir, Replaced: found, Size: so.Size}, nil
}

// objectCopier is an object store, which moves by copying.
type objectCopier interface {
	lookuper
	Remove(ctx context.Context, key string) error
	// copyObject copies src to dst inside the bucket, on the server.
	copyObject(ctx context.Context, src, dst string, overwrite bool) error
	// fingerprint is the size and a checksum of rel's content that a copy
	// keeps ("" when the store gives none komando can compare).
	fingerprint(ctx context.Context, rel string) (size int64, sum string, err error)
}

// copyMove is Move on an object store: copy on the server, check that the
// copy has the source's size and checksum, and only then delete src.
func copyMove(ctx context.Context, b objectCopier, src, dst string, o MoveOpts, store string) (Moved, error) {
	m, err := checkMove(ctx, b, src, dst, o, store)
	if err != nil {
		return m, err
	}
	m.Copied = true
	if o.DryRun {
		return m, nil
	}
	s, d := strings.Trim(src, "/"), strings.Trim(dst, "/")
	size, sum, err := b.fingerprint(ctx, s)
	if err != nil {
		return m, err
	}
	if err := b.copyObject(ctx, s, d, o.Overwrite); err != nil {
		return m, err
	}
	gotSize, gotSum, err := b.fingerprint(ctx, d)
	if err == nil && (gotSize != size || sum != "" && gotSum != "" && gotSum != sum) {
		err = fmt.Errorf("size %d and checksum %q, not %d and %q", gotSize, gotSum, size, sum)
	}
	if err != nil {
		// a copy that does not match is wrong data: it goes, src stays
		_ = b.Remove(ctx, d)
		return m, out.Errf(out.ExitRemote, "MOVE_FAILED", fmt.Sprintf("run it again: `komando storage mv CONN %s %s`", arg(s), arg(d)),
			"the copy at %q could not be checked against %q (%v); %q was kept and the copy deleted", d, s, err, s)
	}
	if err := b.Remove(ctx, s); err != nil {
		return m, out.Errf(out.ExitRemote, "MOVE_FAILED", fmt.Sprintf("delete the old one: `komando storage rm CONN %s`", arg(s)),
			"copied %q to %q and checked the copy, but could not delete %q (%v); both are there now", s, d, s, err)
	}
	return m, nil
}

// markerMkdir is Mkdir on an object store: an empty folder marker.
func markerMkdir(ctx context.Context, b Bucket, rel string) (bool, error) {
	r, err := cleanRel(rel)
	if err != nil {
		return false, err
	}
	o, found, err := b.Lookup(ctx, r)
	if err != nil || found && o.Dir {
		return found, err
	}
	if found {
		return false, fileInTheWay(r)
	}
	return false, b.Put(ctx, r+"/", strings.NewReader(""), 0, "")
}
