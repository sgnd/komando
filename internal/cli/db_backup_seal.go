package cli

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// sealChunk is how much of a backup file one hash covers.
const sealChunk = 1 << 20

// backupSeal ties a restore to the bytes that were checked. The first
// read of the file (the check, before a person is asked) records a hash
// of every chunk; every later read hands on a chunk only after it matched
// its hash. So a file that is swapped, edited or grown after the check
// stops the restore before any changed byte is used, with no second copy
// of the file in memory or on disk.
type backupSeal struct {
	sums    [][sha256.Size]byte
	head    []byte // the file's first bytes, as stored (before gunzip)
	sealed  bool   // the whole file was read once
	changed bool   // a later read met other bytes
}

// archive: the file is a pg_dump custom archive ("PGDMP").
func (s *backupSeal) archive() bool { return bytes.HasPrefix(s.head, []byte("PGDMP")) }

// sealReader reads a file chunk by chunk, recording the chunk hashes into
// a new seal or checking them against a finished one.
type sealReader struct {
	r      io.Reader
	seal   *backupSeal
	verify bool
	buf    []byte
	off, n int
	chunk  int
	err    error
}

func backupChanged(path string) *out.Error {
	return out.Errf(out.ExitConflict, "FILE_CHANGED",
		"run `komando db restore` again: komando checks the file as it is now, and asks again",
		"%s changed after komando checked it; the changed part was not sent to the database", path)
}

// errSealBroken is what a reader of a changed file gets; withBackup turns
// it into FILE_CHANGED (the seal remembers it in changed).
var errSealBroken = errors.New("the backup file changed after it was checked")

func (s *sealReader) fill() {
	n, err := io.ReadFull(s.r, s.buf)
	last := err == io.EOF || err == io.ErrUnexpectedEOF
	if err != nil && !last {
		s.err = err
		return
	}
	if n > 0 {
		sum := sha256.Sum256(s.buf[:n])
		switch {
		case !s.verify:
			if s.chunk == 0 {
				s.seal.head = append([]byte(nil), s.buf[:min(n, 16)]...)
			}
			s.seal.sums = append(s.seal.sums, sum)
		case s.chunk >= len(s.seal.sums) || s.seal.sums[s.chunk] != sum:
			s.seal.changed, s.err = true, errSealBroken
			return
		}
		s.chunk++
	}
	if last {
		if s.verify && s.chunk != len(s.seal.sums) {
			s.seal.changed, s.err = true, errSealBroken
			return
		}
		s.err = io.EOF
	}
	s.off, s.n = 0, n
}

func (s *sealReader) Read(p []byte) (int, error) {
	for s.off == s.n {
		if s.err != nil {
			return 0, s.err
		}
		s.fill()
		if s.err != nil && s.err != io.EOF {
			return 0, s.err
		}
	}
	n := copy(p, s.buf[s.off:s.n])
	s.off += n
	return n, nil
}

// withBackup opens a backup file (decompressing .gz) and passes it to fn.
// The first call for a seal records it and reads the file to its end; a
// later call checks the file against it and ends with FILE_CHANGED when
// the file is not what was sealed.
func withBackup(cl *call, path string, seal *backupSeal, fn func(io.Reader) error) error {
	if err := guardBackupFile(cl, path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return localFileErr("FILE_NOT_FOUND", err, "")
	}
	defer f.Close()
	sr := &sealReader{r: f, seal: seal, verify: seal.sealed, buf: make([]byte, sealChunk)}
	sr.fill() // the first chunk: seal.head is known before fn asks
	if seal.changed {
		return backupChanged(path)
	}
	if sr.err != nil && sr.err != io.EOF {
		return localFileErr("FILE_NOT_FOUND", sr.err, "")
	}
	var r io.Reader = sr
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(sr)
		if err != nil {
			if seal.changed {
				return backupChanged(path)
			}
			return out.Errf(out.ExitUsage, "BAD_FILE", "the file ends in .gz but is not gzip data", "%v", err)
		}
		defer gz.Close()
		r = gz
	}
	err = fn(r)
	if seal.changed {
		return backupChanged(path)
	}
	if err != nil {
		return err
	}
	if !seal.sealed {
		// what fn left unread (bytes after the gzip stream) is sealed too
		if _, err := io.Copy(io.Discard, sr); err != nil {
			return localFileErr("FILE_NOT_FOUND", err, "")
		}
		seal.sealed = true
	}
	return nil
}

// verifyBackup reads the whole file against its seal.
func verifyBackup(cl *call, path string, seal *backupSeal) error {
	if err := guardBackupFile(cl, path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return localFileErr("FILE_NOT_FOUND", err, "")
	}
	defer f.Close()
	sr := &sealReader{r: f, seal: seal, verify: true, buf: make([]byte, sealChunk)}
	if _, err := io.Copy(io.Discard, sr); err != nil {
		if seal.changed {
			return backupChanged(path)
		}
		return localFileErr("FILE_NOT_FOUND", err, "")
	}
	return nil
}
