package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// installRelease downloads tag's archive for this computer, checks it
// against sums (its release's checksums.txt), and puts its komando where
// exe is. On any failure exe stays as it was.
func installRelease(ctx context.Context, tag, exe string, sums []byte) error {
	archive := archiveName()
	data, err := fetch(ctx, tag, archive, maxArchive, "Downloading komando "+tag)
	if err != nil {
		return err
	}
	if err := checkSum(sums, archive, data); err != nil {
		return err
	}
	bin, err := binaryFromArchive(data)
	if err != nil {
		return out.Errf(out.ExitError, "BAD_RELEASE", "nothing was changed; report it at "+releaseSite+"/issues",
			"%s of komando %s: %v", archive, tag, err)
	}
	return replaceSelf(ctx, exe, bin, tag)
}

// sumFor is name's SHA-256 in checksums.txt (sha256sum format), or "".
func sumFor(sums []byte, name string) string {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// checkSum compares data with its line in checksums.txt.
func checkSum(sums []byte, name string, data []byte) error {
	want := sumFor(sums, name)
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); want == "" || got != want {
		return out.Errf(out.ExitError, "CHECKSUM_MISMATCH", "nothing was changed; try again, and report it at "+releaseSite+"/issues if it happens again",
			"%s does not match checksums.txt of its release", name)
	}
	return nil
}

// binaryFromArchive is the komando file inside a release archive.
func binaryFromArchive(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("it has no komando program")
		}
		if err != nil {
			return nil, err
		}
		if path.Clean(h.Name) != "komando" || h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size > maxBinary {
			return nil, fmt.Errorf("its komando is %d bytes, more than komando accepts", h.Size)
		}
		return io.ReadAll(io.LimitReader(tr, h.Size))
	}
}

// replaceSelf writes bin next to exe, checks that it runs and says it is
// tag, then renames it over exe. A rename is atomic: a komando running now
// keeps the old file, the next one starts the new one, and nobody ever runs
// a half-written program.
func replaceSelf(ctx context.Context, exe string, bin []byte, tag string) error {
	dir := filepath.Dir(exe)
	f, err := os.CreateTemp(dir, ".komando-update-*")
	if err != nil {
		return out.Errf(out.ExitError, "WRITE_FAILED", "nothing was changed; check that you may write to "+dir, "%v", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // gone after the rename; cleans up after a failure
	_, err = f.Write(bin)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o755)
	}
	if err == nil {
		err = ownLikeFolder(tmp, dir)
	}
	if err != nil {
		return out.Errf(out.ExitError, "WRITE_FAILED", "nothing was changed; check the free space and permissions of "+dir, "%v", err)
	}
	if err := tryBinary(ctx, tmp, tag); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return out.Errf(out.ExitError, "WRITE_FAILED", "nothing was changed; check that you may write to "+dir, "%v", err)
	}
	return nil
}

// ownLikeFolder gives the new file the folder's owner when root writes it:
// sudo komando update keeps a komando in someone's ~/.local/bin theirs, and
// one in /usr/local/bin root's (as install.sh does).
func ownLikeFolder(file, dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	uid, gid, ok := fileOwner(fi)
	if !ok {
		return nil
	}
	return os.Chown(file, uid, gid)
}

// tryBinary runs the new program once (--version) before it replaces the
// old one: a file for another computer, or a broken one, stops here.
func tryBinary(parent context.Context, file, tag string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, file, "--version").Output()
	if perr := parent.Err(); perr != nil {
		return perr // Ctrl-C or --timeout: updateErr says which
	}
	if got := strings.TrimSpace(string(b)); err != nil || got != tag {
		why := "it says it is " + strconv.Quote(got)
		if err != nil {
			why = flatText(err.Error())
		}
		return out.Errf(out.ExitError, "BAD_RELEASE", "nothing was changed; report it at "+releaseSite+"/issues",
			"the new komando %s does not run on this computer: %s", tag, why)
	}
	return nil
}
