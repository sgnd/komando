package cli

import (
	"archive/tar"
	"archive/zip"
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
	"github.com/sgnd/komando/internal/tmpclean"
)

// installRelease downloads tag's archive for this computer, checks it
// against sums (its release's checksums.txt), and puts its komando where
// exe is. On any failure exe stays as it was.
func installRelease(cl *call, ctx context.Context, tag, exe string, sums []byte) error {
	archive := archiveName()
	data, err := fetch(cl, ctx, tag, archive, maxArchive, "Downloading komando "+tag)
	if err != nil {
		return err
	}
	if err := checkSum(sums, archive, data); err != nil {
		return err
	}
	bin, err := binaryFromArchive(data)
	if err != nil {
		return out.Errf(out.ExitError, "BAD_RELEASE", "report it at "+releaseSite+"/issues",
			"%s of komando %s: %v; nothing was changed", archive, tag, err)
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
		return out.Errf(out.ExitError, "CHECKSUM_MISMATCH", "run it again, and report it at "+releaseSite+"/issues if it happens again",
			"%s does not match checksums.txt of its release; nothing was changed", name)
	}
	return nil
}

// binaryFromArchive is the komando file inside a release archive.
func binaryFromArchive(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return binaryFromZip(data)
	}
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

// binaryFromZip is komando.exe inside a Windows release archive.
func binaryFromZip(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if path.Clean(f.Name) != "komando.exe" || !f.Mode().IsRegular() {
			continue
		}
		if f.UncompressedSize64 > maxBinary {
			return nil, fmt.Errorf("its komando.exe is %d bytes, more than komando accepts", f.UncompressedSize64)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, maxBinary+1))
		if err == nil && int64(len(b)) > maxBinary {
			err = fmt.Errorf("its komando.exe is more than %d bytes, more than komando accepts", maxBinary)
		}
		return b, err
	}
	return nil, errors.New("it has no komando.exe program")
}

// replaceSelf writes bin next to exe, checks that it runs and says it is
// tag, then renames it over exe. A rename is atomic: a komando running now
// keeps the old file, the next one starts the new one, and nobody ever runs
// a half-written program.
func replaceSelf(ctx context.Context, exe string, bin []byte, tag string) error {
	dir := filepath.Dir(exe)
	f, err := os.CreateTemp(dir, ".komando-update-*"+exeSuffix)
	if err != nil {
		return out.Errf(out.ExitError, "WRITE_FAILED", "check that you may write to "+dir, "%v; nothing was changed", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // gone after the rename; cleans up after a failure
	defer tmpclean.Add(tmp)()
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
		return out.Errf(out.ExitError, "WRITE_FAILED", "check the free space and permissions of "+dir, "%v; nothing was changed", err)
	}
	if err := tryBinary(ctx, tmp, tag); err != nil {
		return err
	}
	if err := swapExe(tmp, exe); err != nil {
		return out.Errf(out.ExitError, "WRITE_FAILED", "check that you may write to "+dir, "%v; nothing was changed", err)
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

// runVersion runs file --version and gives what it printed. The update
// tests on Windows replace it: a script cannot stand in for a program there.
var runVersion = func(ctx context.Context, file string) ([]byte, error) {
	return exec.CommandContext(ctx, file, "--version").Output()
}

// tryBinary runs the new program once (--version) before it replaces the
// old one: a file for another computer, or a broken one, stops here.
func tryBinary(parent context.Context, file, tag string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	b, err := runVersion(ctx, file)
	if perr := parent.Err(); perr != nil {
		return perr // Ctrl-C or --timeout: updateErr says which
	}
	if got := strings.TrimSpace(string(b)); err != nil || got != tag {
		why := "it says it is " + strconv.Quote(got)
		if err != nil {
			why = flatText(err.Error())
		}
		return out.Errf(out.ExitError, "BAD_RELEASE", "report it at "+releaseSite+"/issues",
			"the new komando %s does not run on this computer: %s; nothing was changed", tag, why)
	}
	return nil
}
