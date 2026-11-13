package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

// cp copies between this computer and a pod with tar in the container,
// as kubectl cp does (the container needs tar).
func (r *kctlRun) cp() error {
	if len(r.a.pos) != 2 {
		return kfail("cp needs SRC DST, one of them POD:PATH")
	}
	src, dst := r.a.pos[0], r.a.pos[1]
	podOf := func(s string) (string, string, bool) {
		// C:\data on Windows is a path here, as kubectl cp takes it, not pod C
		if strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || !strings.Contains(s, ":") || filepath.VolumeName(s) != "" {
			return "", "", false
		}
		p, path, _ := strings.Cut(s, ":")
		if _, after, ok := strings.Cut(p, "/"); ok { // NAMESPACE/POD
			p = after
		}
		return p, path, true
	}
	c := r.a.val("container")
	if pod, rpath, ok := podOf(src); ok {
		rpath = path.Clean(rpath) // "/data/" is /data, "/x/.." is /
		if err := sensitiveCopyOK(rpath); err != nil {
			return err // a file named like a secret, before anything is read (download does the same)
		}
		var errb bytes.Buffer
		tarball := &capWriter{max: podCopyMax} // a pod cannot fill this computer's memory
		dir, base := path.Dir(rpath), path.Base(rpath)
		err := r.k.Exec(r.ctx, kube.ExecOptions{Namespace: r.ns(), Pod: pod, Container: c, Command: []string{"tar", "cf", "-", "-C", dir, base}, Stdout: tarball, Stderr: &errb})
		if tarball.capped {
			return kstop(out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "copy less at a time (one file or a smaller folder), or pack it in the pod first and copy that",
				"%s is larger than %s, the most a copy from a pod reads", rpath, humanBytes(podCopyMax)))
		}
		if err != nil {
			return kfail("%s %s", strings.TrimSpace(errb.String()), err)
		}
		return untarTo(tarball.buf.Bytes(), dst, base)
	}
	if pod, rpath, ok := podOf(dst); ok {
		var tarball bytes.Buffer
		if err := tarFrom(src, path.Base(rpath), &tarball); err != nil {
			return kwrap(err)
		}
		var errb bytes.Buffer
		err := r.k.Exec(r.ctx, kube.ExecOptions{Namespace: r.ns(), Pod: pod, Container: c, Command: []string{"tar", "xf", "-", "-C", path.Dir(rpath)},
			Stdin: &tarball, Stderr: &errb})
		if err != nil {
			return kfail("%s %s", strings.TrimSpace(errb.String()), err)
		}
		return nil
	}
	return kfail("one of SRC or DST must be POD:PATH")
}

// untarTo writes the tar stream (made by tar in the container, so the
// container picks every name in it) under dst; base is the copied name, so
// a single file can land at dst itself. Every entry must be base or lie
// under it, and land inside dst: one that does not is refused before
// anything is written, as is one inside a .git folder. Links and devices
// are skipped, like kubectl cp; a file gets the tar's mode without setuid,
// setgid or world-write.
func untarTo(tarball []byte, dst, base string) error {
	root, err := filepath.Abs(dst)
	if err != nil {
		return kfail("%v", err)
	}
	dstIsDir := false
	if fi, err := os.Stat(root); err == nil && fi.IsDir() {
		dstIsDir = true
	}
	type entry struct {
		target string
		dir    bool
	}
	var plan []entry
	tr := tar.NewReader(bytes.NewReader(tarball))
	for first := true; ; first = false {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return kfail("%v", err)
		}
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg {
			plan = append(plan, entry{}) // skipped, but keeps the count for pass two
			continue
		}
		if h.Typeflag == tar.TypeReg && guardSensitiveCopy(h.Name) != nil {
			out.P.Skip(out.Skipped{Name: h.Name, Kind: "file", Reason: "holds secrets; an AI agent needs --reveal, which the user allows, to copy it here"})
			plan = append(plan, entry{})
			continue
		}
		rel, ok := tarRel(h.Name, base)
		target := filepath.Join(root, filepath.FromSlash(rel))
		if ok && rel == "" && h.Typeflag == tar.TypeReg && first && dstIsDir {
			target = filepath.Join(root, base) // one file into a folder: keep its name
		}
		r, err := filepath.Rel(root, target)
		if !ok || err != nil || r != "." && !filepath.IsLocal(r) {
			return kfail("refusing %q: it would land outside %s", h.Name, dst)
		}
		if gitPath(r) { // git refuses to check out .git too: its config and hooks run commands
			return kfail("refusing %q: komando does not write into a .git folder", h.Name)
		}
		if link := symlinkOn(root, r); link != "" { // a link already there could lead out
			return kfail("refusing %q: %s is a symbolic link", h.Name, link)
		}
		plan = append(plan, entry{target: target, dir: h.Typeflag == tar.TypeDir})
	}
	tr = tar.NewReader(bytes.NewReader(tarball))
	for _, e := range plan {
		h, err := tr.Next()
		if err != nil {
			return kfail("%v", err)
		}
		switch {
		case e.target == "":
		case e.dir:
			if err := os.MkdirAll(e.target, 0o755); err != nil {
				return kfail("%v", err)
			}
		default:
			if err := os.MkdirAll(filepath.Dir(e.target), 0o755); err != nil {
				return kfail("%v", err)
			}
			mode := os.FileMode(h.Mode)&0o755 | 0o600 // as kubectl cp: never setuid, setgid or world-writable
			if err := writePodFile(tr, e.target, mode); err != nil {
				return kwrap(err)
			}
		}
	}
	return nil
}

// podCopyMax caps a copy from a pod, which is read through memory.
const podCopyMax = 512 << 20

// sensitiveCopyOK is guardSensitiveCopy with kctl's error shape.
func sensitiveCopyOK(p string) error {
	var stop *out.Error
	if err := guardSensitiveCopy(p); errors.As(err, &stop) {
		return kstop(stop)
	} else if err != nil {
		return err
	}
	return nil
}

// writePodFile saves one file of a copy from a pod as target, through a
// temporary file next to it, so a stopped copy leaves no half file. For an
// AI agent it is saved as download saves it (fetchMasked): a text file
// with secret values as [hidden], and a file that holds a vault value and
// cannot be masked is refused (SENSITIVE_FILE), nothing of it kept.
func writePodFile(r io.Reader, target string, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".komando-cp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once it has been moved into place
	if out.P.Mask && !revealOK() {
		_, _, err = fetchMasked(context.Background(), r, tmp, io.Discard, nil)
	} else {
		_, err = io.Copy(tmp, r)
	}
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		var stop *out.Error
		if errors.As(err, &stop) {
			return kstop(stop)
		}
		return err
	}
	return os.Rename(tmp.Name(), target)
}

// gitPath: rel has a .git part (any case: macOS and Windows ignore it).
func gitPath(rel string) bool {
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if strings.EqualFold(part, ".git") {
			return true
		}
	}
	return false
}

// localReadOK stops kctl from reading, for an AI agent, a file of this
// computer that it would send to the cluster (-f, --from-file, cp to a
// pod), where `get` would hand it back in full. It is guardLocalRead
// (komando's own folder always; a secret file unless the person allows
// --reveal) with kctl's error shape.
func localReadOK(p string) error {
	var stop *out.Error
	if err := guardLocalRead(p); errors.As(err, &stop) {
		return kstop(stop)
	} else if err != nil {
		return err
	}
	return nil
}

// symlinkOn is the first symbolic link on the way from root down to rel
// (root itself is the user's choice), or "".
func symlinkOn(root, rel string) string {
	if rel == "." {
		return ""
	}
	p := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		p = filepath.Join(p, part)
		fi, err := os.Lstat(p)
		if err != nil {
			return "" // not there yet: nothing below it is either
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return p
		}
	}
	return ""
}

// tarRel is where a tar entry goes, relative to the destination: "" for
// base itself, the rest of the name for what lies under base. ok is false
// for a name outside base or one that climbs out (.., an absolute path).
func tarRel(name, base string) (string, bool) {
	clean := path.Clean(name)
	var rel string
	switch {
	case base == "." || base == "/": // the whole folder was copied
		rel = strings.TrimPrefix(clean, "/")
		if rel == "." {
			rel = ""
		}
	case clean == base:
		rel = ""
	case strings.HasPrefix(clean, base+"/"):
		rel = clean[len(base)+1:]
	default:
		return "", false
	}
	return rel, rel == "" || filepath.IsLocal(filepath.FromSlash(rel))
}

func tarFrom(src, name string, w io.Writer) error {
	tw := tar.NewWriter(w)
	src = filepath.Clean(expandHome(src))
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = path.Join(name, filepath.ToSlash(rel))
		if rel == "." {
			h.Name = name
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			if err := localReadOK(p); err != nil {
				return err
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}
