package cli

import (
	"archive/tar"
	"bytes"
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
		if strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || !strings.Contains(s, ":") {
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
		var tarball bytes.Buffer
		var errb bytes.Buffer
		rpath = path.Clean(rpath) // "/data/" is /data, "/x/.." is /
		dir, base := path.Dir(rpath), path.Base(rpath)
		err := r.k.Exec(r.ctx, kube.ExecOptions{Namespace: r.ns(), Pod: pod, Container: c, Command: []string{"tar", "cf", "-", "-C", dir, base}, Stdout: &tarball, Stderr: &errb})
		if err != nil {
			return kfail("%s %s", strings.TrimSpace(errb.String()), err)
		}
		return untarTo(tarball.Bytes(), dst, base)
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
			f, err := os.OpenFile(e.target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return kfail("%v", err)
			}
			if err := f.Chmod(mode); err != nil { // a file already there keeps no mode of its own
				f.Close()
				return kfail("%v", err)
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return kfail("%v", err)
			}
		}
	}
	return nil
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
