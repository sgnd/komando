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
		tarball := &capBuffer{max: maxPodCopy}
		var errb bytes.Buffer
		rpath = path.Clean(rpath) // "/data/" is /data, "/x/.." is /
		dir, base := path.Dir(rpath), path.Base(rpath)
		err := r.k.Exec(r.ctx, kube.ExecOptions{Namespace: r.ns(), Pod: pod, Container: c, Command: []string{"tar", "cf", "-", "-C", dir, base}, Stdout: tarball, Stderr: &errb})
		if tarball.over {
			return kstop(out.Errf(out.ExitConflict, "FILE_TOO_LARGE",
				"copy a smaller part, or pack it smaller in the pod first: `komando cluster run TARGET --write -- exec POD -- gzip PATH`",
				"%s:%s is more than %s; komando holds a copy from a pod in memory, and stopped", pod, rpath, humanBytes(maxPodCopy)))
		}
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

// maxPodCopy is the most a copy from a pod brings: the tar stream is held
// in memory (untarTo checks every name before it writes any), so a pod
// must not be able to fill this computer's memory.
const maxPodCopy = 512 << 20

// capBuffer is a bytes.Buffer that takes at most max bytes: past that it
// stops the copy (the writer's error ends the stream) and says so.
type capBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.over = true
		return 0, errors.New("too large")
	}
	return b.Buffer.Write(p)
}

// untarTo writes the tar stream (made by tar in the container, so the
// container picks every name in it) under dst; base is the copied name, so
// a single file can land at dst itself. Every entry must be base or lie
// under it, and land inside dst: one that does not is refused before
// anything is written, as is one inside a .git folder. Links and devices
// are skipped, like kubectl cp; a file gets the tar's mode without setuid,
// setgid or world-write. For an AI agent a file copies as an SFTP download
// does (fetchMasked): a file that is a secret by name is refused, a text
// file is masked before it is written, and a binary or larger one that
// holds a vault value is refused; all of it before anything is written.
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
		mode   os.FileMode
		data   []byte
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
		e := entry{target: target, dir: h.Typeflag == tar.TypeDir, mode: os.FileMode(h.Mode)}
		if !e.dir {
			if err := guardSensitiveCopy(h.Name); err != nil {
				var stop *out.Error
				errors.As(err, &stop)
				return kstop(stop)
			}
			if e.data, err = io.ReadAll(tr); err != nil {
				return kfail("%v", err)
			}
			if e.data, err = podFileMasked(h.Name, e.data); err != nil {
				return err
			}
		}
		plan = append(plan, e)
	}
	for _, e := range plan {
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
			mode := e.mode&0o755 | 0o600 // as kubectl cp: never setuid, setgid or world-writable
			f, err := os.OpenFile(e.target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return kfail("%v", err)
			}
			if err := f.Chmod(mode); err != nil { // a file already there keeps no mode of its own
				f.Close()
				return kfail("%v", err)
			}
			_, err = f.Write(e.data)
			f.Close()
			if err != nil {
				return kfail("%v", err)
			}
		}
	}
	return nil
}

// podFileMasked is a file from a pod as an AI agent may have it on this
// computer (fetchMasked's rule): a text file komando reads whole with its
// secret values [hidden]; a binary or larger one as it is, unless it holds
// a vault value. People and scripts, and --reveal, get it as it is.
func podFileMasked(name string, b []byte) ([]byte, error) {
	if !out.P.Mask || revealOK() {
		return b, nil
	}
	if len(b) <= hiddenScanMax && bytes.IndexByte(b, 0) < 0 {
		return []byte(out.P.Redact(string(b))), nil
	}
	sc := out.P.NewValueScanner()
	_, _ = sc.Write(b)
	if sc.Found() {
		return nil, kstop(out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
			revealHint("it is binary or larger than komando reads whole, so its secrets cannot be shown as [hidden]; if the user wants the real file on this computer, re-run with --reveal"),
			"%s holds a value from komando's vault; komando does not copy it to this computer for an AI agent", name))
	}
	return b, nil
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
