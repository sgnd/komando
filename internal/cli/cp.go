package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// splitRemote parses "TARGET:/path". Local paths (./x, /x, x) return ok=false.
func splitRemote(s string) (target, p string, ok bool) {
	i := strings.Index(s, ":")
	if i <= 0 {
		return "", s, false
	}
	t := s[:i]
	if strings.ContainsAny(t, "/\\") || strings.HasPrefix(s, ".") {
		return "", s, false
	}
	return t, s[i+1:], true
}

type xferStats struct {
	Host   string     `json:"host"`
	OK     bool       `json:"ok"`
	Files  int        `json:"files"`
	Bytes  int64      `json:"bytes"`
	Dest   string     `json:"dest"`
	SHA256 string     `json:"sha256,omitempty"`
	Error  *out.Error `json:"error,omitempty"`
}

type cpOpts struct {
	recursive, sudo, mkdirs, overwrite bool
	mode                               string
}

func (o *cpOpts) bind(c *cobra.Command) {
	c.Flags().BoolVarP(&o.recursive, "recursive", "r", false, "copy directories recursively")
	c.Flags().BoolVarP(&o.sudo, "sudo", "s", false, "upload: install into place via sudo (single file)")
	c.Flags().BoolVarP(&o.mkdirs, "parents", "p", false, "upload: create parent directories")
	c.Flags().StringVar(&o.mode, "mode", "", "upload: file mode, e.g. 0755")
	c.Flags().BoolVar(&o.overwrite, "overwrite", false, "download: replace files that already exist on this computer")
}

func cpCmd() *cobra.Command {
	var o cpOpts
	c := &cobra.Command{
		Use:   "cp SRC DST",
		Short: "Same as `komando upload`/`download`, written SRC DST with TARGET:PATH",
		Long: `Remote paths are written TARGET:PATH. Uploads accept any target selector
(@group, tag:x, ...) and run in parallel. Downloads from several hosts go to
DST/<host>/... . Single-file transfers report sha256 for verification.`,
		Example: `  komando cp ./app.tar.gz @web:/tmp/app.tar.gz
  komando cp -r ./site web1:/var/www/site --sudo
  komando cp web1:/var/log/nginx/error.log ./logs/
  komando cp @web:/etc/nginx/nginx.conf ./configs/`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcT, srcP, srcRemote := splitRemote(args[0])
			dstT, dstP, dstRemote := splitRemote(args[1])
			switch {
			case srcRemote && dstRemote:
				return out.Usage("remote-to-remote copy is not supported; download then upload")
			case !srcRemote && !dstRemote:
				return out.Usage("one side must be remote (TARGET:PATH)")
			case dstRemote:
				return runCp(cmd.Context(), "cp", dstT, dstP, srcP, true, o)
			}
			return runCp(cmd.Context(), "cp", srcT, srcP, dstP, false, o)
		},
	}
	o.bind(c)
	return c
}

// runCp copies between this computer and the servers target picks, over
// SFTP: local to remote when up is true, else remote to local.
func runCp(ctx context.Context, name, target, remote, local string, up bool, o cpOpts) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	dstRemote := up
	srcP, dstP := local, remote
	if !up {
		srcP, dstP = remote, local
	}
	src, dst := local, target+":"+remote
	if !up {
		src, dst = dst, src
	}
	if dstRemote {
		if err := guard(st, hosts, "", true); err != nil {
			return err
		}
		if _, err := os.Stat(srcP); err != nil {
			return out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "", "local %s: %v", srcP, err)
		}
	}
	if g.dryRun {
		out.P.Print(name, map[string]any{"src": src, "dst": dst, "hosts": hostNames(hosts), "direction": map[bool]string{true: "upload", false: "download"}[dstRemote]}, nil)
		return nil
	}
	res := fanout(ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		sc, err := sftpClient(c)
		if err != nil {
			return nil, err
		}
		defer sc.Close()
		if dstRemote {
			return upload(ctx, c, sc, srcP, dstP, o.recursive, o.sudo, o.mkdirs, o.mode)
		}
		local := dstP
		if len(hosts) > 1 {
			local = filepath.Join(dstP, c.Host.Name) + string(os.PathSeparator)
			if err := os.MkdirAll(local, 0o755); err != nil {
				return nil, err
			}
		}
		return download(sc, srcP, local, o.recursive, o.overwrite)
	})
	data := struct {
		Results []xferStats  `json:"results"`
		Summary fleetSummary `json:"summary"`
	}{}
	worst := 0
	for _, o := range res {
		s := xferStats{Host: o.Host.Name}
		if o.Err != nil {
			s.Error = toErr(o.Err)
			worst = worse(worst, s.Error.Exit)
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, s.Host)
		} else {
			v := o.Value.(xferStats)
			v.Host, v.OK = s.Host, true
			s = v
			data.Summary.OK++
		}
		data.Results = append(data.Results, s)
	}
	data.Summary.Total = len(res)
	audit(st, name, hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"src": src, "dst": dst})
	return finish(name, data, data.Summary, worst)
}

func upload(ctx context.Context, c *sshx.Client, sc *sftp.Client, src, dst string, recursive, sudo, mkdirs bool, mode string) (xferStats, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return xferStats{}, err
	}
	// "dst/" or existing remote dir => put inside it
	if strings.HasSuffix(dst, "/") {
		dst = path.Join(dst, filepath.Base(src))
	} else if rfi, err := sc.Stat(dst); err == nil && rfi.IsDir() {
		dst = path.Join(dst, filepath.Base(src))
	}
	if !fi.IsDir() {
		f, err := os.Open(src)
		if err != nil {
			return xferStats{}, err
		}
		defer f.Close()
		if mode == "" {
			mode = "0" + strings.TrimPrefix(fileModeOctal(fi.Mode()), "0")
		}
		// streamed: a multi-GB backup never sits in memory
		r, err := writeRemoteFrom(ctx, c, sc, dst, f, writeOpts{sudo: sudo, mkdirs: mkdirs, mode: mode})
		if err != nil {
			return xferStats{}, err
		}
		return xferStats{Files: 1, Bytes: r["bytes"].(int64), Dest: dst, SHA256: r["sha256"].(string)}, nil
	}
	if !recursive {
		return xferStats{}, out.Usage("%s is a directory; pass -r", src)
	}
	if sudo {
		return xferStats{}, out.Usage("--sudo is supported for single files only; upload to /tmp then `komando exec --sudo -- mv ...`")
	}
	st := xferStats{Dest: dst}
	err = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		rp := path.Join(dst, filepath.ToSlash(rel))
		if info.IsDir() {
			return sc.MkdirAll(rp)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		o, err := sc.OpenFile(rp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return fsErr(rp, err)
		}
		n, err := io.Copy(o, in)
		o.Close()
		if err != nil {
			return err
		}
		_ = sc.Chmod(rp, info.Mode().Perm())
		st.Files++
		st.Bytes += n
		return nil
	})
	return st, err
}

func fileModeOctal(m os.FileMode) string {
	const digits = "01234567"
	p := uint32(m.Perm())
	return string([]byte{digits[(p>>6)&7], digits[(p>>3)&7], digits[p&7]})
}

// download copies src from the server to dst on this computer. Files that
// already exist stay as they are unless overwrite is set, and every file is
// written to a temporary name first, so an interrupted download never
// leaves half a file behind.
func download(sc *sftp.Client, src, dst string, recursive, overwrite bool) (xferStats, error) {
	fi, err := sc.Stat(src)
	if err != nil {
		return xferStats{}, fsErr(src, err)
	}
	if lfi, err := os.Stat(dst); (err == nil && lfi.IsDir()) || strings.HasSuffix(dst, string(os.PathSeparator)) {
		dst = filepath.Join(dst, path.Base(src))
	}
	if !fi.IsDir() {
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return xferStats{}, err
		}
		n, sum, err := fetchFile(sc, src, dst, fi.Mode().Perm(), overwrite)
		return xferStats{Files: 1, Bytes: n, Dest: dst, SHA256: sum}, err
	}
	if !recursive {
		return xferStats{}, out.Usage("%s is a directory; pass -r", src)
	}
	st := xferStats{Dest: dst}
	w := sc.Walk(src)
	for w.Step() {
		if w.Err() != nil {
			return st, fsErr(w.Path(), w.Err())
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(w.Path(), src), "/")
		if rel != "" && !filepath.IsLocal(filepath.FromSlash(rel)) {
			// names come from the server: never let one point outside dst
			return st, out.Errf(out.ExitRemote, "UNSAFE_PATH", "", "server sent the path %q, which leads outside %s", w.Path(), dst)
		}
		lp := filepath.Join(dst, filepath.FromSlash(rel))
		if w.Stat().IsDir() {
			if err := os.MkdirAll(lp, 0o755); err != nil {
				return st, err
			}
			continue
		}
		if !w.Stat().Mode().IsRegular() {
			continue
		}
		n, _, err := fetchFile(sc, w.Path(), lp, w.Stat().Mode().Perm(), overwrite)
		if err != nil {
			return st, err
		}
		st.Files++
		st.Bytes += n
	}
	return st, nil
}

func fetchFile(sc *sftp.Client, src, dst string, perm os.FileMode, overwrite bool) (int64, string, error) {
	if _, err := os.Lstat(dst); err == nil && !overwrite {
		return 0, "", fileExists(dst)
	}
	in, err := sc.Open(src)
	if err != nil {
		return 0, "", fsErr(src, err)
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".komando-download-*")
	if err != nil {
		return 0, "", err
	}
	defer os.Remove(tmp.Name()) // no-op once it has been moved into place
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), in)
	if err == nil {
		err = tmp.Chmod(perm | 0o200)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, "", err
	}
	if overwrite {
		err = os.Rename(tmp.Name(), dst)
	} else {
		err = placeNew(tmp.Name(), dst)
	}
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// placeNew moves tmp to dst only if dst does not exist yet. A hard link
// fails atomically when dst exists; file systems without hard links fall
// back to a check and a rename.
func placeNew(tmp, dst string) error {
	err := os.Link(tmp, dst)
	if err == nil {
		return nil
	}
	if os.IsExist(err) {
		return fileExists(dst)
	}
	if _, serr := os.Lstat(dst); serr == nil {
		return fileExists(dst)
	}
	return os.Rename(tmp, dst)
}

func fileExists(p string) error {
	return out.Errf(out.ExitConflict, "FILE_EXISTS", "choose another --to, remove the file, or pass --overwrite", "%s already exists on this computer", p)
}
