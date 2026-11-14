package cli

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/storex"
)

// sudoSftpSide is a folder on a server that sync --sudo writes as root:
// it is listed as the SSH user (SFTP), and each file goes in as `upload
// --sudo` puts one there (writeRemoteSudo): staged in the SSH user's /tmp
// (0600), its path checked by root, never written through a folder
// another user may change (SHARED_FOLDER_CONFLICT), an existing file
// keeping its owner. The mode is the source file's, so the next sync
// sees no change.
type sudoSftpSide struct {
	sftpSide
	c *sshx.Client
}

func (s sudoSftpSide) write(ctx context.Context, rel string, r io.Reader, f syncFile) error {
	if strings.Contains("/"+rel+"/", "/../") {
		return out.Errf(out.ExitRemote, "UNSAFE_PATH", "rename the file so it has no .. in its path", "path %q leads outside %s; nothing outside the folder was written", rel, s.root)
	}
	dst := path.Join(s.root, rel)
	mode := ""
	if f.Mode != 0 {
		mode = fmt.Sprintf("%04o", f.Mode.Perm())
	}
	tmpName := fmt.Sprintf(".komando-sync-%d-%s", time.Now().UnixNano(), path.Base(dst))
	_, err := writeRemoteSudo(s.cl, ctx, s.c, s.sc, dst, mode, tmpName, writeOpts{sudo: true, mkdirs: true}, map[string]any{},
		func(w io.Writer) error { _, err := io.Copy(w, storex.CtxReader(ctx, r)); return err })
	return err
}

func (s sudoSftpSide) remove(ctx context.Context, rel string) error {
	if strings.Contains("/"+rel+"/", "/../") {
		return out.Errf(out.ExitRemote, "UNSAFE_PATH", "rename the file so it has no .. in its path", "path %q leads outside %s; nothing outside the folder was written", rel, s.root)
	}
	p := path.Join(s.root, rel)
	r, err := sshx.Run(ctx, s.c, sshx.RunRequest{Command: "rm -f -- " + sshx.Q(p), Sudo: true, Timeout: time.Minute, MaxOutput: 4096})
	if err != nil {
		return err
	}
	if e := sudoProblem(s.c.Host.Name, r); e != nil {
		return e
	}
	if r.ExitCode != 0 {
		return out.Errf(out.ExitRemote, "WRITE_FAILED", "look at it with `komando fs stat SERVER PATH`", "%s: %s", p, strings.TrimSpace(r.Stderr))
	}
	return nil
}
