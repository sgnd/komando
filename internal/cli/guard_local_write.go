package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/tmpclean"
)

// An AI agent's command that saves a file on this computer (download, cp,
// sync, storage download, db dump --to, export --to, cluster cp) never
// writes into komando's own folder, ssh's folder or the cloud and cluster
// tools' credentials: a download over ~/.komando/store.db destroys the
// vault, inventory and audit log; one into ~/.ssh adds an authorized key.
// Every writer checks its destination with guardLocalWrite, through links,
// first and again just before the file is put in place.

// writeProtectedDirs are the folders in a home folder an agent's command
// writes nothing into, besides komando's own: ssh's (keys,
// authorized_keys, config) and the credential stores and configuration of
// the cloud, cluster and secret tools.
var writeProtectedDirs = []string{".ssh", ".aws", ".config/gcloud", ".azure", ".kube", ".docker", ".gnupg", ".password-store", "Library/Keychains"}

// localWriteProtected says why p, a file or folder on this computer, is no
// place for an agent's command to write, or "". p is made absolute and its
// links are followed (also those of a folder above a file not there yet).
func localWriteProtected(cl *call, p string) string {
	abs, err := filepath.Abs(expandHome(p))
	if err != nil {
		abs = filepath.Clean(p)
	}
	var komandoDirs, otherDirs []string
	komandoDirs = withReal(komandoDirs, store.Home(), cl.getenv("KOMANDO_HOME"))
	for _, home := range guardHomes() {
		komandoDirs = withReal(komandoDirs, filepath.Join(home, ".komando"))
		for _, d := range writeProtectedDirs {
			otherDirs = withReal(otherDirs, filepath.Join(home, filepath.FromSlash(d)))
		}
	}
	in := func(p, d string) bool {
		return pathIn(p, d) || caseFoldFS && pathIn(strings.ToLower(p), strings.ToLower(d))
	}
	for _, p := range withReal(nil, abs) {
		if isProcEnviron(p) {
			return procEnv
		}
		for _, d := range komandoDirs {
			if in(p, d) {
				return komandoData
			}
		}
		for _, d := range otherDirs {
			if in(p, d) {
				return "in " + d + ", which holds keys, credentials or the settings that say what to trust"
			}
		}
	}
	return ""
}

// withReal adds each non-empty path to l, and the path its links lead to
// when that is another one.
func withReal(l []string, paths ...string) []string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		l = append(l, p)
		if r := realPath(p); r != p {
			l = append(l, r)
		}
	}
	return l
}

// guardLocalWrite stops an AI agent's command from writing p on this
// computer when p is in a protected folder (localWriteProtected). No flag
// clears it: a person runs such a command in their own terminal.
func guardLocalWrite(cl *call, p string) error {
	if p == "" || p == "-" || !cl.isAgent() {
		return nil
	}
	why := localWriteProtected(cl, p)
	if why == "" {
		return nil
	}
	return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
		"save it in another folder (the project folder, /tmp), or ask the user to run the command in their own terminal",
		"%s is %s; komando does not write there for an AI agent", p, why).NoFlag()
}

// guardDownload stops an AI agent's download of a file that is secret by
// its name (guardSensitiveCopy) or to a protected place here
// (guardLocalWrite), before anything is fetched.
func guardDownload(cl *call, remote, local string) error {
	if err := guardSensitiveCopy(cl, remote); err != nil {
		return err
	}
	return guardLocalWrite(cl, local)
}

// writeAtomic lets fill write a temp file inside a private (0700) folder
// next to path, then links it into place, so path appears complete or not
// at all, and an existing file is never overwritten. For an AI agent the
// destination is checked first and again before the link (guardLocalWrite).
func writeAtomic(cl *call, path string, fill func(tmp string) error) error {
	if err := guardLocalWrite(cl, path); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(path), ".komando-*")
	if err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder exists and is writable", "%v", err)
	}
	defer os.RemoveAll(dir)
	defer tmpclean.Add(dir)()
	tmp := filepath.Join(dir, "data")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	if err := fill(tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := guardLocalWrite(cl, path); err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick a new file name; existing files are never overwritten", "%s already exists", path)
		}
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder is writable and has free space", "%v", err)
	}
	return nil
}
