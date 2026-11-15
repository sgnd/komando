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

// writeProtectedDirs are the folders and files in a home folder an
// agent's command writes nothing into, besides komando's own: ssh's (keys,
// authorized_keys, config); the credential stores and settings of the
// cloud, cluster, git and secret tools; what runs at the next login (shell
// start files, LaunchAgents, systemd user units: one that runs komando
// without the agent's variables would pass every stop for agents); and the
// AI agents' own folders, where komando's guard hooks live.
var writeProtectedDirs = []string{
	".ssh", ".aws", ".config/gcloud", ".azure", ".kube", ".docker", ".gnupg", ".password-store", "Library/Keychains",
	".gitconfig", ".config/git", ".netrc", ".config/gh", ".git-credentials",
	".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile",
	"Library/LaunchAgents", ".config/systemd/user", ".config/autostart",
	".claude", ".codex", ".gemini", ".cursor", ".agents",
}

// dotDotThroughLink is localWriteProtected's reason for a path whose ..
// comes after a link: the system goes up from where the link leads, while
// the text reads as another folder.
const dotDotThroughLink = "a path with .. after a link, which leads elsewhere than it reads; give the folder's real path"

// localWriteProtected says why p, a file or folder on this computer, is no
// place for an agent's command to write, or "". p is read as the system
// reads it: from the working folder when relative, each link followed
// before the next part (a .. after a link is refused), with case folded
// as macOS and Windows fold it, and by identity (os.SameFile) for every
// folder on the way that exists.
func localWriteProtected(cl *call, p string) string {
	raw := p
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			raw = home + string(filepath.Separator) + rest
		}
	}
	if !filepath.IsAbs(raw) {
		wd, err := os.Getwd()
		if err != nil {
			return "a path komando cannot place (" + err.Error() + ")"
		}
		raw = wd + string(filepath.Separator) + raw
	}
	clean := filepath.Clean(raw)
	kernel := kernelPath(raw)
	if hasDotDot(raw) && kernel != realPath(clean) {
		return dotDotThroughLink
	}
	var komandoDirs, otherDirs []string
	komandoDirs = withReal(komandoDirs, store.Home(), cl.getenv("KOMANDO_HOME"))
	for _, home := range guardHomes() {
		komandoDirs = withReal(komandoDirs, filepath.Join(home, ".komando"))
		for _, d := range writeProtectedDirs {
			otherDirs = withReal(otherDirs, filepath.Join(home, filepath.FromSlash(d)))
		}
	}
	otherWhy := func(d string) string {
		return "in " + d + ", which holds keys, credentials, what runs at login or an AI agent's settings"
	}
	in := func(p, d string) bool {
		return pathIn(p, d) || caseFoldFS && pathIn(foldCase(p), foldCase(d))
	}
	cands := withReal([]string{clean}, kernel)
	for _, c := range cands {
		if isProcEnviron(c) {
			return procEnv
		}
		for _, d := range komandoDirs {
			if in(c, d) {
				return komandoData
			}
		}
		for _, d := range otherDirs {
			if in(c, d) {
				return otherWhy(d)
			}
		}
	}
	// by identity: another spelling of a protected folder (another case or
	// Unicode form, a hard link to a file) that names the same one
	ids := func(dirs []string) []os.FileInfo {
		var l []os.FileInfo
		for _, d := range dirs {
			if fi, err := os.Stat(d); err == nil {
				l = append(l, fi)
			}
		}
		return l
	}
	kIDs, oIDs := ids(komandoDirs), ids(otherDirs)
	for dir := kernel; ; dir = filepath.Dir(dir) {
		if fi, err := os.Stat(dir); err == nil {
			for _, k := range kIDs {
				if os.SameFile(fi, k) {
					return komandoData
				}
			}
			for _, o := range oIDs {
				if os.SameFile(fi, o) {
					return otherWhy(dir)
				}
			}
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
	}
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
