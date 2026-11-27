package cli

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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

// mkdirLocal makes the folder dir on this computer, with the folders
// above it, after guardLocalWrite.
func mkdirLocal(cl *call, dir string) error {
	if err := guardLocalWrite(cl, dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, 0o755)
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

// cp, mv, install and rsync write in their destination folder a file the
// line does not name: DEST/NAME for each source, or, for a source that
// names a folder's contents (src/., ., rsync's src/, or a glob copied
// whole), any name in DEST. ln -s makes a path that leads where its target
// does.

// checkCopyInto refuses cp, mv, install, rsync, ln or link ARGS (values of
// a line with vars, read from cwd) when what they write in their
// destination is, or holds, a protected file or a guard file
// (touchesProtected), or when ln links to a folder that holds one.
func checkCopyInto(cl *call, base string, args []string, globs []bool, vars lineVars, home, cwd string) guardDecision {
	var ops []string
	var oglobs []bool
	dest, intoDir, recursive := "", false, base == "mv"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			ops, oglobs = append(ops, args[i+1:]...), append(oglobs, globs[i+1:]...)
			i = len(args)
		case a == "--target-directory":
			if i+1 < len(args) {
				i++
				dest, intoDir = args[i], true
			}
		case strings.HasPrefix(a, "--target-directory="):
			dest, intoDir = strings.TrimPrefix(a, "--target-directory="), true
		case a == "--recursive" || a == "--archive":
			recursive = true
		case base == "rsync" && len(a) > 1 && a[0] == '-' && a[1] != '-':
			recursive = recursive || strings.ContainsAny(a[1:], "ra")
		case len(a) > 1 && a[0] == '-' && a[1] != '-':
			// a cluster of short options: -a, -rf, -t DIR, -atDIR, install's -m MODE
			for k := 1; k < len(a); k++ {
				c := a[k]
				recursive = recursive || base == "cp" && strings.IndexByte("rRa", c) >= 0
				if c != 't' && !(c == 'S' || base == "install" && strings.IndexByte("mog", c) >= 0) {
					continue
				}
				val := a[k+1:]
				if val == "" && i+1 < len(args) {
					i++
					val = args[i]
				}
				if c == 't' {
					dest, intoDir = val, true
				}
				break
			}
		case strings.HasPrefix(a, "-"):
		default:
			ops, oglobs = append(ops, a), append(oglobs, globs[i])
		}
	}
	if dest == "" && len(ops) > 1 {
		dest, ops, oglobs = ops[len(ops)-1], ops[:len(ops)-1], oglobs[:len(oglobs)-1]
	}
	dvals, _ := vars.expand(cl, dest, home, cwd)
	if base == "ln" || base == "link" {
		return checkLinkTargets(cl, ops, dvals, vars, home, cwd)
	}
	if dest == "" {
		return allow()
	}
	if _, known := vars.expand(cl, dest, home, cwd); !known {
		return checkCopyIntoUnknown(cl, base, ops, oglobs, recursive, dest, vars, home, cwd)
	}
	for _, d := range dvals {
		dp := guardPathAt(cl, d, home, cwd)
		if !filepath.IsAbs(dp) {
			continue // checkWritten refuses a relative name after a lost cd
		}
		if fi, err := os.Stat(dp); err == nil && fi.IsDir() || strings.HasSuffix(d, "/") {
			intoDir = true
		}
		for k, s := range ops {
			svals, _ := vars.expand(cl, s, home, cwd)
			for _, v := range svals {
				t := filepath.Join(dp, filepath.Base(v))
				whole := wholeCopy(base, v, recursive, oglobs[k])
				if !intoDir || whole {
					t = dp // the source becomes dest, or its names land in dest
				}
				if why := secretWord(cl, t, home, cwd, oglobs[k] && !whole); why != "" {
					return deny("%s writes %s, which is %s. komando keeps it away from AI agents; ask the user if you need something from it%s", base, t, why, viaKomando(why))
				}
				if (recursive || whole) && touchesProtected(cl, t, home) || guardSelfWhy(t) != "" {
					return deny("%s writes into %s, which is or holds komando's data, private keys or guard files; copy into a project folder instead", base, t)
				}
			}
		}
	}
	return allow()
}

// wholeCopy says whether base copies what the source v holds rather than
// v itself: ditto always, a folder's contents (src/., ., .., rsync's src/),
// or a glob copied recursively.
func wholeCopy(base, v string, recursive, glob bool) bool {
	return base == "ditto" || v == "." || v == ".." || strings.HasSuffix(v, "/.") || base == "rsync" && strings.HasSuffix(v, "/") ||
		recursive && (glob || wordHasGlob(v))
}

// checkLinkTargets refuses ln or link OPS when a target is or holds a
// protected path or a guard file. A relative target of ln -s leads from
// the link's folder (dvals are the link's values).
func checkLinkTargets(cl *call, ops, dvals []string, vars lineVars, home, cwd string) guardDecision {
	from := []string{cwd}
	for _, d := range dvals {
		if dp := guardPathAt(cl, d, home, cwd); d != "" && filepath.IsAbs(dp) {
			from = append(from, dp, filepath.Dir(dp))
		}
	}
	for _, s := range ops {
		vals, _ := vars.expand(cl, s, home, cwd)
		for _, v := range vals {
			for _, f := range from {
				if p := guardPathAt(cl, v, home, f); filepath.IsAbs(p) && touchesProtected(cl, p, home) {
					return deny("%s is or holds komando's data, private keys or guard files; a link to it would let a later write reach them. Link a project folder instead", s)
				}
			}
		}
	}
	return allow()
}

// checkCopyIntoUnknown is checkCopyInto for a destination the guard cannot
// know, whose fixed last name checkWritten let through. If it is a folder,
// what lands in it is each source's own name, or for a whole copy every
// name the source holds: refused when that is not on the line or is a
// protected name.
func checkCopyIntoUnknown(cl *call, base string, ops []string, oglobs []bool, recursive bool, dest string, vars lineVars, home, cwd string) guardDecision {
	for k, s := range ops {
		svals, _ := vars.expand(cl, s, home, cwd)
		for _, v := range svals {
			if wholeCopy(base, v, recursive, oglobs[k]) || protectedName(cl, filepath.Base(v), home) {
				return deny("%s copies %s into %s, a folder komando's guard cannot know before the line runs, and the names that land there are not all on the line or are komando's, a key's or an agent's; copy into a full path", base, s, dest)
			}
		}
	}
	return allow()
}

// touchesProtected says whether the path p is or holds a folder secretPath
// guards, a file it guards, an AI agent's settings folder or a komando
// program the guard hook runs, seen as named and through its links.
func touchesProtected(cl *call, p, home string) bool {
	for _, q := range []string{filepath.Clean(p), realPath(p)} {
		if secretPath(cl, q, home) != "" || holdsProtected(cl, q, home) || holdsGuardFiles(q, home) || guardSelfWhy(q) != "" {
			return true
		}
		for _, d := range protectedDirs(cl, home) {
			if q == d || caseFoldFS && foldCase(q) == foldCase(d) {
				return true
			}
		}
	}
	return false
}

// holdsGuardFiles says whether the folder p is an AI agent's settings
// folder or the worktrees folder in it (Claude Code's .claude/worktrees,
// whose worktrees hold their own), holds one (the home folder's, or one
// right in p), or holds a komando program the guard hook runs. A folder
// deeper in a project's agent folder (.claude/skills/x, a worktree's
// files) holds none of its hook settings.
func holdsGuardFiles(p, home string) bool {
	fold := func(s string) string {
		if caseFoldFS {
			return foldCase(s)
		}
		return s
	}
	parts := strings.Split(strings.TrimRight(filepath.ToSlash(p), "/"), "/")
	last := parts[len(parts)-1]
	if fold(last) == "worktrees" && len(parts) > 1 {
		last = parts[len(parts)-2]
	}
	for dir := range hookSettingFiles {
		if fold(last) == fold(dir) {
			return true
		}
	}
	for dir := range hookSettingFiles {
		if pathIn(fold(filepath.Join(home, dir)), fold(p)) {
			return true
		}
		if _, err := os.Lstat(filepath.Join(p, dir)); err == nil {
			return true
		}
	}
	for _, prog := range guardPrograms() {
		if pathIn(fold(prog), fold(p)) {
			return true
		}
	}
	return false
}

// checkPartWriters checks the programs that write only some of their
// arguments, or names the line does not write out into a folder: perl and
// ruby -i the files after the script, sqlite3 its database, tar (create,
// append) its archive, and tar, unzip and cpio (extract) and git (-C,
// clone) any name in their folder. A folder that receives names the line
// does not write out may not be, or hold, a protected file or a guard file.
func checkPartWriters(cl *call, base string, args []string, globs []bool, vars lineVars, home, cwd string) guardDecision {
	files, dirs := partWrites(base, args)
	if slices.Contains(files, -2) || slices.Contains(dirs, -2) {
		return deny("%s takes its file or folder in a cluster of options here, which komando's guard does not read; give it as its own word (tar -f FILE -C DIR)", base)
	}
	cwds, here := []string{cwd}, "the working folder"
	if base == "git" && slices.Contains(args, "-C") {
		cwds, here = gitFolders(cl, args, vars, home, cwd), "the -C folder"
	}
	value := func(i int) string { // --file=X and --directory=X give X
		if _, v, ok := strings.Cut(args[i], "="); ok && strings.HasPrefix(args[i], "--") {
			return v
		}
		return args[i]
	}
	at := func(cwd string) guardDecision {
		for _, i := range files {
			if d := checkWritten(cl, value(i), globs[i], true, vars, home, cwd); d.Deny {
				return d
			}
		}
		for _, i := range dirs {
			dir, glob, shown := ".", false, here
			if i >= 0 {
				dir, glob = value(i), globs[i]
				shown = dir
				if d := checkWritten(cl, dir, glob, true, vars, home, cwd); d.Deny {
					return d
				}
			}
			vals, known := vars.expand(cl, dir, home, cwd)
			for _, v := range vals {
				p := guardPathAt(cl, v, home, cwd)
				if !known || glob || !filepath.IsAbs(p) {
					return deny("%s writes names it reads from elsewhere into %s, a folder komando's guard cannot know before the line runs; name the folder on the line", base, shown)
				}
				if touchesProtected(cl, p, home) {
					return deny("%s writes names it reads from elsewhere into %s, which is or holds komando's data, private keys or guard files; use a project folder instead", base, p)
				}
			}
		}
		return allow()
	}
	for _, c := range cwds {
		if d := at(c); d.Deny {
			return d
		}
	}
	return allow()
}

// partWrites gives, for base ARGS, the indexes of the arguments it writes
// as files, and of the folders it writes other names into (-1 for the
// working folder).
func partWrites(base string, args []string) (files, dirs []int) {
	switch base {
	case "perl", "ruby":
		return inPlaceFiles(base, args), nil
	case "sqlite3":
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "-cmd" || a == "-init" || a == "-separator" || a == "-newline" || a == "-nullvalue" || a == "-mmap" || a == "-vfs" || a == "-maxsize":
				i++
			case !strings.HasPrefix(a, "-"):
				return []int{i}, nil
			}
		}
	case "tar", "bsdtar", "gtar":
		return tarWrites(args)
	case "unzip":
		dir := -1
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "-l" || a == "-v" || a == "-t" || a == "-Z" || a == "-p" || a == "-z":
				return nil, nil // lists, tests or prints
			case a == "-d" && i+1 < len(args):
				i++
				dir = i
			}
		}
		return nil, []int{dir}
	case "cpio":
		dir, extract := -1, false
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "-D" || a == "--directory":
				if i+1 < len(args) {
					i++
					dir = i
				}
			case a == "-p" || a == "--pass-through":
				extract = true
				if j := len(args) - 1; j > i && !strings.HasPrefix(args[j], "-") {
					dir = j
				}
			case a == "--extract" || len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a, 'i'):
				extract = true
			}
		}
		if extract {
			return nil, []int{dir}
		}
	case "git":
		return gitWrites(args)
	}
	return files, dirs
}

// gitDotGitOnly are the git commands besides gitReadOnlyCommands that
// write no file outside .git: their own output options are checked as any
// program's (checkOutputOptions). Every other command, an alias among them,
// may change the files of the worktree.
var gitDotGitOnly = map[string]bool{"fetch": true, "push": true, "add": true, "commit": true, "gc": true, "prune": true,
	"repack": true, "pack-refs": true, "notes": true, "update-ref": true, "symbolic-ref": true, "maintenance": true,
	"fsck": true, "count-objects": true, "hash-object": true, "update-index": true, "check-ignore": true, "check-attr": true,
	"merge-tree": true, "cherry": true, "name-rev": true, "var": true, "range-diff": true, "whatchanged": true,
	"show-branch": true, "verify-commit": true, "verify-tag": true, "archive": true, "format-patch": true, "config": true}

// gitWrites is partWrites for git, its relative names read from the -C
// folder (gitFolder): the worktree (-1 for the -C folder, or --work-tree)
// of a command that may change its files, --git-dir for any command that
// is not only a reader, the path worktree add, move and remove write, the
// repository clone makes, and the file config --file and bundle create
// write. Without -C or --work-tree the working folder's worktree is not
// counted.
func gitWrites(args []string) (files, dirs []int) {
	var tree []int
	i := 0
	for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
		switch a := args[i]; {
		case a == "-C" && i+1 < len(args):
			i++
			if len(tree) == 0 {
				tree = append(tree, -1)
			}
		case (a == "--work-tree" || a == "--git-dir") && i+1 < len(args):
			i++
			if a == "--git-dir" {
				dirs = append(dirs, i)
			} else {
				tree = append(tree, i)
			}
		case strings.HasPrefix(a, "--git-dir="):
			dirs = append(dirs, i)
		case strings.HasPrefix(a, "--work-tree="):
			tree = append(tree, i)
		case a == "-c" || a == "--namespace":
			i++
		}
	}
	if i == len(args) || gitReadOnlyCommands[args[i]] {
		return nil, nil
	}
	sub, rest, at := args[i], args[i+1:], i+1
	ops := func(values string) (idx []int) { // operands, skipping the values of the options in values
		for j := 0; j < len(rest); j++ {
			switch a := rest[j]; {
			case strings.Contains(" "+values+" ", " "+a+" "):
				j++
			case !strings.HasPrefix(a, "-"):
				idx = append(idx, at+j)
			}
		}
		return idx
	}
	switch {
	case sub == "clone":
		if o := ops("-o --origin -b --branch -u --upload-pack --reference --separate-git-dir --depth -c --config"); len(o) > 1 {
			dirs = append(dirs, o[len(o)-1])
		}
	case sub == "worktree" && len(rest) > 0 && (rest[0] == "add" || rest[0] == "move" || rest[0] == "remove"):
		o := ops("-b -B --reason")
		if rest[0] == "add" && len(o) > 2 {
			o = o[:2] // add PATH COMMIT: the commit is no path
		}
		dirs = append(dirs, o[1:]...)
	case sub == "config":
		for j, a := range rest {
			if (a == "-f" || a == "--file") && j+1 < len(rest) {
				files = append(files, at+j+1)
			} else if strings.HasPrefix(a, "--file=") {
				files = append(files, at+j)
			}
		}
	case sub == "bundle":
		if o := ops(""); len(o) > 1 && args[o[0]] == "create" {
			files = append(files, o[1])
		}
	case sub == "reset" && !slices.ContainsFunc(rest, func(a string) bool { return a == "--hard" || a == "--merge" || a == "--keep" }):
	case sub == "stash" && len(rest) > 0 && slices.Contains([]string{"list", "show", "drop", "clear", "create", "store"}, rest[0]):
	case gitDotGitOnly[sub], sub == "worktree", sub == "bundle":
	default:
		dirs = append(dirs, tree...)
	}
	return files, dirs
}

// gitFolders are the folders git's -C words lead to from cwd, one for each
// value they may have (git -C "$repo" in a loop): lostDir when one is not
// known.
func gitFolders(cl *call, args []string, vars lineVars, home, cwd string) []string {
	dirs := []string{cwd}
	for i := 0; i+1 < len(args) && strings.HasPrefix(args[i], "-"); i++ {
		switch args[i] {
		case "-C":
			vals, known := vars.expand(cl, args[i+1], home, cwd)
			var next []string
			for _, d := range dirs {
				for _, v := range vals {
					if !known || wordHasGlob(v) || d == lostDir && !filepath.IsAbs(guardPath(cl, v, home)) {
						return []string{lostDir}
					}
					next = append(next, guardPathAt(cl, v, home, d))
				}
			}
			if len(next) == 0 || len(next) > maxValues {
				return []string{lostDir}
			}
			dirs = next
			i++
		case "-c", "--namespace", "--work-tree", "--git-dir":
			i++
		}
	}
	return dirs
}

// inPlaceFiles are the indexes of the files perl or ruby -i ARGS edit in
// place: the arguments after the script; none without -i.
func inPlaceFiles(base string, args []string) (files []int) {
	// letters whose value is the rest of the cluster or the next word
	values, scripts := "MmIx0lCdD", "eE"
	if base == "ruby" {
		values, scripts = "IrCEFKTWx0l", "e"
	}
	inPlace, script := false, false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' && a[1] != '-' {
			for k := 1; k < len(a); k++ {
				if a[k] == 'i' {
					inPlace = true
					break // the rest is the backup suffix
				}
				if strings.IndexByte(values, a[k]) >= 0 {
					if k == len(a)-1 && strings.IndexByte("MmIrx", a[k]) >= 0 {
						i++
					}
					break
				}
				if strings.IndexByte(scripts, a[k]) >= 0 {
					script = true
					if k == len(a)-1 {
						i++
					}
					break
				}
			}
			continue
		}
		if !script {
			script = true // the script file
			continue
		}
		files = append(files, i)
	}
	if !inPlace {
		return nil
	}
	return files
}

// tarWrites is partWrites for tar: the archive it creates, appends to or
// updates (-f), and the folder it extracts into (-C, --directory, or the
// working folder). Options come bundled (xzf), in clusters (-xzf) or long.
func tarWrites(args []string) (files, dirs []int) {
	mode, file, dir := "", -1, -1
	next := 0 // the next argument a value letter takes
	for i := 0; i < len(args); i++ {
		if i < next {
			continue
		}
		a := args[i]
		name, _, eq := strings.Cut(a, "=")
		switch {
		case a == "--extract" || a == "--get":
			mode += "x"
		case a == "--create" || a == "--append" || a == "--update":
			mode += "c"
		case name == "--file" || name == "--directory":
			v := i
			if !eq && i+1 < len(args) {
				v, next = i+1, i+2
			}
			if name == "--file" {
				file = v
			} else {
				dir = v
			}
		case strings.HasPrefix(a, "--"):
		case i == 0 && !strings.HasPrefix(a, "-") || len(a) > 1 && a[0] == '-':
			// letters; f, C, b, T and X take the next arguments in turn, or
			// the rest of a -cluster
			letters, n := strings.TrimPrefix(a, "-"), max(i+1, next)
			for k := 0; k < len(letters); k++ {
				c := letters[k]
				switch c {
				case 'x':
					mode += "x"
				case 'c', 'r', 'u':
					mode += "c"
				}
				if !strings.ContainsRune("fCbTX", rune(c)) {
					continue
				}
				v := n
				if a[0] == '-' && k+1 < len(letters) {
					v = -2 // the value is the rest of the cluster
				} else {
					n++
				}
				if c == 'f' {
					file = v
				}
				if c == 'C' {
					dir = v
				}
				if v == -2 {
					break
				}
			}
			next = n
		}
	}
	if strings.Contains(mode, "c") && (file == -2 || file >= 0 && file < len(args) && args[file] != "-") {
		files = append(files, file)
	}
	if strings.Contains(mode, "x") {
		if dir >= len(args) {
			dir = -1
		}
		dirs = append(dirs, dir)
	}
	return files, dirs
}
