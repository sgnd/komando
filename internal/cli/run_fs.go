package cli

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/sftp"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// remoteHome is the login user's home folder (where SFTP starts).
func remoteHome(sc *sftp.Client) string {
	if h, err := sc.Getwd(); err == nil && h != "" {
		return h
	}
	if h, err := sc.RealPath("."); err == nil {
		return h
	}
	return "."
}

// expandRemote reads a remote path the way scp does: "" and "~" are the
// home folder, "~/x" is x in it.
func expandRemote(sc *sftp.Client, p string) string {
	switch {
	case p == "" || p == "~":
		return remoteHome(sc)
	case strings.HasPrefix(p, "~/"):
		return path.Join(remoteHome(sc), p[2:])
	}
	return p
}

// rq quotes a remote path for the shell, leaving a leading ~ to it.
func rq(p string) string {
	switch {
	case p == "~" || p == "":
		return `"$HOME"`
	case strings.HasPrefix(p, "~/"):
		return `"$HOME"/` + sshx.Q(p[2:])
	}
	return sshx.Q(p)
}

func rqAll(ps []string) string {
	q := make([]string, len(ps))
	for i, p := range ps {
		q[i] = rq(p)
	}
	return strings.Join(q, " ")
}

// oneServer is singleHost with a hint that fits the command when the
// target picks several servers.
func oneServer(st *store.State, target, manyHint string) (*store.Host, error) {
	hs, err := resolveTargets(st, target)
	if err != nil {
		return nil, err
	}
	if len(hs) != 1 {
		return nil, out.Errf(out.ExitUsage, "USAGE", manyHint, "target %q matched %d servers; this command works on one", target, len(hs))
	}
	return hs[0], nil
}

// --- fs ls -------------------------------------------------------------------

type lsResult struct {
	Path      string     `json:"path"`
	Count     int        `json:"count"`
	Truncated bool       `json:"truncated"`
	Entries   []fileInfo `json:"entries"`
	recursive bool
}

// Text is ls -l: MODE SIZE MODIFIED NAME, by name, "-> target" for links.
func (r lsResult) Text() string {
	es := append([]fileInfo(nil), r.Entries...)
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
	rows := make([][]string, 0, len(es))
	for _, e := range es {
		name := e.Name
		if r.recursive {
			name = strings.TrimPrefix(strings.TrimPrefix(e.Path, r.Path), "/")
		}
		if e.Type == "dir" {
			name += "/"
		}
		if e.Link != "" {
			name += " -> " + e.Link
		}
		size := humanBytes(e.Size)
		if e.Type == "dir" {
			size = "-"
		}
		rows = append(rows, []string{lsMode(e), size, e.ModTime.Local().Format("2006-01-02 15:04"), name})
	}
	if len(rows) == 0 {
		return "(empty folder)\n"
	}
	s := textTable([]string{"mode", "size", "modified", "name"}, rows)
	if r.Truncated {
		s += fmt.Sprintf("(showing the first %d; raise --max)\n", len(rows))
	}
	return s
}

func lsMode(e fileInfo) string {
	t := "-"
	switch e.Type {
	case "dir":
		t = "d"
	case "symlink":
		t = "l"
	case "other":
		t = "?"
	}
	m, err := strconv.ParseUint(e.Mode, 8, 32)
	if err != nil {
		return t + "?????????"
	}
	return t + os.FileMode(m).Perm().String()[1:]
}

// --- fs write / replace ------------------------------------------------------

// fsChange is the result of fs write and fs replace: JSON as before, and a
// sentence plus the diff for a person.
type fsChange map[string]any

func (r fsChange) Text() string {
	var b strings.Builder
	p := fmt.Sprint(r["path"])
	if f, ok := r["followed"]; ok {
		p += " (a link; wrote its target " + fmt.Sprint(f) + ")"
	}
	_, isReplace := r["replacements"]
	switch {
	case r["would_change"] == false || r["changed"] == false:
		b.WriteString("no change: " + p + " already has this content\n")
		if n, ok := r["note"]; ok {
			b.WriteString(fmt.Sprint(n) + "\n")
		}
	case g.dryRun:
		if r["exists"] == false {
			b.WriteString("would create " + p + "\n")
		} else if isReplace {
			fmt.Fprintf(&b, "would replace %v match(es) in %s\n", r["replacements"], p)
		} else {
			b.WriteString("would write " + p + "\n")
		}
	case isReplace:
		fmt.Fprintf(&b, "replaced %v match(es) in %s\n", r["replacements"], p)
	default:
		size := ""
		if n, ok := r["bytes"].(int64); ok {
			size = humanBytes(n) + ", "
		}
		fmt.Fprintf(&b, "wrote %s (%smode %v)\n", p, size, r["mode"])
	}
	if bk, ok := r["backup"]; ok {
		b.WriteString("backup: " + fmt.Sprint(bk) + "\n")
	}
	if d, ok := r["diff"].(string); ok && d != "" {
		b.WriteString(d)
	}
	if s, ok := r["diff_skipped"]; ok {
		b.WriteString("(no diff: " + fmt.Sprint(s) + ")\n")
	}
	return b.String()
}

// resolveLink follows a symlink chain to the file it names (which may not
// exist yet), so a write changes the target and keeps the link.
func resolveLink(sc *sftp.Client, p string) (string, error) {
	cur := p
	for i := 0; i < 40; i++ {
		fi, err := sc.Lstat(cur)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			return cur, nil
		}
		t, err := sc.ReadLink(cur)
		if err != nil {
			return "", fsErr(cur, err)
		}
		if !path.IsAbs(t) {
			t = path.Join(path.Dir(cur), t)
		}
		cur = path.Clean(t)
	}
	return "", out.Errf(out.ExitConflict, "SYMLINK_LOOP", "a link points back to itself; look at it with `komando fs stat TARGET PATH`", "%s: too many levels of symbolic links", p)
}

func folderMissing(dir string) error {
	return out.Errf(out.ExitNotFound, "FOLDER_NOT_FOUND", "add -p/--parents to create it", "folder %s does not exist", dir)
}

func isASymlink(p string) error {
	return out.Errf(out.ExitConflict, "IS_A_SYMLINK", "drop --no-follow to write the file it points to", "%s is a symbolic link (--no-follow)", p)
}

// --- rm, mkdir, mv, chmod ----------------------------------------------------

// Exit codes the fs shell scripts use to say what went wrong.
const (
	fsExitIsFolder   = 81
	fsExitNotFolder  = 82
	fsExitNoSource   = 83
	fsExitDestExists = 84
)

// fsExitMap turns those exit codes into typed errors.
func fsExitMap(code int, stderr string) *out.Error {
	msg := strings.TrimSpace(stderr)
	switch code {
	case fsExitIsFolder:
		return out.Errf(out.ExitUsage, "IS_A_DIRECTORY", "add --recursive (-r) to remove a folder and everything in it", "%s", msg)
	case fsExitNotFolder:
		return out.Errf(out.ExitConflict, "NOT_A_FOLDER", "pick another name, or remove the file first", "%s", msg)
	case fsExitNoSource:
		return out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "check the path with `komando fs ls`", "%s", msg)
	case fsExitDestExists:
		return out.Errf(out.ExitConflict, "FILE_EXISTS", "add --overwrite to replace it", "%s", msg)
	}
	if strings.Contains(msg, "Permission denied") || strings.Contains(msg, "Operation not permitted") {
		return out.Errf(out.ExitRemote, "PERMISSION_DENIED", "retry with --sudo", "%s", msg)
	}
	return nil
}

// say prints a fixed message from a script.
func say(s string) string { return "printf '%s\\n' " + sshx.Q(s) }

// fail prints a message on stderr and exits with code.
func failWith(code int, msg string) string {
	return "{ " + say(msg) + " >&2; exit " + strconv.Itoa(code) + "; }"
}

func hasGlob(p string) bool { return strings.ContainsAny(p, "*?[") }

// rmScript removes paths. A missing one is reported, not an error (rm -f);
// a folder needs recursive. All checks run before anything is removed.
func rmScript(paths []string, recursive bool) string {
	var b strings.Builder
	if !recursive {
		for _, p := range paths {
			b.WriteString("if [ -d " + rq(p) + " ] && [ ! -L " + rq(p) + " ]; then " + failWith(fsExitIsFolder, p+" is a folder") + "; fi; ")
		}
	}
	flags := "-f"
	if recursive {
		flags = "-rf"
	}
	b.WriteString("st=0; ")
	for _, p := range paths {
		missing := "not found: " + p + " (nothing removed)"
		if hasGlob(p) {
			missing = "no file named '" + p + "' (globs are not expanded; use `komando exec` for patterns)"
		}
		b.WriteString("if [ -e " + rq(p) + " ] || [ -L " + rq(p) + " ]; then rm " + flags + " -- " + rq(p) + " && " + say("removed: "+p) + " || st=1; else " + say(missing) + "; fi; ")
	}
	b.WriteString("exit $st")
	return b.String()
}

func mkdirScript(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		b.WriteString("if [ -e " + rq(p) + " ] && [ ! -d " + rq(p) + " ]; then " + failWith(fsExitNotFolder, p+" exists and is not a folder") + "; fi; ")
	}
	b.WriteString("mkdir -p -- " + rqAll(paths))
	return b.String()
}

// mvScript moves src to dst like mv, but never replaces a file unless
// overwrite: into an existing folder it moves to folder/name.
func mvScript(src, dst string, overwrite bool) string {
	var b strings.Builder
	b.WriteString("s=" + rq(src) + "; t=" + rq(dst) + "; ")
	b.WriteString(`if [ ! -e "$s" ] && [ ! -L "$s" ]; then ` + failWith(fsExitNoSource, src+": no such file or directory") + "; fi; ")
	b.WriteString(`if [ -d "$t" ] && [ ! -L "$t" ]; then t="$t/$(basename -- "$s")"; fi; `)
	if overwrite {
		b.WriteString(`if [ -e "$t" ] || [ -L "$t" ]; then printf 'replaced: %s\n' "$t"; fi; `)
	} else {
		b.WriteString(`if [ -e "$t" ] || [ -L "$t" ]; then printf '%s already exists\n' "$t" >&2; exit ` + strconv.Itoa(fsExitDestExists) + "; fi; ")
	}
	b.WriteString(`mv -- "$s" "$t" && printf 'moved to: %s\n' "$t"`)
	return b.String()
}

func chmodScript(mode string, paths []string, recursive bool) string {
	var b strings.Builder
	for _, p := range paths {
		b.WriteString("if [ ! -e " + rq(p) + " ]; then " + failWith(fsExitNoSource, p+": no such file or directory") + "; fi; ")
	}
	r := ""
	if recursive {
		r = "-R "
	}
	b.WriteString("chmod " + r + sshx.Q(mode) + " -- " + rqAll(paths))
	return b.String()
}

// validMode accepts 644, 0755, u+x, go-w, a=r,u+w.
func validMode(m string) bool {
	if m == "" {
		return false
	}
	if _, err := strconv.ParseUint(m, 8, 32); err == nil {
		return len(m) <= 4
	}
	for _, part := range strings.Split(m, ",") {
		i := 0
		for i < len(part) && strings.ContainsRune("ugoa", rune(part[i])) {
			i++
		}
		if i >= len(part) || !strings.ContainsRune("+-=", rune(part[i])) {
			return false
		}
		for _, c := range part[i+1:] {
			if !strings.ContainsRune("rwxXstugo+-=", c) {
				return false
			}
		}
	}
	return true
}
