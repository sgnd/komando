package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// find changes files three ways: -delete removes what it finds; -exec,
// -execdir, -ok and -okdir run a command with {} for each file it finds;
// and -fprint, -fprint0, -fprintf and -fls write the file they name.

// checkFind checks what find ARGS (globs are theirs) changes. The command
// of -exec and the others is checked as a shell line one level deeper. Its
// {} is a file under the start folders: known when every start folder is
// known and holds nothing an agent may not change (findStarts), unknown
// otherwise, and -delete is refused where it is unknown. -execdir and
// -okdir run in the found file's folder, so a relative name in their
// command is unknown too.
func checkFind(cl *call, args []string, globs []bool, vars lineVars, home, cwd string, depth int) guardDecision {
	i, follows := 0, false
	var starts []string
	var sglobs []bool
opts:
	for ; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-H" || a == "-L":
			follows = true // links lead out of the start folders
		case a == "-P" || a == "-E" || a == "-X" || a == "-d" || a == "-s" || a == "-x" || strings.HasPrefix(a, "-O"):
		case a == "-D" && i+1 < len(args):
			i++
		case a == "-f" && i+1 < len(args): // BSD: a start folder
			i++
			starts, sglobs = append(starts, args[i]), append(sglobs, globs[i])
		default:
			break opts
		}
	}
	for ; i < len(args) && !strings.HasPrefix(args[i], "-") && !strings.ContainsAny(args[i][:min(1, len(args[i]))], "()!,"); i++ {
		starts, sglobs = append(starts, args[i]), append(sglobs, globs[i])
	}
	if len(starts) == 0 {
		starts, sglobs = []string{"."}, []bool{false}
	}
	expr, eglobs := args[i:], globs[i:]
	first, safe := findStarts(cl, starts, sglobs, vars, home, cwd)
	safe = safe && !follows && !slices.ContainsFunc(expr, func(w string) bool { return w == "-follow" || w == "-files0-from" })
	name := unknownOutput
	if safe {
		name = filepath.Join(first, "{}")
	}
	for j := 0; j < len(expr); j++ {
		switch e := expr[j]; e {
		case "-delete":
			if !safe {
				return deny("find -delete removes files under %s, which komando's guard cannot tell apart from komando's data, keys or guard files; delete the files by name", strings.Join(starts, " "))
			}
		case "-fprint", "-fprint0", "-fprintf", "-fls":
			if j+1 < len(expr) {
				if d := checkWritten(cl, expr[j+1], eglobs[j+1], true, vars, home, cwd); d.Deny {
					return d
				}
			}
		case "-exec", "-execdir", "-ok", "-okdir":
			k := j + 1
			for k < len(expr) && expr[k] != ";" && !(expr[k] == "+" && expr[k-1] == "{}") {
				k++
			}
			if k > j+1 {
				if depth >= guardDepth {
					return tooDeep()
				}
				icwd := cwd
				if e == "-execdir" || e == "-okdir" {
					icwd = lostDir
				}
				if d := checkShellIn(cl, findCommandLine(expr[j+1:k], name), home, icwd, depth+1, vars); d.Deny {
					return d
				}
			}
			j = k
		}
	}
	return allow()
}

// findCommandLine is the command of find's -exec WORDS as a shell line:
// each word in "...", where a $ is still read as a variable as the line had
// it, with name in place of each {}.
func findCommandLine(words []string, name string) string {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`")
	var b strings.Builder
	for i, w := range words {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(`"` + esc.Replace(strings.ReplaceAll(w, "{}", name)) + `"`)
	}
	return b.String()
}

// findStarts says whether every start folder of find is known and holds
// nothing an agent may not change: it is not in and does not hold a folder
// secretPath guards, an AI agent's settings folder or a komando program the
// guard hook runs. It gives the first as a full path.
func findStarts(cl *call, starts []string, globs []bool, vars lineVars, home, cwd string) (string, bool) {
	first := ""
	for i, s := range starts {
		vals, known := vars.expand(cl, s, home, cwd)
		if globs[i] || !known {
			return "", false
		}
		for _, v := range vals {
			p := guardPathAt(cl, v, home, cwd)
			if !filepath.IsAbs(p) {
				return "", false // the working folder is not known
			}
			for _, x := range []string{p, realPath(p)} {
				if secretPath(cl, x, home) != "" || holdsProtected(cl, x, home) || holdsGuardFiles(x, home) {
					return "", false
				}
			}
			if first == "" {
				first = p
			}
		}
	}
	return first, first != ""
}

// holdsGuardFiles says whether the folder p is in or holds an AI agent's
// settings folder (the home folder's, or one right in p), or holds a
// komando program the guard hook runs.
func holdsGuardFiles(p, home string) bool {
	fold := func(s string) string {
		if caseFoldFS {
			return foldCase(s)
		}
		return s
	}
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		for dir := range hookSettingFiles {
			if fold(part) == fold(dir) {
				return true
			}
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
