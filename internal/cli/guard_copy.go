package cli

import (
	"os"
	"path/filepath"
	"strings"
)

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
		// a relative target of ln -s leads from the link's folder
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
	if dest == "" {
		return allow()
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
				whole := v == "." || v == ".." || strings.HasSuffix(v, "/.") || base == "rsync" && strings.HasSuffix(v, "/") || recursive && (oglobs[k] || wordHasGlob(v))
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
