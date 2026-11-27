package cli

import (
	"os"
	"path/filepath"
	"slices"
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
				whole := base == "ditto" || v == "." || v == ".." || strings.HasSuffix(v, "/.") || base == "rsync" && strings.HasSuffix(v, "/") || recursive && (oglobs[k] || wordHasGlob(v))
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
	value := func(i int) string { // --file=X and --directory=X give X
		if _, v, ok := strings.Cut(args[i], "="); ok && strings.HasPrefix(args[i], "--") {
			return v
		}
		return args[i]
	}
	for _, i := range files {
		if d := checkWritten(cl, value(i), globs[i], true, vars, home, cwd); d.Deny {
			return d
		}
	}
	for _, i := range dirs {
		dir, glob := ".", false
		if i >= 0 {
			dir, glob = value(i), globs[i]
			if d := checkWritten(cl, dir, glob, true, vars, home, cwd); d.Deny {
				return d
			}
		}
		vals, known := vars.expand(cl, dir, home, cwd)
		for _, v := range vals {
			p := guardPathAt(cl, v, home, cwd)
			if !known || glob || !filepath.IsAbs(p) {
				return deny("%s writes names it reads from elsewhere into %s, a folder komando's guard cannot know before the line runs; name the folder on the line", base, dir)
			}
			if touchesProtected(cl, p, home) {
				return deny("%s writes names it reads from elsewhere into %s, which is or holds komando's data, private keys or guard files; use a project folder instead", base, p)
			}
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
			files = nil
		}
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
		if gitReadsOnly(args) {
			return nil, nil
		}
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "-C" && i+1 < len(args):
				i++
				dirs = append(dirs, i)
			case a == "-c" || a == "--git-dir" || a == "--work-tree" || a == "--namespace":
				i++
			case a == "clone":
				var ops []int
				for j := i + 1; j < len(args); j++ {
					if !strings.HasPrefix(args[j], "-") {
						ops = append(ops, j)
					}
				}
				if len(ops) > 1 {
					dirs = append(dirs, ops[len(ops)-1])
				}
				return nil, dirs
			case !strings.HasPrefix(a, "-"):
				return nil, dirs
			}
		}
	}
	return files, dirs
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
