package cli

import (
	"regexp"
	"slices"
	"strings"
)

func findWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		switch a {
		case "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls":
			return "find " + a
		}
	}
	return ""
}

// sedWrite: sed -i edits files, and a sed program can run commands (e,
// s///e) and write files (w, W, s///w); a program from a file (-f) is not
// seen at all.
func sedWrite(cmd string, args []string, _ bool) string {
	var progs []string
	given := false // the program came with -e
	for k := 0; k < len(args); k++ {
		a := args[k]
		switch {
		case a == "--":
			if !given && k+1 < len(args) {
				progs = append(progs, args[k+1])
			}
			k = len(args)
		case strings.HasPrefix(a, "--in-place"):
			return cmd + " -i"
		case a == "--expression" || strings.HasPrefix(a, "--expression="):
			given = true
			if v, ok := strings.CutPrefix(a, "--expression="); ok {
				progs = append(progs, v)
			} else if k+1 < len(args) {
				progs = append(progs, args[k+1])
				k++
			}
		case a == "--file" || strings.HasPrefix(a, "--file="):
			return cmd + " -f"
		case a == "--line-length":
			k++
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'i':
					return cmd + " -i"
				case 'f':
					return cmd + " -f"
				case 'e':
					given = true
					if j+1 < len(a) {
						progs = append(progs, a[j+1:])
					} else if k+1 < len(args) {
						progs = append(progs, args[k+1])
						k++
					}
					j = len(a)
				case 'l':
					if j+1 == len(a) {
						k++
					}
					j = len(a)
				}
			}
		default:
			if !given {
				progs = append(progs, a) // the program; the rest are files
				given = true
			}
		}
	}
	for _, p := range progs {
		if sedProgramWrites(p) {
			return cmd + " running commands or writing files (e, w)"
		}
	}
	return ""
}

// sedProgramWrites reads a sed program closely enough to find its e, w
// and W commands and the e and w flags of s///.
func sedProgramWrites(p string) bool {
	n := len(p)
	i := 0
	skip := func() { // a regex or s/// part, from its opening delimiter
		if i >= n {
			return
		}
		d := p[i]
		i++
		for i < n && p[i] != d {
			if p[i] == '\\' {
				i++
			}
			i++
		}
		i++
	}
	for i < n {
		switch c := p[i]; {
		case c == '/':
			skip()
		case c == '\\' && i+1 < n: // \%regex%
			i++
			skip()
		case c == 'e' || c == 'w' || c == 'W':
			return true
		case (c == 's' || c == 'y') && i+1 < n:
			i++
			skip()
			i = min(i, n) - 1 // the closing delimiter of the first part opens the second
			skip()
			for i < n && strings.IndexByte(";}\n", p[i]) < 0 {
				if c == 's' && (p[i] == 'w' || p[i] == 'e') {
					return true
				}
				i++
			}
		case c == 'a' || c == 'i' || c == 'c' || c == 'r' || c == 'R' || c == '#':
			for i < n && p[i] != '\n' { // text or a file name, to the line end
				i++
			}
		case c == 'b' || c == 't' || c == 'T' || c == ':':
			for i < n && p[i] != ';' && p[i] != '\n' { // a label
				i++
			}
		default:
			i++
		}
	}
	return false
}

// awkWrite: an awk program can run commands (system, | "cmd") and write
// files (print > "file"); a program from a file (-f) is not seen at all,
// and neither is a function called by name (gawk @f()).
func awkWrite(cmd string, args []string, _ bool) string {
	var progs []string
	given := false
	for k := 0; k < len(args); k++ {
		a := args[k]
		switch {
		case a == "--":
			if !given && k+1 < len(args) {
				progs = append(progs, args[k+1])
			}
			k = len(args)
		case a == "-f" || strings.HasPrefix(a, "-f") || strings.HasPrefix(a, "--file") || a == "-E" || strings.HasPrefix(a, "--exec") ||
			a == "-i" || strings.HasPrefix(a, "--include") || a == "-l" || strings.HasPrefix(a, "--load") || strings.HasPrefix(a, "-We") || a == "-W" && k+1 < len(args) && strings.HasPrefix(args[k+1], "e"):
			return cmd + " " + a
		case a == "-F" || a == "-v" || a == "-W" || a == "--assign" || a == "--field-separator":
			k++
		case a == "-e" || a == "--source":
			given = true
			if k+1 < len(args) {
				progs = append(progs, args[k+1])
			}
			k++
		case strings.HasPrefix(a, "--source="):
			given = true
			progs = append(progs, strings.TrimPrefix(a, "--source="))
		case strings.HasPrefix(a, "-e"):
			given = true
			progs = append(progs, a[2:])
		case strings.HasPrefix(a, "-") && a != "-":
		default: // the program; the rest are files
			if !given {
				progs = append(progs, a)
			}
			k = len(args)
		}
	}
	for _, p := range progs {
		if awkProgramWrites.MatchString(awkPlain(p)) {
			return cmd + " running commands or writing files"
		}
	}
	return ""
}

// awkProgramWrites: system(), a pipe to or from a command (| or |&), a
// file written with > or >>, and gawk's call by name (@f) or @include.
var awkProgramWrites = regexp.MustCompile(`\bsystem\s*\(|(^|[^|])\|($|[^|])|>>|>\s*["$(a-zA-Z_]|@[A-Za-z_]`)

// awkPlain empties the strings and /regex/ literals of an awk program, so
// that /ERROR|WARN/ or "a > b" is not read as a pipe or a redirect.
func awkPlain(p string) string {
	var b strings.Builder
	prev := byte(0) // the last character that was not a space
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '"' || c == '/' && (prev == 0 || strings.IndexByte("(,~!{};&|?:\n", prev) >= 0):
			b.WriteByte(c)
			for i++; i < len(p) && p[i] != c; i++ {
				if p[i] == '\\' {
					i++
				}
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
		if c != ' ' && c != '\t' {
			prev = c
		}
	}
	return b.String()
}

func isStdout(v string) bool {
	return v == "-" || v == "/dev/null" || v == "/dev/stdout" || v == "/dev/stderr"
}

// tarWrite: only listing (-t), comparing (-d) and creating an archive on
// standard output are read-only; extracting, appending and options that
// run a program (--to-command, --checkpoint-action, -I) are not.
func tarWrite(cmd string, args []string, _ bool) string {
	mode, archive := "", ""
	takes := "bCfgHIKLNTVX" // short options with a value
	letter := func(l byte, value func() string) string {
		switch {
		case strings.IndexByte("Arux", l) >= 0:
			return "tar -" + string(l)
		case l == 'I' || l == 'g':
			return "tar -" + string(l)
		case l == 'c' || l == 't' || l == 'd':
			mode = string(l)
		}
		if strings.IndexByte(takes, l) >= 0 {
			v := value()
			if l == 'f' {
				archive = v
			}
		}
		return ""
	}
	for k := 0; k < len(args); k++ {
		a := args[k]
		next := func() string {
			if k+1 < len(args) {
				k++
				return args[k]
			}
			return ""
		}
		switch {
		case k == 0 && a != "" && a[0] != '-': // old style: tar xzf FILE
			for j := 0; j < len(a); j++ {
				if w := letter(a[j], next); w != "" {
					return w
				}
			}
		case strings.HasPrefix(a, "--"):
			name, val, has := strings.Cut(a, "=")
			switch name {
			case "--extract", "--get", "--append", "--update", "--catenate", "--concatenate", "--delete",
				"--to-command", "--checkpoint-action", "--use-compress-program", "--info-script", "--new-volume-script",
				"--rsh-command", "--rmt-command", "--index-file", "--remove-files", "--listed-incremental", "--volno-file":
				return "tar " + name
			case "--list":
				mode = "t"
			case "--diff", "--compare":
				mode = "d"
			case "--create":
				mode = "c"
			case "--file":
				if !has {
					val = next()
				}
				archive = val
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				l := a[j]
				rest := a[j+1:]
				if w := letter(l, func() string {
					if rest != "" {
						return rest
					}
					return next()
				}); w != "" {
					return w
				}
				if strings.IndexByte(takes, l) >= 0 {
					break
				}
			}
		}
	}
	if mode == "c" && archive != "" && !isStdout(archive) {
		return "tar -c writing " + archive
	}
	return ""
}

// curlWrite: curl saves files (-o FILE, -O, -c jar) and sends data or a
// changing request (-d, -F, -T, -X POST); -K reads options komando does
// not see. Output to standard output or /dev/null is fine.
func curlWrite(cmd string, args []string, _ bool) string {
	getish := func(m string) bool {
		m = strings.ToUpper(m)
		return m == "GET" || m == "HEAD" || m == "OPTIONS"
	}
	for k := 0; k < len(args); k++ {
		a := args[k]
		next := func() string {
			if k+1 < len(args) {
				k++
				return args[k]
			}
			return ""
		}
		if strings.HasPrefix(a, "--") {
			name, val, has := strings.Cut(a, "=")
			switch name {
			case "--output", "--dump-header", "--trace", "--trace-ascii", "--stderr", "--libcurl", "--cookie-jar",
				"--etag-save", "--hsts", "--alt-svc", "--output-dir":
				if !has {
					val = next()
				}
				if !isStdout(val) || name == "--output-dir" {
					return "curl " + name + " " + val
				}
			case "--remote-name", "--remote-name-all", "--remote-header-name", "--upload-file", "--config", "--create-dirs",
				"--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--form", "--form-string", "--json", "--quote":
				return "curl " + name
			case "--request":
				if !has {
					val = next()
				}
				if !getish(val) {
					return "curl " + name + " " + val
				}
			}
			continue
		}
		if !strings.HasPrefix(a, "-") || len(a) < 2 {
			continue
		}
		for j := 1; j < len(a); j++ {
			l := a[j]
			if strings.IndexByte("OTKJdFQ", l) >= 0 {
				return "curl -" + string(l)
			}
			if strings.IndexByte("AbCcDdEeFHKmoPQrTtUuwXxYyz", l) < 0 {
				continue
			}
			v := a[j+1:]
			if v == "" {
				v = next()
			}
			if (l == 'o' || l == 'D' || l == 'c') && !isStdout(v) || l == 'X' && !getish(v) {
				return "curl -" + string(l) + " " + v
			}
			break
		}
	}
	return ""
}

// wgetWrite: wget saves what it gets unless it goes to standard output
// (-O -) or nothing is fetched (--spider).
func wgetWrite(cmd string, args []string, _ bool) string {
	safe := false
	for k := 0; k < len(args); k++ {
		a := args[k]
		next := func() string {
			if k+1 < len(args) {
				k++
				return args[k]
			}
			return ""
		}
		if strings.HasPrefix(a, "--") {
			name, val, has := strings.Cut(a, "=")
			switch name {
			case "--output-document", "--output-file", "--append-output":
				if !has {
					val = next()
				}
				if !isStdout(val) {
					return "wget " + name + " " + val
				}
				safe = safe || name == "--output-document"
			case "--spider":
				safe = true
			case "--post-data", "--post-file", "--method", "--body-data", "--body-file", "--recursive", "--mirror", "--execute":
				return "wget " + name
			}
			continue
		}
		if !strings.HasPrefix(a, "-") || len(a) < 2 {
			continue
		}
		for j := 1; j < len(a); j++ {
			l := a[j]
			if l == 'e' || l == 'r' || l == 'm' {
				return "wget -" + string(l)
			}
			if strings.IndexByte("OoaiBPUtTlADRIXwQ", l) < 0 {
				continue
			}
			v := a[j+1:]
			if v == "" {
				v = next()
			}
			if l == 'O' || l == 'o' || l == 'a' {
				if !isStdout(v) {
					return "wget -" + string(l) + " " + v
				}
				safe = safe || l == 'O'
			}
			break
		}
	}
	if !safe {
		return "wget saving a file"
	}
	return ""
}

// compressWrite: gzip FILE replaces the file; -c (to standard output), -l
// and -t only read, and so does compressing a pipe.
func compressWrite(cmd string, args []string, _ bool) string {
	files, reads := 0, false
	for _, a := range args {
		switch {
		case a == "--stdout" || a == "--to-stdout" || a == "--list" || a == "--test":
			reads = true
		case strings.HasPrefix(a, "--"), a == "-":
		case strings.HasPrefix(a, "-"):
			reads = reads || strings.ContainsAny(a[1:], "clt")
		default:
			files++
		}
	}
	if files > 0 && !reads {
		return cmd + " replacing files"
	}
	return ""
}

// unzipWrite: only listing, testing and printing (-l -t -v -p -c -z -Z)
// leave the files alone.
func unzipWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsAny(a[1:], "ltvpczZ") {
			return ""
		}
	}
	return "unzip"
}

func patchWrite(cmd string, args []string, _ bool) string {
	if slices.Contains(args, "--dry-run") {
		return ""
	}
	return "patch"
}

// crontabWrite: only crontab -l (and -u USER -l) reads; crontab FILE and
// crontab with nothing install a new table.
func crontabWrite(cmd string, args []string, _ bool) string {
	list := false
	for k := 0; k < len(args); k++ {
		switch a := args[k]; a {
		case "-u":
			k++
		case "-l":
			list = true
		default:
			return "crontab " + a
		}
	}
	if !list {
		return "crontab reading a new table from its input"
	}
	return ""
}

func hashWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && strings.Contains(a, "p") {
			return "hash -p" // runs another program under a known name
		}
	}
	return ""
}

// gitWrites are git subcommands that change the repository, the work tree
// or a remote, or run a program.
var gitWrites = map[string]bool{"commit": true, "push": true, "pull": true, "reset": true, "checkout": true, "clean": true,
	"merge": true, "rebase": true, "fetch": true, "clone": true, "init": true, "rm": true, "mv": true, "add": true,
	"apply": true, "am": true, "cherry-pick": true, "revert": true, "restore": true, "switch": true, "worktree": true,
	"submodule": true, "gc": true, "prune": true, "update-ref": true, "notes": true, "replace": true, "filter-branch": true,
	"update-index": true, "repack": true, "bisect": true, "fast-import": true, "maintenance": true, "sparse-checkout": true,
	"lfs": true, "symbolic-ref": true, "pack-refs": true, "read-tree": true, "checkout-index": true, "commit-tree": true,
	"write-tree": true, "mktag": true, "mktree": true, "credential": true, "send-email": true, "daemon": true,
	"instaweb": true, "difftool": true, "mergetool": true, "hook": true, "bundle": true, "format-patch": true, "svn": true,
	"p4": true, "imap-send": true, "http-push": true, "upload-pack": true, "receive-pack": true, "shell": true, "archive": true}

// gitWrite: git -c sets config for one run (an alias, a pager or a hook
// that runs anything), so it is never read-only; the global options that
// take a value (-C DIR) are not the subcommand.
func gitWrite(cmd string, args []string, _ bool) string {
	k := 0
	for ; k < len(args); k++ {
		a := args[k]
		switch {
		case a == "-c" || strings.HasPrefix(a, "-c") || strings.HasPrefix(a, "--config-env"):
			return "git " + a + " (config for one run can run commands)"
		case a == "-C" || a == "--git-dir" || a == "--work-tree" || a == "--namespace" || a == "--super-prefix":
			k++
		case strings.HasPrefix(a, "-"):
		default:
			return gitSubWrite(a, args[k+1:])
		}
	}
	return ""
}

func gitSubWrite(sub string, rest []string) string {
	for _, a := range rest {
		for _, o := range []string{"--output", "--upload-pack", "--receive-pack", "--exec", "--ext-diff"} {
			if a == o || strings.HasPrefix(a, o+"=") {
				return "git " + sub + " " + o
			}
		}
	}
	first := ""
	if len(rest) > 0 {
		first = rest[0]
	}
	switch sub {
	case "stash":
		if first != "list" && first != "show" {
			return "git stash"
		}
	case "branch":
		return gitRefWrite("branch", rest, "dDmMcCfut", []string{"--delete", "--move", "--copy", "--force", "--set-upstream-to", "--unset-upstream", "--edit-description", "--track"},
			[]string{"-l", "--list", "-a", "--all", "-r", "--remotes", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--show-current"})
	case "tag":
		return gitRefWrite("tag", rest, "dfasmFue", []string{"--delete", "--force", "--annotate", "--sign", "--message", "--file", "--local-user", "--edit"},
			[]string{"-l", "--list", "-n", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at"})
	case "remote":
		switch first {
		case "add", "remove", "rm", "rename", "set-url", "set-head", "set-branches", "prune", "update":
			return "git remote " + first
		}
	case "reflog":
		if first == "expire" || first == "delete" {
			return "git reflog " + first
		}
	case "hash-object":
		if slices.Contains(rest, "-w") {
			return "git hash-object -w"
		}
	case "config":
		return gitConfigWrite(rest)
	default:
		if gitWrites[sub] {
			return "git " + sub
		}
	}
	return ""
}

// gitRefWrite: git branch and git tag list, unless they get a change
// option or a name without a listing option (git branch new).
func gitRefWrite(sub string, rest []string, letters string, long, listing []string) string {
	list, names := false, 0
	for _, a := range rest {
		opt, _, _ := strings.Cut(a, "=")
		switch {
		case slices.Contains(listing, opt) || strings.HasPrefix(a, "-n") && sub == "tag":
			list = true
		case slices.Contains(long, opt):
			return "git " + sub + " " + a
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-"):
			if strings.ContainsAny(a[1:], letters) {
				return "git " + sub + " " + a
			}
		default:
			names++
		}
	}
	if names > 0 && !list {
		return "git " + sub + " NAME"
	}
	return ""
}

// gitConfigWrite: git config NAME and --get/--list read; NAME VALUE, the
// set/unset subcommands and the change options write.
func gitConfigWrite(rest []string) string {
	get, names := false, 0
	for k := 0; k < len(rest); k++ {
		a := rest[k]
		switch {
		case a == "--unset" || a == "--unset-all" || a == "--add" || a == "--replace-all" || a == "--remove-section" ||
			a == "--rename-section" || a == "-e" || a == "--edit":
			return "git config " + a
		case strings.HasPrefix(a, "--get") || a == "-l" || a == "--list":
			get = true
		case a == "-f" || a == "--file" || a == "--blob" || a == "--type" || a == "--default":
			k++
		case strings.HasPrefix(a, "-"):
		default:
			if names == 0 {
				switch a {
				case "set", "unset", "rename-section", "remove-section", "edit":
					return "git config " + a
				case "get", "list":
					get = true
				}
			}
			names++
		}
	}
	if names >= 2 && !get {
		return "git config NAME VALUE"
	}
	return ""
}
