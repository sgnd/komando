package cli

import (
	"regexp"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/driver"
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
		case strings.HasPrefix(a, "-F") || strings.HasPrefix(a, "-v"): // the value attached
		case strings.HasPrefix(a, "-") && a != "-":
			return cmd + " " + a + " (komando does not know this option only reads)"
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
		case l == 'I' || l == 'g' || l == 'F' || l == 'M':
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
	if mode == "" {
		return "tar (only listing, comparing and an archive to standard output are known to read)"
	}
	if strings.Contains(archive, ":") && !slices.Contains(args, "--force-local") {
		return "tar -f " + archive + " (an archive on another computer)"
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
			if strings.Trim(a[1:], "cdltkvqfn0123456789") != "" {
				return cmd + " " + a + " (komando does not know this option only reads)"
			}
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

// sortWrite: sort -o FILE writes the result to FILE.
func sortWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "--output") || len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.Contains(a, "o") {
			return cmd + " -o"
		}
	}
	return ""
}

// operands are the words of args that are not options, leaving out the
// value after each option in valued (uniq -f 2).
func operands(args []string, valued ...string) []string {
	var ops []string
	opts := true
	for k := 0; k < len(args); k++ {
		switch a := args[k]; {
		case opts && a == "--":
			opts = false
		case opts && slices.Contains(valued, a):
			k++
		case opts && len(a) > 1 && a[0] == '-':
		default:
			ops = append(ops, a)
		}
	}
	return ops
}

// uniqWrite: uniq IN OUT writes OUT.
func uniqWrite(cmd string, args []string, _ bool) string {
	if len(operands(args, "-f", "-s", "-w")) > 1 {
		return cmd + " writing its second file"
	}
	return ""
}

// opensslWrite: only the subcommands that show a certificate, a request or
// a connection read; -out and its like write a file, and -engine and
// -provider load code.
func opensslWrite(cmd string, args []string, _ bool) string {
	if len(args) == 0 || !opensslReads[args[0]] {
		return cmd + " " + strings.Join(args[:min(len(args), 1)], "") + " (not a form komando knows only reads)"
	}
	for _, a := range args[1:] {
		if opensslWrites[a] {
			return cmd + " " + a
		}
	}
	return ""
}

var (
	opensslReads  = set(`x509 req crl verify version ciphers s_client`)
	opensslWrites = set(`-out -keyout -writerand -engine -provider -provider-path -provider_path -config -CAcreateserial
		-CAserial -sess_out -keylogfile -msgfile -passout -signkey -CAkey -key -new -x509 -proxy -starttls`)
)

// dateWrite: date -s TIME, or a bare MMDDhhmm, sets the clock.
func dateWrite(cmd string, args []string, _ bool) string {
	for k := 0; k < len(args); k++ {
		switch a := args[k]; {
		case len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.Contains(a, "s"):
			return cmd + " --set"
		case a == "-d" || a == "-r" || a == "-f" || a == "--date" || a == "--reference" || a == "--file":
			k++ // --date TEXT, --reference FILE, --file FILE
		case !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+"):
			return cmd + " setting the time"
		}
	}
	return ""
}

// hostnameWrite: hostname NAME (or -F FILE, -b) sets the host name.
func hostnameWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || !strings.HasPrefix(a, "--") && strings.ContainsAny(a, "Fb") {
			return cmd + " setting the host name"
		}
	}
	return ""
}

// dmesgWrite: clearing the ring buffer or changing the console level
// (-c -C -n -D -E).
func dmesgWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if a == "--clear" || a == "--read-clear" || strings.HasPrefix(a, "--console-") ||
			len(a) > 1 && a[0] == '-' && a[1] != '-' && !strings.Contains(a, "=") && strings.ContainsAny(a, "cCnDE") {
			return cmd + " " + a
		}
	}
	return ""
}

// redisCliValued are the redis-cli options that take a value.
var redisCliValued = set(`-h -p -t -s -a -u -r -i -n -d -D -X --user --pass --sni --cacert --cacertdir
	--tls-ciphers --tls-ciphersuites --cert --key --show-pushes --lru-test --pipe-timeout --memkeys-samples
	--pattern --count --quoted-pattern --intrinsic-latency --keystats-samples --top`)

// redisCliWrite: the command redis-cli sends is rated like `cache redis raw`'s
// (cachex.Classify). Modes that write here, send a script or load data
// break the promise; with no command it reads commands from its input.
func redisCliWrite(cmd string, args []string, input bool) string {
	for k := 0; k < len(args); k++ {
		a := args[k]
		switch {
		case a == "--pipe" || a == "--eval" || a == "--rdb" || a == "--functions-rdb" || a == "--ldb" || a == "--ldb-sync-mode" || a == "-x":
			return cmd + " " + a
		case a == "--cluster":
			if k+1 < len(args) && (args[k+1] == "info" || args[k+1] == "check" || args[k+1] == "help") {
				return ""
			}
			return cmd + " --cluster"
		case redisCliValued[a]:
			k++
		case strings.HasPrefix(a, "-") && len(a) > 1:
		default:
			if v := cachex.Classify(args[k:]); v.Risk != driver.RiskRead {
				return cmd + " " + strings.ToUpper(a)
			}
			return ""
		}
	}
	if input {
		return cmd + " reading commands from a pipe or a file"
	}
	return ""
}
