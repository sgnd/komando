package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// readsOnly says whether the program base, run with args, only reads the
// files it names: a reader (readOnlyPrograms), or a program that writes
// only in a form args do not use (readerArgs).
func readsOnly(base string, args []string) bool {
	if readOnlyPrograms[base] {
		return true
	}
	_, ok := readerArgs(base, args)
	return ok
}

// readerArgs says whether a program that reads in one form and writes in
// another (sort -o, uniq's output file, sed -i, awk -i inplace, a write or
// a command in a sed or awk program) is run in its read form, and which
// args are the files it reads. Its options are read as getopt reads them
// (optSpec); an option it does not know is taken as a write.
func readerArgs(base string, args []string) (files []int, ok bool) {
	spec, known := readerSpecs[base]
	if !known {
		return nil, false
	}
	scripts, operands, ok := spec.parse(args)
	if !ok {
		return nil, false
	}
	switch base {
	case "sort":
		return operands, true
	case "uniq": // uniq [IN [OUT]]: a second file is written
		return operands, len(operands) <= 1
	case "go":
		if len(operands) == 0 || args[operands[0]] != "version" {
			return nil, false
		}
		return operands[1:], true
	case "sed", "gsed":
		if len(scripts) == 0 { // no -e: the first operand is the script
			if len(operands) == 0 {
				return nil, false
			}
			scripts, operands = []string{args[operands[0]]}, operands[1:]
		}
		for _, sc := range scripts {
			if !sedScriptReadsOnly(sc) {
				return nil, false
			}
		}
		return operands, true
	default: // awk: the first operand is the program
		if len(operands) == 0 || awkWrites.MatchString(args[operands[0]]) {
			return nil, false
		}
		var l []int
		for _, i := range operands[1:] {
			if !envAssign.MatchString(args[i]) { // var=value is no file
				l = append(l, i)
			}
		}
		return l, true
	}
}

// optSpec says how a program reads its options, as getopt does: short
// letters that stand alone (flags), that take a value (the rest of the
// word, or else the next word), that take a script (a value that is
// checked), and long names with their kind. A letter or name not listed
// is refused, and so is a long name shortened so that it could be two.
type optSpec struct {
	flags, values, scripts string
	long                   map[string]optKind
}

type optKind int

const (
	optRefuse optKind = iota
	optFlag
	optValue
	optScript
)

// parse gives the scripts the options carry and the indexes of the
// operands, or false when an option is refused or unknown.
func (o optSpec) parse(args []string) (scripts []string, operands []int, ok bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			for j := i + 1; j < len(args); j++ {
				operands = append(operands, j)
			}
			return scripts, operands, true
		case strings.HasPrefix(a, "--"):
			name, val, hasVal := strings.Cut(a[2:], "=")
			k := o.longKind(name)
			switch {
			case k == optRefuse:
				return nil, nil, false
			case k == optFlag:
			case hasVal:
				if k == optScript {
					scripts = append(scripts, val)
				}
			case i+1 < len(args):
				i++
				if k == optScript {
					scripts = append(scripts, args[i])
				}
			default:
				return nil, nil, false
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				c := a[j]
				switch {
				case strings.IndexByte(o.flags, c) >= 0:
					continue
				case strings.IndexByte(o.values, c) >= 0 || strings.IndexByte(o.scripts, c) >= 0:
					v := a[j+1:]
					if v == "" {
						if i+1 == len(args) {
							return nil, nil, false
						}
						i++
						v = args[i]
					}
					if strings.IndexByte(o.scripts, c) >= 0 {
						scripts = append(scripts, v)
					}
				default:
					return nil, nil, false
				}
				break
			}
		default:
			operands = append(operands, i)
		}
	}
	return scripts, operands, true
}

// longKind is the kind of a long option name, which may be shortened to
// any prefix that fits one name only.
func (o optSpec) longKind(name string) optKind {
	if k, ok := o.long[name]; ok {
		return k
	}
	found, kind := 0, optRefuse
	for n, k := range o.long {
		if strings.HasPrefix(n, name) {
			found, kind = found+1, k
		}
	}
	if found != 1 {
		return optRefuse
	}
	return kind
}

// readerSpecs are the options of the programs readerArgs knows. A form
// that writes is left out, so it is refused: sort -o, -T and
// --compress-program, sed -i, -I and -f, awk's every option but -F and -v.
var readerSpecs = map[string]optSpec{
	"sort": {flags: "bdfgiMhnRrVcCmsuz", values: "ktS", long: map[string]optKind{
		"ignore-leading-blanks": optFlag, "dictionary-order": optFlag, "ignore-case": optFlag, "general-numeric-sort": optFlag,
		"ignore-nonprinting": optFlag, "month-sort": optFlag, "human-numeric-sort": optFlag, "numeric-sort": optFlag,
		"random-sort": optFlag, "reverse": optFlag, "version-sort": optFlag, "check": optFlag, "merge": optFlag,
		"stable": optFlag, "unique": optFlag, "zero-terminated": optFlag, "debug": optFlag,
		"key": optValue, "field-separator": optValue, "buffer-size": optValue, "parallel": optValue, "sort": optValue,
		"output": optRefuse, "compress-program": optRefuse, "temporary-directory": optRefuse}},
	"uniq": {flags: "cdDiuz", values: "fsw", long: map[string]optKind{
		"count": optFlag, "repeated": optFlag, "all-repeated": optFlag, "group": optFlag, "ignore-case": optFlag,
		"unique": optFlag, "zero-terminated": optFlag, "skip-fields": optValue, "skip-chars": optValue, "check-chars": optValue}},
	"go":  {flags: "mv"},
	"sed": sedSpec, "gsed": sedSpec,
	"awk": awkSpec, "gawk": awkSpec, "mawk": awkSpec, "nawk": awkSpec,
}

var sedSpec = optSpec{flags: "nErsuzba", values: "l", scripts: "e", long: map[string]optKind{
	"quiet": optFlag, "silent": optFlag, "regexp-extended": optFlag, "separate": optFlag, "unbuffered": optFlag,
	"null-data": optFlag, "zero-terminated": optFlag, "posix": optFlag, "debug": optFlag, "sandbox": optFlag,
	"follow-symlinks": optFlag, "binary": optFlag, "line-length": optValue, "expression": optScript,
	"file": optRefuse, "in-place": optRefuse}}

var awkSpec = optSpec{values: "Fv"}

// sedScriptReadsOnly says whether a sed script writes no file and runs no
// command: every command is p, d, q, =, a line move or a hold-space step,
// a substitution without the w or e flag, or y. Anything else (w, W, e, r,
// R, a, i, c, labels) does not pass.
func sedScriptReadsOnly(sc string) bool {
	i := 0
	skipDelimited := func(delim byte) bool { // past the next unescaped delim
		for i < len(sc) {
			switch c := sc[i]; {
			case c == '\\':
				i += 2
			case c == delim:
				i++
				return true
			default:
				i++
			}
		}
		return false
	}
	address := func() bool {
		switch {
		case i < len(sc) && sc[i] == '$':
			i++
		case i < len(sc) && sc[i] >= '0' && sc[i] <= '9':
			for i < len(sc) && (sc[i] >= '0' && sc[i] <= '9' || sc[i] == '~') {
				i++
			}
		case i < len(sc) && sc[i] == '/':
			i++
			if !skipDelimited('/') {
				return false
			}
			for i < len(sc) && (sc[i] == 'I' || sc[i] == 'M') {
				i++
			}
		}
		return true
	}
	for i < len(sc) {
		switch sc[i] {
		case ' ', '\t', '\n', ';', '{', '}':
			i++
			continue
		}
		if !address() {
			return false
		}
		if i < len(sc) && sc[i] == ',' {
			i++
			if !address() {
				return false
			}
		}
		for i < len(sc) && (sc[i] == ' ' || sc[i] == '!') {
			i++
		}
		if i == len(sc) {
			return false
		}
		c := sc[i]
		i++
		switch {
		case strings.IndexByte("pdDqQ=nNPgGhHxlz", c) >= 0:
			for i < len(sc) && sc[i] >= '0' && sc[i] <= '9' { // q EXIT
				i++
			}
		case c == '{' || c == '}':
		case c == 's' || c == 'y':
			if i == len(sc) {
				return false
			}
			d := sc[i]
			i++
			if d == '\\' || d == '\n' || !skipDelimited(d) || !skipDelimited(d) {
				return false
			}
			for i < len(sc) && strings.IndexByte("gpiImM0123456789", sc[i]) >= 0 {
				i++
			}
		default:
			return false
		}
	}
	return true
}

// awkWrites is awk code that writes a file or runs a command: print or
// printf into a file (> or >>), a pipe (| but not ||), system(), and
// gawk's @load and @include (an extension such as inplace or rwarray).
var awkWrites = regexp.MustCompile(`\bprintf?\b[^;{}]*>|(^|[^|])\|($|[^|])|\bsystem\s*\(|@(load|include)`)

// komandoWordHarmless says whether a word w of line that ends in /komando
// may stay: nothing is at its path p (no file, link or folder), and line
// cannot create it (harmlessKomandoLine). A repo slug (gh -R sgnd/komando),
// a URL and a loop over repo slugs name no file.
func komandoWordHarmless(line, p string) bool {
	if _, err := os.Lstat(p); err == nil || p == "" {
		return false
	}
	return harmlessKomandoLine(line)
}

// harmlessKomandoLine is a line that creates no file by a name it holds:
// no redirect, no command or process substitution, no variable set, and
// every command a reader, a for loop's list, or gh or git in a form that
// only reads (ghReadsOnly, gitReadsOnly).
func harmlessKomandoLine(line string) bool {
	if len(redirectFiles(line)) > 0 || strings.ContainsAny(line, "`") || strings.Contains(line, "$(") ||
		strings.Contains(line, "<(") || strings.Contains(line, ">(") {
		return false
	}
	for _, seg := range splitShell(line) {
		words := shellWords(seg)
		if len(words) > 0 && words[0] == "for" {
			continue // for NAME in WORDS: a list, not a command
		}
		for _, w := range words {
			if envAssign.MatchString(w) {
				return false
			}
		}
		prog, args := program(words)
		base := filepath.Base(prog)
		switch {
		case prog == "" || readsOnly(base, args):
		case base == "gh" && ghReadsOnly(args):
		case base == "git" && gitReadsOnly(args):
		case base == "orca" && orcaNamesNoFile(args):
		default:
			return false
		}
	}
	return true
}

// orcaNamesNoFile says whether orca, run with args, names only Orca's own
// records (a repo, a worktree, a session: --repo komando): no output and
// no path flag.
func orcaNamesNoFile(args []string) bool {
	for _, a := range args {
		if writesOutput(a) || strings.HasPrefix(a, "--path") || strings.HasPrefix(a, "--file") {
			return false
		}
	}
	return len(args) > 0
}

// lineForOthers is line as its command seg sees it: without the commands
// that only print (printsOnly) and hand no word on through a pipe. Only a
// plain line (plainShellLine) is narrowed; any other is returned whole.
func lineForOthers(line, seg string) string {
	segs, ends := shellCuts(line)
	if !plainShellLine(line, segs, ends) {
		return line
	}
	var kept []string
	for i, s := range segs {
		piped := ends[i] == '|' && !(i+1 < len(segs) && segs[i+1] == "" && ends[i+1] == '|')
		if s == seg || piped || !printsOnly(shellWords(s)) {
			kept = append(kept, s)
		}
	}
	return strings.Join(kept, " ; ")
}

// plainShellLine says whether every command of line is plain literal text, so
// that none hands another a word except through a pipe. A line is not
// plain with a $, a backtick or a ! anywhere, a parenthesis outside quotes
// (a subshell, <( and >(), a heredoc, a redirect to a file, a group, a
// compound command, a background job, BASH_COMMAND, a source (.) or a word
// of lineCarrier or a shell anywhere. A line that is not plain is checked
// whole: a false refusal is the safe side.
func plainShellLine(line string, segs []string, ends []byte) bool {
	if ends == nil || strings.ContainsAny(line, "$`!") || strings.Contains(line, "<<") ||
		strings.Contains(line, "BASH_COMMAND") || len(redirectFiles(line)) > 0 {
		return false
	}
	for i, e := range ends {
		if e == '(' || e == ')' || e == '&' && backgroundJob(segs, ends, i) {
			return false
		}
	}
	for _, s := range segs {
		words := shellWords(s)
		if prog, _ := program(words); prog == "." {
			return false
		}
		for _, w := range words {
			if b := filepath.Base(w); compoundWord[w] || lineCarrier[b] || isShell(b) {
				return false
			}
		}
	}
	return true
}

// backgroundJob says whether the & that ends segs[i] runs it in the
// background: it is not half of && and not the & of |&.
func backgroundJob(segs []string, ends []byte, i int) bool {
	first := i+1 < len(segs) && segs[i+1] == "" && ends[i+1] == '&'
	second := i > 0 && segs[i] == "" && (ends[i-1] == '&' || ends[i-1] == '|')
	return !first && !second
}

// compoundWord are the words of the shell's groups and compound commands,
// whose output goes on as a whole (`for ...; do ls X; done | xargs rm`).
var compoundWord = map[string]bool{"{": true, "}": true, "!": true, "if": true, "then": true, "else": true, "elif": true, "fi": true,
	"for": true, "select": true, "while": true, "until": true, "do": true, "done": true, "case": true, "esac": true,
	"function": true, "coproc": true}

// lineCarrier are the words of the shell's commands that run code in the
// shell, read the line back (history, a DEBUG trap), change the folder, or
// change what a program's name runs (hash -p, alias, enable).
var lineCarrier = map[string]bool{"eval": true, "trap": true, "source": true, "exec": true, "command": true, "builtin": true,
	"declare": true, "local": true, "typeset": true, "export": true, "readonly": true, "alias": true, "unalias": true,
	"hash": true, "enable": true, "disable": true, "autoload": true, "functions": true, "zmodload": true,
	"set": true, "setopt": true, "shopt": true, "emulate": true, "history": true, "fc": true, "r": true,
	"cd": true, "pushd": true, "popd": true, "chdir": true}

// printsOnly says whether the command words runs komando or a reader and
// sets no variable: what it does with the words it names stays its own.
func printsOnly(words []string) bool {
	for _, w := range words {
		if envAssign.MatchString(w) {
			return false
		}
	}
	prog, args := program(words)
	base := filepath.Base(prog)
	if len(setNames(base, args)) > 0 {
		return false // printf -v NAME: a later command reads the variable
	}
	return base == "komando" || prog != "" && readsOnly(base, args)
}

// writesOutput is a flag that names a file a program writes: -o, -O, -D,
// --output, --dir (also joined to its value).
func writesOutput(a string) bool {
	return a == "-O" || a == "-D" || strings.HasPrefix(a, "--output") || strings.HasPrefix(a, "--dir") ||
		strings.HasPrefix(a, "-o") && !strings.HasPrefix(a, "--")
}

// ghReadsOnly says whether gh, run with args, writes no local file: a
// command group that talks to GitHub only, with no download, clone,
// checkout or copy, and no output flag.
func ghReadsOnly(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "pr", "issue", "run", "release", "repo", "search", "api", "workflow", "label", "status", "auth", "cache", "variable", "ruleset", "project":
	default:
		return false
	}
	for _, a := range args[1:] {
		switch {
		case writesOutput(a), a == "download", a == "checkout", a == "cp", strings.Contains(a, "clone"):
			return false
		}
	}
	return true
}

// gitReadOnlyCommands only read the repository and the remote.
var gitReadOnlyCommands = map[string]bool{"status": true, "log": true, "show": true, "diff": true, "ls-remote": true, "ls-files": true,
	"ls-tree": true, "rev-parse": true, "rev-list": true, "remote": true, "describe": true, "blame": true, "grep": true,
	"cat-file": true, "shortlog": true, "branch": true, "tag": true, "merge-base": true, "for-each-ref": true, "show-ref": true, "reflog": true}

// gitReadsOnly says whether git, run with args, writes no file outside
// .git: a command in gitReadOnlyCommands, after git's own flags, and no
// output flag.
func gitReadsOnly(args []string) bool {
	i := 0
	for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
		switch args[i] {
		case "-C", "-c", "--git-dir", "--work-tree", "--namespace":
			i++
		}
	}
	if i == len(args) || !gitReadOnlyCommands[args[i]] {
		return false
	}
	for _, a := range args[i+1:] {
		if writesOutput(a) {
			return false
		}
	}
	return true
}

// lineWithoutReadFiles is line, its commands' words joined, without the
// files its readers read: every argument of a program in
// readOnlyPrograms, and the operands readerArgs gives for a program in its
// read form. Scripts, flag values, variables and every other command stay.
func lineWithoutReadFiles(line string) string {
	var out []string
	for _, seg := range splitShell(line) {
		words := shellWords(seg)
		prog, args := program(words)
		first := len(words) - len(args) // where the arguments start
		base := filepath.Base(prog)
		drop := map[int]bool{}
		if prog != "" && readOnlyPrograms[base] {
			for i := range args {
				drop[i] = true
			}
		} else if files, ok := readerArgs(base, args); prog != "" && ok {
			for _, i := range files {
				drop[i] = true
			}
		}
		var kept []string
		for j, w := range words {
			if j < first || !drop[j-first] {
				kept = append(kept, w)
			}
		}
		out = append(out, strings.Join(kept, " "))
	}
	return strings.Join(out, " ; ")
}
