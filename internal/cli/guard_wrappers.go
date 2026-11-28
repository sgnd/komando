package cli

import (
	"path/filepath"
	"slices"
	"strings"
)

// shellKeyword are words that can start a simple command before the
// command itself: `{ unset X; }`, `! unset X`, `if unset X`, `builtin unset X`.
var shellKeyword = map[string]bool{"{": true, "}": true, "!": true, "if": true, "then": true, "else": true, "elif": true, "fi": true,
	"do": true, "done": true, "while": true, "until": true, "builtin": true, "coproc": true, "noglob": true, "nocorrect": true, "function": true}

// program is the command a simple command runs, after shell keywords,
// VAR=value words and wrappers such as sudo, env, time, timeout and nohup.
func program(words []string) (string, []string) {
	at := readWrappers(words, nil).at
	if at < 0 {
		return "", nil
	}
	return words[at], words[at+1:]
}

// wrapperRead is what readWrappers finds in a simple command's words: the
// program's index (-1 for none), the wrapper options the guard does not
// know, and the folder a wrapper runs the program in when chdir is set
// (env -C DIR, sudo -D DIR; lostDir or "" when the guard cannot read it).
type wrapperRead struct {
	at      int
	unknown []int
	dir     string
	chdir   bool
}

// readWrappers reads words as program does, where each wrapper option the
// guard does not know whose index is in valued takes the next word as its
// value; the others take none.
func readWrappers(words []string, valued map[int]bool) wrapperRead {
	r := wrapperRead{at: -1}
	wrapper, pos := "", 0
	for i := 0; i < len(words); i++ {
		w := words[i]
		base := filepath.Base(w)
		switch {
		case wrapper == "" && shellKeyword[w]:
			if w == "function" {
				i++
			}
			continue
		case envAssign.MatchString(w):
			continue
		case isWrapper(base) && base != "env":
			wrapper, pos = base, 0
			continue
		case base == "env" && i+1 < len(words): // env alone lists the variables
			wrapper, pos = "env", 0
			continue
		case strings.HasPrefix(w, "-") && i > 0:
			// a wrapper's option, e.g. sudo -u app: skip its value too
			name, value, next, known := wrapperOption(wrapper, w)
			if !known && wrapper != "" {
				r.unknown = append(r.unknown, i)
				next = valued[i]
			}
			if next && i+1 < len(words) {
				i++
				value = words[i]
			}
			switch {
			case chdirOption[wrapper][name]:
				r.dir, r.chdir = value, true
			case mayChdir(wrapper, w, known):
				r.dir, r.chdir = lostDir, true
			}
			continue
		case pos < wrapperPositional[wrapper]:
			pos++
			continue
		}
		r.at = i
		return r
	}
	return r
}

// wrapperOption reads w, an option word of wrapper: the option in it that
// takes a value ("" for none), that value when w holds it (--chdir=DIR,
// -CDIR), whether the next word is the value instead, and whether the
// guard knows each option in w.
func wrapperOption(wrapper, w string) (name, value string, next, known bool) {
	if w == "-" || w == "--" {
		return "", "", false, true
	}
	if strings.HasPrefix(w, "--") {
		n, v, eq := strings.Cut(w, "=")
		switch {
		case wrapperValue[wrapper][n]:
			return n, v, !eq, true
		case eq || wrapperFlag[wrapper][n]:
			return "", "", false, true
		}
		return "", "", false, false
	}
	for k := 1; k < len(w); k++ {
		o := "-" + w[k:k+1]
		switch {
		case wrapperValue[wrapper][o]:
			return o, w[k+1:], k == len(w)-1, true
		case !wrapperFlag[wrapper][o] && !(wrapper == "nice" && w[k] >= '0' && w[k] <= '9'):
			return "", "", false, false // nice -10 is a flag
		}
	}
	return "", "", false, true
}

// chdirOption are the wrapper options that run the program in another folder.
var chdirOption = map[string]map[string]bool{"env": {"-C": true, "--chdir": true}, "sudo": {"-D": true, "--chdir": true}}

// mayChdir reports whether w, an option of wrapper that is no chdirOption
// itself, may still be one: the start of a long one (GNU takes --ch for
// --chdir), or a cluster the guard does not know (known) holding its letter.
func mayChdir(wrapper, w string, known bool) bool {
	n, _, _ := strings.Cut(w, "=")
	for o := range chdirOption[wrapper] {
		if strings.HasPrefix(o, "--") && len(n) > 2 && n != o && strings.HasPrefix(o, n) ||
			!known && !strings.HasPrefix(w, "--") && strings.Contains(w[1:], o[1:]) {
			return true
		}
	}
	return false
}

// maxReadings is how many other ways of reading a simple command's wrapper
// options the guard checks (wrapperReadings).
const maxReadings = 8

// wrapperReadings are seg and the other ways its wrappers may read: a
// wrapper option the guard does not know may take the next word as its
// value (`nice --adjustment 5 rm`) or not (`sudo -B rm`). In each other way
// the options that take one are joined to it with =, one word to the
// shell, and seg's redirects, which seg itself checks, are left out. It is
// false past maxReadings ways.
func wrapperReadings(seg string) ([]string, bool) {
	raw := rawWords(seg)
	words := shellWords(strings.Join(raw, " "))
	ways := optionWays(words)
	if len(ways) == 0 {
		return []string{seg}, true
	}
	if len(ways) > maxReadings || len(words) != len(raw) {
		return nil, false
	}
	out := []string{seg}
	for _, valued := range ways {
		var b strings.Builder
		for i, w := range raw {
			if i > 0 && valued[i-1] {
				b.WriteByte('=')
			} else if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(w)
		}
		out = append(out, b.String())
	}
	return out, true
}

// optionWays are the ways words' wrapper options the guard does not know
// may take a value, other than program's, where none does: for each, the
// indexes of the options that take the next word.
func optionWays(words []string) []map[int]bool {
	var ways []map[int]bool
	var walk func(valued map[int]bool, from int)
	walk = func(valued map[int]bool, from int) {
		for _, u := range readWrappers(words, valued).unknown {
			if u < from || len(ways) > maxReadings {
				continue
			}
			next := map[int]bool{u: true}
			for k := range valued {
				next[k] = true
			}
			ways = append(ways, next)
			walk(next, u+1)
		}
	}
	walk(nil, 0)
	return ways
}

// wrapperCwd is the folder the program of words runs in: the one a wrapper
// names (env -C DIR, sudo -D DIR), lostDir when the guard cannot read it,
// else cwd; and whether a wrapper names one.
func wrapperCwd(cl *call, words []string, vars lineVars, home, cwd string) (string, bool) {
	r := readWrappers(words, nil)
	switch {
	case !r.chdir:
		return cwd, false
	case r.dir == "" || r.dir == lostDir:
		return lostDir, true
	}
	return cdTarget(cl, []string{r.dir}, vars, home, cwd), true
}

// programRun is what a simple command may run: the base names of the
// programs, the words they are given, whether the shell globs each,
// whether each holds a value outside quotes, and whether they run under
// xargs.
type programRun struct {
	bases       []string
	words       []string
	globs, bare []bool
	xargs       bool
}

// valueRuns are what a simple command may run whose program word,
// words[0], has the values progs; programs given the same words share one
// run. A value not quoted (split) is split at the line's separators, and
// its fields and the words after it are read as a line is (program): an
// empty value is gone and a wrapper runs the program after it. A program
// that is still a value is one the guard cannot name.
func valueRuns(progs, words []string, globs, bare []bool, split bool, seps string) []programRun {
	var runs []programRun
	add := func(base string, r programRun) {
		for i, o := range runs {
			if o.xargs == r.xargs && slices.Equal(o.words, r.words) && slices.Equal(o.globs, r.globs) && slices.Equal(o.bare, r.bare) {
				if !slices.Contains(o.bases, base) {
					runs[i].bases = append(o.bases, base)
				}
				return
			}
		}
		r.bases = []string{base}
		runs = append(runs, r)
	}
	for _, p := range progs {
		if p == words[0] { // the program written on the line, $ or ` as text
			add(filepath.Base(p), programRun{words: words[1:], globs: globs[1:], bare: bare[1:]})
			continue
		}
		fields := []string{p}
		if split {
			fields = splitAt(p, seps)
		}
		all, allGlobs := slices.Clone(words[1:]), slices.Clone(globs[1:])
		for i := len(fields) - 1; i >= 0; i-- {
			all = slices.Insert(all, 0, strings.ReplaceAll(fields[i], "$", literalDollar))
			allGlobs = slices.Insert(allGlobs, 0, split && wordHasGlob(fields[i]))
		}
		allBare := append(make([]bool, len(fields)), bare[1:]...)
		next, rest := program(all)
		if next == "" {
			continue
		}
		at := len(all) - len(rest)
		base := filepath.Base(next)
		if strings.ContainsAny(next, "$`") || strings.Contains(next, unknownOutput) {
			base = anyProgram
		}
		add(base, programRun{words: rest, globs: allGlobs[at:], bare: allBare[at:], xargs: slices.ContainsFunc(all[:at-1], isXargs)})
	}
	return runs
}

// checkValuePrograms is checkProgram and checkReadWords for a simple command
// whose program word is a value: each program the value may run is checked
// with its own words (valueRuns), and each word with a blank given to a
// program the guard cannot name is read as a shell line, as that program may
// be eval or a shell. It gives the working folder after the command.
func checkValuePrograms(cl *call, seg string, vars lineVars, home, cwd string, depth int) (string, guardDecision) {
	if !strings.ContainsAny(seg, "$`") && !strings.Contains(seg, unknownOutput) {
		return cwd, allow()
	}
	// a $ in single quotes is text to the program (literalDollars)
	words, globs, bare := shellWordsFlags(dropRedirects(literalDollars(seg)))
	prog, args := program(words)
	if !strings.ContainsAny(prog, "$`") && !strings.Contains(prog, unknownOutput) {
		return cwd, allow()
	}
	first := len(words) - len(args)
	runs := []programRun{{[]string{anyProgram}, args, globs[first:], bare[first:], false}}
	progs, known := vars.expand(cl, prog, home, cwd)
	if _, aliased := vars[aliasVar]; known && !aliased {
		seps, _ := vars.separators()
		runs = valueRuns(progs, words[first-1:], globs[first-1:], bare[first-1:], bare[first-1], seps)
	}
	after, set := cwd, false
	for _, r := range runs {
		for _, b := range r.bases {
			next, d := checkValueProgram(cl, b, r, vars, home, cwd, depth)
			if d.Deny {
				return cwd, d
			}
			if set && next != after {
				next = lostDir
			}
			after, set = next, true
		}
	}
	return after, allow()
}

// checkValueProgram is checkValuePrograms for one program b of the run r.
func checkValueProgram(cl *call, b string, r programRun, vars lineVars, home, cwd string, depth int) (string, guardDecision) {
	switch b {
	case "komando":
		return cwd, allow()
	case anyProgram:
		for _, w := range unmarked(r.words) {
			if !strings.ContainsAny(w, " \t\n") {
				continue
			}
			if depth >= guardDepth {
				return cwd, tooDeep()
			}
			if d := checkShellIn(cl, w, home, cwd, depth+1, vars); d.Deny {
				return cwd, d
			}
		}
		return cwd, allow()
	}
	// a script runner reads its script again: a $ in it is a value there
	words := unmarked(r.words)
	next, d := checkProgram(cl, b, words, words, r.globs, vars, home, cwd, depth)
	if d.Deny {
		return cwd, d
	}
	return next, checkReadWords(cl, b, r.words, r.globs, r.words, vars, home, cwd)
}

func isXargs(w string) bool { return filepath.Base(w) == "xargs" }

func isWrapper(w string) bool {
	switch w {
	case "env", "sudo", "doas", "time", "nohup", "exec", "command", "nice", "xargs",
		"timeout", "setsid", "stdbuf", "chrt", "ionice", "taskset", "caffeinate", "busybox", "toybox", "unbuffer", "rtk":
		return true
	}
	return false
}

// wrapperValue are the wrappers' flags that take the next word as a value.
var wrapperValue = map[string]map[string]bool{
	"env": {"-u": true, "--unset": true, "-C": true, "--chdir": true, "-S": true, "--split-string": true, "-a": true, "--argv0": true,
		"-P": true, "-L": true, "-U": true},
	"sudo": {"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true, "-r": true, "-t": true, "-U": true, "-T": true, "-R": true,
		"--user": true, "--group": true, "--host": true, "--prompt": true, "--close-from": true, "--chdir": true, "--role": true,
		"--type": true, "--other-user": true, "--command-timeout": true, "--chroot": true},
	"doas": {"-u": true, "-C": true, "-a": true},
	"nice": {"-n": true, "--adjustment": true},
	"exec": {"-a": true},
	"time": {"-f": true, "-o": true, "--format": true, "--output": true},
	"xargs": {"-I": true, "-n": true, "-P": true, "-L": true, "-d": true, "-E": true, "-s": true, "-a": true, "-J": true, "-R": true, "-S": true,
		"--max-args": true, "--max-procs": true, "--delimiter": true, "--max-chars": true, "--arg-file": true, "--process-slot-var": true},
	"timeout":    {"-s": true, "--signal": true, "-k": true, "--kill-after": true},
	"stdbuf":     {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"ionice":     {"-c": true, "-n": true, "-p": true, "-P": true, "-u": true, "--class": true, "--classdata": true, "--pid": true, "--pgid": true, "--uid": true},
	"chrt":       {"-T": true, "-P": true, "-D": true, "--sched-runtime": true, "--sched-period": true, "--sched-deadline": true},
	"caffeinate": {"-t": true, "-w": true},
}

// wrapperFlag are the wrappers' options that take no value. An option in
// neither table is read both ways (wrapperReadings).
var wrapperFlag = map[string]map[string]bool{
	"env": {"-i": true, "-0": true, "-v": true, "--ignore-environment": true, "--null": true, "--debug": true, "--block-signal": true,
		"--default-signal": true, "--ignore-signal": true, "--list-signal-handling": true},
	"sudo": {"-A": true, "-B": true, "-b": true, "-E": true, "-e": true, "-H": true, "-i": true, "-K": true, "-k": true, "-l": true, "-N": true,
		"-n": true, "-P": true, "-S": true, "-s": true, "-V": true, "-v": true, "--askpass": true, "--background": true, "--bell": true,
		"--edit": true, "--login": true, "--list": true, "--non-interactive": true, "--no-update": true, "--preserve-env": true,
		"--preserve-groups": true, "--remove-timestamp": true, "--reset-timestamp": true, "--set-home": true, "--shell": true,
		"--stdin": true, "--validate": true, "--version": true},
	"doas":    {"-n": true, "-s": true, "-L": true},
	"exec":    {"-c": true, "-l": true},
	"command": {"-p": true, "-v": true, "-V": true},
	"time":    {"-p": true, "-l": true, "-v": true, "-a": true, "-q": true, "-h": true, "--portability": true, "--verbose": true, "--append": true, "--quiet": true},
	"xargs": {"-0": true, "-r": true, "-t": true, "-p": true, "-x": true, "-o": true, "-e": true, "-i": true, "-l": true, "--null": true,
		"--no-run-if-empty": true, "--verbose": true, "--interactive": true, "--exit": true, "--open-tty": true, "--replace": true,
		"--max-lines": true, "--eof": true},
	"timeout":    {"-v": true, "-f": true, "-p": true, "--foreground": true, "--preserve-status": true, "--verbose": true},
	"setsid":     {"-c": true, "-f": true, "-w": true, "--ctty": true, "--fork": true, "--wait": true},
	"caffeinate": {"-d": true, "-i": true, "-m": true, "-s": true, "-u": true},
	"ionice":     {"-t": true, "--ignore": true},
	"taskset":    {"-a": true, "-c": true, "-p": true, "--all-tasks": true, "--cpu-list": true, "--pid": true},
	"chrt": {"-a": true, "-m": true, "-p": true, "-v": true, "-b": true, "-d": true, "-f": true, "-i": true, "-o": true, "-r": true, "-R": true,
		"--all-tasks": true, "--max": true, "--pid": true, "--verbose": true, "--batch": true, "--deadline": true, "--fifo": true,
		"--idle": true, "--other": true, "--rr": true, "--reset-on-fork": true},
	"unbuffer": {"-p": true},
}

// wrapperPositional are the wrappers that take words before the program:
// timeout DURATION, chrt PRIORITY, taskset MASK.
var wrapperPositional = map[string]int{"timeout": 1, "chrt": 1, "taskset": 1}

func isShell(base string) bool {
	switch base {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish":
		return true
	}
	return false
}

// shellScript is the script a shell's arguments give with -c, or "": -c can
// come in a cluster (`bash -lc`, `sh -ec`), and options and their values
// (`-o pipefail`, `--`) can come between it and the script.
func shellScript(args []string) string {
	c := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if c && i+1 < len(args) {
				return args[i+1]
			}
			return ""
		case a == "--rcfile" || a == "--init-file":
			i++
		case strings.HasPrefix(a, "--"):
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			if a[0] == '-' && strings.ContainsRune(a[1:], 'c') {
				c = true
			}
			if strings.ContainsAny(a[1:], "oO") {
				i++ // -o pipefail
			}
		default:
			if c {
				return a
			}
			return "" // a script file
		}
	}
	return ""
}

// scriptOption are programs that run the text of their -c (or --command)
// option as a shell line.
var scriptOption = map[string]bool{"script": true, "su": true, "runuser": true, "flock": true}

// commandScript is the shell line base ARGS runs: watch's words after its
// options, the -c text of a scriptOption program, or the command BSD's
// script FILE COMMAND runs; "" when there is none.
func commandScript(base string, args []string) string {
	if base == "script" && !slices.ContainsFunc(args, func(a string) bool { return a == "-c" || strings.HasPrefix(a, "--command") }) {
		for i, a := range args {
			if !strings.HasPrefix(a, "-") {
				if i+1 < len(args) {
					return findCommandLine(args[i+1:], "{}")
				}
				return ""
			}
		}
		return ""
	}
	if base == "watch" {
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "-n" || a == "--interval" || a == "-q" || a == "--equexit":
				i++
			case a == "--":
				return strings.Join(args[i+1:], " ")
			case !strings.HasPrefix(a, "-"):
				return strings.Join(args[i:], " ")
			}
		}
		return ""
	}
	for i, a := range args {
		if (a == "-c" || a == "--command") && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--command="); ok {
			return v
		}
	}
	return ""
}
