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
			// a wrapper's flag, e.g. sudo -u app: skip its value too
			if wrapperValue[wrapper][w] {
				i++
			}
			continue
		case pos < wrapperPositional[wrapper]:
			pos++
			continue
		}
		return w, words[i+1:]
	}
	return "", nil
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
	"env":        {"-u": true, "--unset": true, "-C": true, "--chdir": true, "-S": true, "--split-string": true},
	"sudo":       {"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true, "-r": true, "-t": true, "-U": true, "-T": true},
	"doas":       {"-u": true, "-C": true},
	"nice":       {"-n": true},
	"exec":       {"-a": true},
	"time":       {"-f": true, "-o": true},
	"xargs":      {"-I": true, "-n": true, "-P": true, "-L": true, "-d": true, "-E": true, "-s": true, "-a": true},
	"timeout":    {"-s": true, "--signal": true, "-k": true, "--kill-after": true},
	"stdbuf":     {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"ionice":     {"-c": true, "-n": true, "--class": true, "--classdata": true},
	"chrt":       {"-T": true, "-P": true, "-D": true},
	"caffeinate": {"-t": true, "-w": true},
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
