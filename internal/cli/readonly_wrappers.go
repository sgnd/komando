package cli

import (
	"regexp"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/policy"
)

// wrappers run the next word as the command. The first list is the
// options that take a value (sudo -u root, timeout -s KILL): the value is
// not the command. The second is the options that take none. A wrapper
// option that is in neither list is refused: komando could not tell where
// the command starts, or what the option does (sudo -h HOST, ionice -p PID).
var wrappers = map[string][]string{
	"sudo":    {"-u", "-g", "-p", "--user", "--group", "--prompt"},
	"doas":    {"-u"},
	"env":     {"-u", "-C", "--unset", "--chdir"},
	"nice":    {"-n", "--adjustment"},
	"timeout": {"-s", "-k", "--signal", "--kill-after"},
	"ionice":  {"-c", "-n", "--class", "--classdata"},
	"stdbuf":  {"-i", "-o", "-e", "--input", "--output", "--error"},
	"xargs":   {"-I", "-L", "-n", "-P", "-d", "-E", "-s", "-a", "--max-args", "--max-lines", "--max-procs", "--delimiter", "--eof", "--max-chars", "--arg-file", "--replace"},
	"time":    {"-f", "--format"},
	"command": nil,
}

var wrapperFlags = map[string]map[string]bool{
	"sudo":    set(`-n -E -H --non-interactive --preserve-env --set-home`),
	"doas":    set(`-n`),
	"env":     set(`-i -S --ignore-environment --split-string`),
	"timeout": set(`-v --preserve-status --foreground --verbose`),
	"ionice":  set(`-t --ignore`),
	"xargs":   set(`-0 -r -t -x --null --no-run-if-empty --verbose --exit`),
	"time":    set(`-p -v -o --portability --verbose --output`),
	"command": set(`-p -v -V`),
}

// wrapperOptionKnown: a is an option of the wrapper komando knows, alone,
// in a group of letters (-nE) or with its value attached (-uroot, --user=x).
func wrapperOptionKnown(name string, opts []string, a string) bool {
	flags := wrapperFlags[name]
	if n, _, _ := strings.Cut(a, "="); flags[a] || flags[n] || slices.Contains(opts, a) || slices.Contains(opts, n) {
		return true
	}
	if strings.HasPrefix(a, "--") {
		return false
	}
	for j := 1; j < len(a); j++ {
		l := "-" + string(a[j])
		if slices.Contains(opts, l) {
			return true // the rest of the word is its value
		}
		if !flags[l] {
			return false
		}
	}
	return true
}

// wrapperWords are the words a wrapper takes before its command, each
// with the form it must have: timeout DURATION CMD.
var wrapperWords = map[string][]*regexp.Regexp{
	"timeout": {regexp.MustCompile(`^([0-9]+(\.[0-9]*)?|\.[0-9]+)[smhd]?$`)},
}

// skipWrapper steps over a wrapper's options and values (sudo -u root,
// timeout 10) and returns where its command starts, -1 when there is
// nothing more to check, or why the wrapper itself changes something.
func skipWrapper(name string, opts []string, toks []policy.Token, i int, input bool, depth int) (int, string) {
	words := texts(toks)
	positional := 0
	for i < len(words) {
		a := words[i]
		if a == "--" {
			i++
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			long := strings.HasPrefix(a, "--")
			flags := ""
			if !long {
				flags = a[1:]
			}
			switch {
			case name == "command" && (a == "-v" || a == "-V"):
				return -1, "" // only says where a command is
			case (name == "sudo" || name == "doas") && (strings.ContainsAny(flags, "e") && name == "sudo" || a == "--edit"):
				return -1, "sudo -e"
			case (name == "sudo" || name == "doas") && (strings.ContainsAny(flags, "si") || a == "--shell" || a == "--login"):
				return -1, name + " " + a + " (a shell reads the command again)"
			case name == "env" && (strings.Contains(flags, "S") || strings.HasPrefix(a, "--split-string")):
				return -1, "env -S"
			case name == "time" && (strings.Contains(flags, "o") || strings.HasPrefix(a, "--output")):
				return -1, "time -o"
			}
			if !wrapperOptionKnown(name, opts, a) {
				return -1, name + " " + a + " (komando does not know this option)"
			}
			if takesValue(opts, a) {
				i++
			}
			i++
			continue
		}
		if isAssign(a) || name == "env" && strings.Contains(a, "=") { // env NAME=VALUE, sudo NAME=VALUE
			if v := envWrite(a); v != "" {
				return -1, v
			}
			i++
			continue
		}
		if forms := wrapperWords[name]; positional < len(forms) { // timeout DURATION
			if !forms[positional].MatchString(a) {
				return -1, name + " " + a + " (komando cannot tell where the command starts)"
			}
			positional++
			i++
			continue
		}
		break
	}
	if i >= len(words) {
		return -1, ""
	}
	return i, ""
}

// takesValue says whether option a takes the next word as its value, the
// way getopt reads it: in a group of letters the first one that takes a
// value ends the group (-nu root: root is -u's value; -uroot: attached).
func takesValue(opts []string, a string) bool {
	if strings.Contains(a, "=") {
		return false
	}
	if slices.Contains(opts, a) {
		return true
	}
	if strings.HasPrefix(a, "--") {
		return false
	}
	for j := 1; j < len(a); j++ {
		if slices.Contains(opts, "-"+string(a[j])) {
			return j == len(a)-1
		}
	}
	return false
}
