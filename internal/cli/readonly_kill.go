package cli

import "strings"

// Read tools whose one flag or form writes a file or kills (the allowlist
// otherwise lets them through --read-only).
// optionWrite finds a writing or killing option in args: a short option
// whose letter is in letters, alone or in a cluster (-tK), or a long one in
// longs, alone or with =VALUE. valued are short options whose value is the
// next word (or the rest of the cluster), so it is not read as options.
func optionWrite(cmd string, args []string, letters, valued string, longs ...string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return ""
		case strings.HasPrefix(a, "--"):
			name, _, _ := strings.Cut(a, "=")
			for _, l := range longs {
				if name == l {
					return cmd + " " + name
				}
			}
		case len(a) > 1 && a[0] == '-':
			for _, f := range a[1:] {
				if strings.ContainsRune(letters, f) {
					return cmd + " -" + string(f)
				}
				if strings.ContainsRune(valued, f) {
					break // the rest of the word is its value
				}
			}
			if strings.ContainsRune(valued, rune(a[len(a)-1])) {
				i++
			}
		}
	}
	return ""
}

// xxdWrite: xxd IN OUT (also -r) writes OUT; one file, or OUT "-", prints.
// Its options are single words with a dash (-cols 8, -c8), some with a
// value as the next word.
func xxdWrite(cmd string, args []string, _ bool) string {
	valued := map[string]bool{"-c": true, "-cols": true, "-g": true, "-groupsize": true, "-l": true, "-len": true,
		"-o": true, "-offset": true, "-s": true, "-seek": true, "-n": true, "-name": true}
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case valued[a]:
			i++
		case len(a) > 1 && a[0] == '-':
		default:
			files = append(files, a)
		}
	}
	if len(files) >= 2 && files[1] != "-" {
		return cmd + " writing " + files[1]
	}
	return ""
}

// yqWrite: -i/--inplace (--in-place in the Python yq) rewrites the file,
// -s/--split-exp writes a file per document.
func yqWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "is", "o", "--inplace", "--in-place", "--split-exp")
}

// xmllintWrite: --output/-o FILE writes FILE; --shell runs commands
// (save, write) read from its input.
func xmllintWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		name, _, _ := strings.Cut(a, "=")
		if name == "--output" || name == "-o" || name == "--shell" {
			return cmd + " " + name
		}
	}
	return ""
}

// fuserWrite: -k/--kill kills the processes it finds.
func fuserWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "k", "n", "--kill")
}

// ssWrite: -K/--kill closes sockets, -D/--diag FILE writes FILE.
func ssWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "KD", "fAF", "--kill", "--diag")
}

// arpWrite: -d deletes, -s sets and -f FILE loads entries.
func arpWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "dsf", "Hi", "--delete", "--set", "--file")
}

// sarWrite: -o [FILE] saves the readings to a file.
func sarWrite(cmd string, args []string, _ bool) string {
	return optionWrite(cmd, args, "o", "fiesIPnm")
}
